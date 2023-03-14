package e2e_test

import (
	"context"
	"fmt"
	mrand "math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/agentbaker/pkg/agent"
	"github.com/Azure/agentbaker/pkg/agent/datamodel"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/barkimedes/go-deepcopy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const agentbakerTestResourceGroupName = "MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus"

var cases = map[string]scenarioConfig{
	"base": {},
	"gpu": {
		bootstrapConfigMutator: func(t *testing.T, nbc *datamodel.NodeBootstrappingConfiguration) {
			nbc.ContainerService.Properties.AgentPoolProfiles[0].VMSize = "Standard_NC6"
			nbc.ContainerService.Properties.AgentPoolProfiles[0].Distro = "aks-ubuntu-containerd-18.04-gen2"
			nbc.AgentPoolProfile.VMSize = "Standard_NC6"
			nbc.AgentPoolProfile.Distro = "aks-ubuntu-containerd-18.04-gen2"
			nbc.ConfigGPUDriverIfNeeded = true
			nbc.EnableGPUDevicePluginIfNeeded = false
			nbc.EnableNvidia = true
		},
		vmConfigMutator: func(vmss *armcompute.VirtualMachineScaleSet) {
			vmss.SKU.Name = to.Ptr("Standard_NC6s_v3")
		},
	},
}

func Test_All(t *testing.T) {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	suiteConfig, err := newSuiteConfig()
	if err != nil {
		t.Fatal(err)
	}

	cloud, err := newAzureClient(suiteConfig.subscription)
	if err != nil {
		t.Fatal(err)
	}

	if err := setupCluster(ctx, cloud, suiteConfig.location, suiteConfig.resourceGroupName, suiteConfig.clusterName); err != nil {
		t.Fatal(err)
	}

	subnetID, err := getClusterSubnetID(ctx, cloud, suiteConfig.location, suiteConfig.resourceGroupName, suiteConfig.clusterName)
	if err != nil {
		t.Fatal(err)
	}

	kube, err := getClusterKubeClient(ctx, cloud, suiteConfig)
	if err != nil {
		t.Fatal(err)
	}

	clusterParams, err := extractClusterParameters(ctx, t, kube)
	if err != nil {
		t.Fatal(err)
	}

	baseConfig, err := getBaseBootstrappingConfig(ctx, t, cloud, suiteConfig, clusterParams)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range cases {
		tc := tc
		copied, err := deepcopy.Anything(baseConfig)
		if err != nil {
			t.Error(err)
			continue
		}
		nbc := copied.(*datamodel.NodeBootstrappingConfiguration)

		if tc.bootstrapConfigMutator != nil {
			tc.bootstrapConfigMutator(t, nbc)
		}

		t.Run(name, func(t *testing.T) {
			baker := agent.InitializeTemplateGenerator()
			base64EncodedCustomData := baker.GetNodeBootstrappingPayload(nbc)
			cseCmd := baker.GetNodeBootstrappingCmd(nbc)

			vmssName := fmt.Sprintf("abtest%s", randomLowercaseString(r, 4))

			t.Logf("vmss name: %q", vmssName)

			cleanup := func() {
				poller, err := cloud.vmssClient.BeginDelete(ctx, suiteConfig.resourceGroupName, vmssName, nil)
				if err != nil {
					t.Error(err)
					return
				}
				_, err = poller.PollUntilDone(ctx, nil)
				if err != nil {
					t.Error(err)
				}
			}

			defer cleanup()

			sshPrivateKeyBytes, err := createVMSSWithPayload(ctx, r, cloud, suiteConfig.location, suiteConfig.resourceGroupName, vmssName, subnetID, base64EncodedCustomData, cseCmd, tc.vmConfigMutator)
			if err != nil {
				t.Error(err)
				return
			}

			err = waitUntilNodeReady(ctx, kube, vmssName)
			if err != nil {
				t.Error(err)
			}

			_, err = extractLogsFromFailedVM(ctx, t, cloud, kube, suiteConfig.subscription, suiteConfig.resourceGroupName, suiteConfig.clusterName, vmssName, string(sshPrivateKeyBytes))
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func getClusterSubnetID(ctx context.Context, cloud *azureClient, location, resourceGroupName, clusterName string) (string, error) {
	pager := cloud.vnetClient.NewListPager(agentbakerTestResourceGroupName, nil)

	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to advance page: %q", err)
		}
		for _, v := range nextResult.Value {
			if v == nil {
				return "", fmt.Errorf("aks vnet id was empty")
			}
			return fmt.Sprintf("%s/subnets/%s", *v.ID, "aks-subnet"), nil
		}
	}

	return "", fmt.Errorf("failed to find aks vnet")
}

func setupCluster(ctx context.Context, cloud *azureClient, location, resourceGroupName, clusterName string) error {
	aksCluster, err := cloud.aksClient.Get(ctx, resourceGroupName, clusterName, nil)
	if err != nil {
		return fmt.Errorf("failed to get aks cluster: %q", err)
	}

	rgExistence, err := cloud.resourceGroupClient.CheckExistence(ctx, resourceGroupName, nil)
	if err != nil {
		return fmt.Errorf("failed to get MC RG: %q", err)
	}

	if !rgExistence.Success || aksCluster.Properties == nil || aksCluster.Properties.ProvisioningState == nil || *aksCluster.Properties.ProvisioningState == "Failed" {
		poller, err := cloud.aksClient.BeginDelete(ctx, resourceGroupName, clusterName, nil)
		if err != nil {
			return fmt.Errorf("failed to start aks cluster deletion: %q", err)
		}

		_, err = poller.PollUntilDone(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to wait for aks cluster deletion: %q", err)
		}

		pollerResp, err := cloud.aksClient.BeginCreateOrUpdate(
			ctx,
			resourceGroupName,
			clusterName,
			armcontainerservice.ManagedCluster{
				Location: to.Ptr(location),
				Properties: &armcontainerservice.ManagedClusterProperties{
					DNSPrefix: to.Ptr(clusterName),
					AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
						{
							Name:         to.Ptr("nodepool1"),
							Count:        to.Ptr[int32](1),
							VMSize:       to.Ptr("Standard_DS2_v2"),
							MaxPods:      to.Ptr[int32](110),
							MinCount:     to.Ptr[int32](1),
							MaxCount:     to.Ptr[int32](100),
							OSType:       to.Ptr(armcontainerservice.OSTypeLinux),
							Type:         to.Ptr(armcontainerservice.AgentPoolTypeVirtualMachineScaleSets),
							Mode:         to.Ptr(armcontainerservice.AgentPoolModeSystem),
							OSDiskSizeGB: to.Ptr[int32](512),
						},
					},
					NetworkProfile: &armcontainerservice.NetworkProfile{
						NetworkPlugin: to.Ptr(armcontainerservice.NetworkPluginKubenet),
					},
				},
			},
			nil,
		)

		if err != nil {
			return fmt.Errorf("failed to  recreate aks cluster: %q", err)
		}

		_, err = pollerResp.PollUntilDone(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to finish aks cluster recreation %q", err)
		}
	}

	return nil
}

func waitUntilNodeReady(ctx context.Context, kube *kubeclient, vmssName string) error {
	return wait.PollImmediateUntilWithContext(ctx, 5*time.Second, func(ctx context.Context) (bool, error) {
		nodes, err := kube.typed.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		for _, node := range nodes.Items {
			if strings.HasPrefix(node.Name, vmssName) {
				for _, cond := range node.Status.Conditions {
					if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
						return true, nil
					}
				}
			}
		}

		return false, nil
	})
}

type suiteConfig struct {
	subscription      string
	location          string
	resourceGroupName string
	clusterName       string
}

func newSuiteConfig() (*suiteConfig, error) {
	var environment = map[string]string{
		"SUBSCRIPTION_ID":     "",
		"LOCATION":            "",
		"RESOURCE_GROUP_NAME": "",
		"CLUSTER_NAME":        "",
	}

	for k := range environment {
		value := os.Getenv(k)
		if value == "" {
			return nil, fmt.Errorf("missing required environment variable %q", k)
		}
		environment[k] = value
	}

	return &suiteConfig{
		subscription:      environment["SUBSCRIPTION_ID"],
		location:          environment["LOCATION"],
		resourceGroupName: environment["RESOURCE_GROUP_NAME"],
		clusterName:       environment["CLUSTER_NAME"],
	}, nil
}

type scenarioConfig struct {
	// bootstrapConfig          *datamodel.NodeBootstrappingConfiguration
	bootstrapConfigMutator   func(*testing.T, *datamodel.NodeBootstrappingConfiguration)
	bootstrapConfigValidator func(context.Context, *testing.T, *bootstrapConfigValidationInput) error
	vmConfigMutator          func(*armcompute.VirtualMachineScaleSet)
	vmConfigValidator        func(context.Context, *testing.T, *vmConfigValidationInput) error
}

type bootstrapConfigValidationInput struct{}
type vmConfigValidationInput struct{}
