package e2e

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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/barkimedes/go-deepcopy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var cases = map[string]scenarioConfig{
	"base": {},
	// "gpu": {
	// 	bootstrapConfigMutator: func(t *testing.T, nbc *datamodel.NodeBootstrappingConfiguration) {
	// 		nbc.ContainerService.Properties.AgentPoolProfiles[0].VMSize = "Standard_NC6"
	// 		nbc.ContainerService.Properties.AgentPoolProfiles[0].Distro = "aks-ubuntu-containerd-18.04-gen2"
	// 		nbc.AgentPoolProfile.VMSize = "Standard_NC6"
	// 		nbc.AgentPoolProfile.Distro = "aks-ubuntu-containerd-18.04-gen2"
	// 		nbc.ConfigGPUDriverIfNeeded = true
	// 		nbc.EnableGPUDevicePluginIfNeeded = false
	// 		nbc.EnableNvidia = true
	// 	},
	// },
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

			err = createVMSSWithPayload(ctx, r, cloud, suiteConfig.location, suiteConfig.resourceGroupName, vmssName, base64EncodedCustomData, cseCmd)
			if err != nil {
				t.Error(err)
			}

			_, err = extractLogsFromFailedVM(ctx, t, cloud, kube, suiteConfig.subscription, suiteConfig.resourceGroupName, suiteConfig.clusterName, vmssName)
			if err != nil {
				t.Error(err)
			}

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

			err = waitUntilNodeReady(ctx, kube, vmssName)
			if err != nil {
				t.Error(err)
			}
		})
	}
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
	vmConfig                 armcompute.VirtualMachineScaleSet
	vmConfigValidator        func(context.Context, *testing.T, *vmConfigValidationInput) error
}

type bootstrapConfigValidationInput struct{}
type vmConfigValidationInput struct{}
