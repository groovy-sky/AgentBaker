package e2e_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/go-armbalancer"
)

type azureClient struct {
	coreClient     *azcore.Client
	vmssClient     *armcompute.VirtualMachineScaleSetsClient
	vmssVMClient   *armcompute.VirtualMachineScaleSetVMsClient
	resourceClient *armresources.Client
	aksClient      *armcontainerservice.ManagedClustersClient
}

func newAzureClient(subscription string) (*azureClient, error) {
	httpClient := &http.Client{
		// For Now using the defaults recommended by Track 2
		Transport: armbalancer.New(armbalancer.Options{
			PoolSize: 100,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		}),
	}

	logger := runtime.NewLogPolicy(&policy.LogOptions{
		IncludeBody: true,
	})

	opts := &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: httpClient,
			PerCallPolicies: []policy.Policy{
				logger,
			},
		},
	}

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %q", err)
	}

	plOpts := runtime.PipelineOptions{}
	clOpts := &azcore.ClientOptions{
		Transport: httpClient,
		PerCallPolicies: []policy.Policy{
			runtime.NewBearerTokenPolicy(credential, []string{"https://management.azure.com/.default"}, nil),
			logger,
		},
	}

	coreClient, err := azcore.NewClient("agentbakere2e.e2e_test", "v0.0.0", plOpts, clOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create core client: %q", err)
	}

	aksClient, err := armcontainerservice.NewManagedClustersClient(subscription, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vmss client: %q", err)
	}

	vmssClient, err := armcompute.NewVirtualMachineScaleSetsClient(subscription, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vmss client: %q", err)
	}

	vmssVMClient, err := armcompute.NewVirtualMachineScaleSetVMsClient(subscription, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create vmss vm client: %q", err)
	}

	resourceClient, err := armresources.NewClient(subscription, credential, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource client: %q", err)
	}

	var cloud = &azureClient{
		coreClient:     coreClient,
		aksClient:      aksClient,
		resourceClient: resourceClient,
		vmssClient:     vmssClient,
		vmssVMClient:   vmssVMClient,
	}

	return cloud, nil
}
