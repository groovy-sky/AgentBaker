package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	mrand "math/rand"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"golang.org/x/crypto/ssh"
)

func createVMSSWithPayload(ctx context.Context, r *mrand.Rand, cloud *azureClient, location, resourceGroupName, name string, customData, cseCmd string) error {
	// TODO(ace): FIX ME
	// will break when cluster recreates because vnet/subnet will change
	// also won't work for multiple clusters
	subnetID := "/subscriptions/8ecadfc9-d1a3-4ea4-b844-0d9f87e4d7c8/resourceGroups/MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus/providers/Microsoft.Network/virtualNetworks/aks-vnet-31509630/subnets/aks-subnet"

	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to create rsa private key: %q", err)
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate private key: %q", err)
	}

	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to convert private to public key: %q", err)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	_ = pubKeyBytes

	pollerResp, err := cloud.vmssClient.BeginCreateOrUpdate(
		ctx,
		"MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus",
		name,
		armcompute.VirtualMachineScaleSet{
			Location: to.Ptr(location),
			SKU: &armcompute.SKU{
				Name:     to.Ptr("Standard_DS2_v2"),
				Capacity: to.Ptr[int64](1),
			},
			Properties: &armcompute.VirtualMachineScaleSetProperties{
				Overprovision: to.Ptr(false),
				UpgradePolicy: &armcompute.UpgradePolicy{
					Mode: to.Ptr(armcompute.UpgradeModeManual),
				},
				VirtualMachineProfile: &armcompute.VirtualMachineScaleSetVMProfile{
					ExtensionProfile: &armcompute.VirtualMachineScaleSetExtensionProfile{
						Extensions: []*armcompute.VirtualMachineScaleSetExtension{
							{
								Name: to.Ptr("vmssCSE"),
								Properties: &armcompute.VirtualMachineScaleSetExtensionProperties{
									Publisher:               to.Ptr("Microsoft.Azure.Extensions"),
									Type:                    to.Ptr("CustomScript"),
									TypeHandlerVersion:      to.Ptr("2.0"),
									AutoUpgradeMinorVersion: to.Ptr(true),
									Settings:                map[string]interface{}{},
									ProtectedSettings: map[string]interface{}{
										"commandToExecute": cseCmd,
									},
								},
							},
						},
					},
					OSProfile: &armcompute.VirtualMachineScaleSetOSProfile{
						ComputerNamePrefix: to.Ptr(name),
						AdminUsername:      to.Ptr("azureuser"),
						CustomData:         &customData,
						LinuxConfiguration: &armcompute.LinuxConfiguration{
							SSH: &armcompute.SSHConfiguration{
								PublicKeys: []*armcompute.SSHPublicKey{
									{
										KeyData: to.Ptr("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1EETTQ47Q9VhAAtjCb7fjciPU1+JehogdXCr6HhMWHLWGciiCgiSz5CmGBBcVSHJXKBaPdq1CcGF8qTiP7C7wMyo+WweeDVrmSzvpQK/RBNr7JO9UuA4oguxCGMtRoc9Ak4ME8h80+oSkHdsgixbcyeXUpzdhO1cfidtWWzezWIKIQzIw5wgShnFw4jq1RnANH0Cz8aaDdG5SZOi5/OCobmUdLuQMivqs6+PA13+i6AZtcNTz79pLkJZvoU/UZDU1jpmLzqNj1LX3Rl7TeXIJAj5RzbdagAGPZkOQNAyipxeyu2oisGXe2oU1IZJbyzf6VQGLfc7Q+Is+aK3c7id04bA+OXznW1zYC5S5AFdyy1sBNMgyC7IX+oko7eczWdTVH3jFrcQaMH/FfxMoTPOXBm8wv6xUVpsKKJ3aZlzsGsL4uURF/B2owydp7qx7vnmqim2I8WZoLdMavcL0t1lgR8qe3U9cH4qnar8/cW6fQdvuBazB3//3Rtfzx6rJoW0= root@Ubuntu-2004-focal-64-minimal"),
										Path:    to.Ptr("/home/azureuser/.ssh/authorized_keys"),
									},
								},
							},
						},
					},
					StorageProfile: &armcompute.VirtualMachineScaleSetStorageProfile{
						ImageReference: &armcompute.ImageReference{
							ID: to.Ptr("/subscriptions/8ecadfc9-d1a3-4ea4-b844-0d9f87e4d7c8/resourceGroups/aksvhdtestbuildrg/providers/Microsoft.Compute/galleries/PackerSigGalleryEastUS/images/1804Gen2/versions/1.1677169694.31375"),
							// 	Offer:     to.Ptr("0001-com-ubuntu-server-jammy"),
							// 	Publisher: to.Ptr("Canonical"),
							// 	SKU:       to.Ptr("22_04-lts-gen2"),
							// 	Version:   to.Ptr("latest"),
						},
						OSDisk: &armcompute.VirtualMachineScaleSetOSDisk{
							CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
							DiskSizeGB:   to.Ptr(int32(512)),
							OSType:       to.Ptr(armcompute.OperatingSystemTypesLinux),
						},
					},
					NetworkProfile: &armcompute.VirtualMachineScaleSetNetworkProfile{
						NetworkInterfaceConfigurations: []*armcompute.VirtualMachineScaleSetNetworkConfiguration{
							{
								Name: to.Ptr(name),
								Properties: &armcompute.VirtualMachineScaleSetNetworkConfigurationProperties{
									Primary:            to.Ptr(true),
									EnableIPForwarding: to.Ptr(true),
									IPConfigurations: []*armcompute.VirtualMachineScaleSetIPConfiguration{
										{
											Name: to.Ptr(name),
											Properties: &armcompute.VirtualMachineScaleSetIPConfigurationProperties{
												LoadBalancerBackendAddressPools: []*armcompute.SubResource{
													{
														ID: to.Ptr("/subscriptions/8ecadfc9-d1a3-4ea4-b844-0d9f87e4d7c8/resourceGroups/MC_agentbaker-e2e-tests_agentbaker-e2e-test-cluster_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/backendAddressPools/aksOutboundBackendPool"),
													},
												},
												Subnet: &armcompute.APIEntityReference{
													ID: to.Ptr(subnetID),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		nil,
	)
	if err != nil {
		return err
	}

	res, err := pollerResp.PollUntilDone(ctx, nil)
	if err != nil {
		return err
	}

	_ = res

	return nil
}
