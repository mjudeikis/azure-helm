package arm

import (
	"encoding/base64"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-07-01/network"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2018-02-01/storage"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/openshift/openshift-azure/pkg/api"
	"github.com/openshift/openshift-azure/pkg/cluster/names"
	"github.com/openshift/openshift-azure/pkg/util/arm"
	"github.com/openshift/openshift-azure/pkg/util/resourceid"
	"github.com/openshift/openshift-azure/pkg/util/template"
	"github.com/openshift/openshift-azure/pkg/util/tls"
)

var (
	// The versions referenced here must be kept in lockstep with the imports
	// above.
	versionMap = map[string]string{
		"Microsoft.Compute": "2018-10-01",
		"Microsoft.Network": "2018-07-01",
		"Microsoft.Storage": "2018-02-01",
	}
)

func (g *simpleGenerator) vnet() *network.VirtualNetwork {
	return &network.VirtualNetwork{
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{
					g.cs.Properties.NetworkProfile.VnetCIDR,
				},
			},
			Subnets: &[]network.Subnet{
				{
					SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
						AddressPrefix: to.StringPtr(g.cs.Properties.AgentPoolProfiles[0].SubnetCIDR),
					},
					Name: to.StringPtr(arm.VnetSubnetName),
				},
				{
					SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
						AddressPrefix: to.StringPtr("10.0.1.0/24"),
					},
					Name: to.StringPtr(arm.VnetManagementSubnetName),
				},
			},
		},
		Name:     to.StringPtr(arm.VnetName),
		Type:     to.StringPtr("Microsoft.Network/virtualNetworks"),
		Location: to.StringPtr(g.cs.Location),
	}
}

func (g *simpleGenerator) ipAPIServer() *network.PublicIPAddress {
	return &network.PublicIPAddress{
		Sku: &network.PublicIPAddressSku{
			Name: network.PublicIPAddressSkuNameStandard,
		},
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			DNSSettings: &network.PublicIPAddressDNSSettings{
				DomainNameLabel: to.StringPtr(derived.MasterLBCNamePrefix(g.cs)),
			},
			IdleTimeoutInMinutes: to.Int32Ptr(15),
		},
		Name:     to.StringPtr(arm.IPAPIServerName),
		Type:     to.StringPtr("Microsoft.Network/publicIPAddresses"),
		Location: to.StringPtr(g.cs.Location),
	}
}

func (g *simpleGenerator) ipOutbound() *network.PublicIPAddress {
	return &network.PublicIPAddress{
		Sku: &network.PublicIPAddressSku{
			Name: network.PublicIPAddressSkuNameStandard,
		},
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			IdleTimeoutInMinutes:     to.Int32Ptr(15),
		},
		Name:     to.StringPtr(arm.IPOutboundName),
		Type:     to.StringPtr("Microsoft.Network/publicIPAddresses"),
		Location: to.StringPtr(g.cs.Location),
	}
}

func (g *simpleGenerator) lbAPIServer() *network.LoadBalancer {
	lb := &network.LoadBalancer{
		Sku: &network.LoadBalancerSku{
			Name: network.LoadBalancerSkuNameStandard,
		},
		LoadBalancerPropertiesFormat: &network.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: &[]network.FrontendIPConfiguration{
				{
					FrontendIPConfigurationPropertiesFormat: &network.FrontendIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: network.Dynamic,
						PublicIPAddress: &network.PublicIPAddress{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/publicIPAddresses",
								arm.IPAPIServerName,
							)),
						},
					},
					Name: to.StringPtr(arm.LbAPIServerFrontendConfigurationName),
				},
			},
			BackendAddressPools: &[]network.BackendAddressPool{
				{
					Name: to.StringPtr(arm.LbAPIServerBackendPoolName),
				},
			},
			LoadBalancingRules: &[]network.LoadBalancingRule{
				{
					LoadBalancingRulePropertiesFormat: &network.LoadBalancingRulePropertiesFormat{
						FrontendIPConfiguration: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.LbAPIServerName,
							) + "/frontendIPConfigurations/" + arm.LbAPIServerFrontendConfigurationName),
						},
						BackendAddressPool: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.LbAPIServerName,
							) + "/backendAddressPools/" + arm.LbAPIServerBackendPoolName),
						},
						Probe: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.LbAPIServerName,
							) + "/probes/" + arm.LbAPIServerProbeName),
						},
						Protocol:             network.TransportProtocolTCP,
						LoadDistribution:     network.Default,
						FrontendPort:         to.Int32Ptr(443),
						BackendPort:          to.Int32Ptr(443),
						IdleTimeoutInMinutes: to.Int32Ptr(15),
						EnableFloatingIP:     to.BoolPtr(false),
					},
					Name: to.StringPtr(arm.LbAPIServerLoadBalancingRuleName),
				},
			},
			Probes: &[]network.Probe{
				{
					ProbePropertiesFormat: &network.ProbePropertiesFormat{
						Protocol:          network.ProbeProtocolHTTPS,
						Port:              to.Int32Ptr(443),
						IntervalInSeconds: to.Int32Ptr(5),
						NumberOfProbes:    to.Int32Ptr(2),
						RequestPath:       to.StringPtr("/healthz"),
					},
					Name: to.StringPtr(arm.LbAPIServerProbeName),
				},
			},
			InboundNatRules: &[]network.InboundNatRule{},
			InboundNatPools: &[]network.InboundNatPool{},
			OutboundRules:   &[]network.OutboundRule{},
		},
		Name:     to.StringPtr(arm.LbAPIServerName),
		Type:     to.StringPtr("Microsoft.Network/loadBalancers"),
		Location: to.StringPtr(g.cs.Location),
	}

	return lb
}

func (g *simpleGenerator) ilbAPIServer() *network.LoadBalancer {
	lb := &network.LoadBalancer{
		Sku: &network.LoadBalancerSku{
			Name: network.LoadBalancerSkuNameStandard,
		},
		LoadBalancerPropertiesFormat: &network.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: &[]network.FrontendIPConfiguration{
				{
					FrontendIPConfigurationPropertiesFormat: &network.FrontendIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: network.Dynamic,
						Subnet: &network.Subnet{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/virtualNetworks",
								arm.VnetName,
							) + "/subnets/" + arm.VnetSubnetName),
						},
					},
					Name: to.StringPtr(arm.IlbAPIServerFrontendConfigurationName),
				},
			},
			BackendAddressPools: &[]network.BackendAddressPool{
				{
					Name: to.StringPtr(arm.LbAPIServerBackendPoolName),
				},
			},
			LoadBalancingRules: &[]network.LoadBalancingRule{
				{
					LoadBalancingRulePropertiesFormat: &network.LoadBalancingRulePropertiesFormat{
						FrontendIPConfiguration: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.IlbAPIServerName,
							) + "/frontendIPConfigurations/" + arm.IlbAPIServerFrontendConfigurationName),
						},
						BackendAddressPool: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.IlbAPIServerName,
							) + "/backendAddressPools/" + arm.LbAPIServerBackendPoolName),
						},
						Probe: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.IlbAPIServerName,
							) + "/probes/" + arm.LbAPIServerProbeName),
						},
						Protocol:             network.TransportProtocolTCP,
						LoadDistribution:     network.Default,
						FrontendPort:         to.Int32Ptr(443),
						BackendPort:          to.Int32Ptr(443),
						IdleTimeoutInMinutes: to.Int32Ptr(15),
						EnableFloatingIP:     to.BoolPtr(false),
					},
					Name: to.StringPtr(arm.LbAPIServerLoadBalancingRuleName),
				},
			},
			Probes: &[]network.Probe{
				{
					ProbePropertiesFormat: &network.ProbePropertiesFormat{
						Protocol:          network.ProbeProtocolHTTPS,
						Port:              to.Int32Ptr(443),
						IntervalInSeconds: to.Int32Ptr(5),
						NumberOfProbes:    to.Int32Ptr(2),
						RequestPath:       to.StringPtr("/healthz"),
					},
					Name: to.StringPtr(arm.LbAPIServerProbeName),
				},
			},
			InboundNatRules: &[]network.InboundNatRule{},
			InboundNatPools: &[]network.InboundNatPool{},
			OutboundRules:   &[]network.OutboundRule{},
		},
		Name:     to.StringPtr(arm.IlbAPIServerName),
		Type:     to.StringPtr("Microsoft.Network/loadBalancers"),
		Location: to.StringPtr(g.cs.Location),
	}

	return lb
}

func (g *simpleGenerator) lbKubernetes() *network.LoadBalancer {
	lb := &network.LoadBalancer{
		Sku: &network.LoadBalancerSku{
			Name: network.LoadBalancerSkuNameStandard,
		},
		LoadBalancerPropertiesFormat: &network.LoadBalancerPropertiesFormat{
			FrontendIPConfigurations: &[]network.FrontendIPConfiguration{
				{
					FrontendIPConfigurationPropertiesFormat: &network.FrontendIPConfigurationPropertiesFormat{
						PrivateIPAllocationMethod: network.Dynamic,
						PublicIPAddress: &network.PublicIPAddress{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/publicIPAddresses",
								arm.IPOutboundName,
							)),
						},
					},
					Name: to.StringPtr(arm.LbKubernetesOutboundFrontendConfigurationName),
				},
			},
			BackendAddressPools: &[]network.BackendAddressPool{
				{
					Name: to.StringPtr(arm.LbKubernetesBackendPoolName),
				},
			},
			OutboundRules: &[]network.OutboundRule{
				{
					Name: to.StringPtr(arm.LbKubernetesOutboundRuleName),
					OutboundRulePropertiesFormat: &network.OutboundRulePropertiesFormat{
						FrontendIPConfigurations: &[]network.SubResource{
							{
								ID: to.StringPtr(resourceid.ResourceID(
									g.cs.Properties.AzProfile.SubscriptionID,
									g.cs.Properties.AzProfile.ResourceGroup,
									"Microsoft.Network/loadBalancers",
									arm.LbKubernetesName,
								) + "/frontendIPConfigurations/" + arm.LbKubernetesOutboundFrontendConfigurationName),
							},
						},
						BackendAddressPool: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								g.cs.Properties.AzProfile.SubscriptionID,
								g.cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								arm.LbKubernetesName,
							) + "/backendAddressPools/" + arm.LbKubernetesBackendPoolName),
						},
						Protocol:             network.Protocol1All,
						IdleTimeoutInMinutes: to.Int32Ptr(15),
					},
				},
			},
		},
		Name:     to.StringPtr(arm.LbKubernetesName),
		Type:     to.StringPtr("Microsoft.Network/loadBalancers"),
		Location: to.StringPtr(g.cs.Location),
	}

	return lb
}

func (g *simpleGenerator) storageAccount(name string, tags map[string]*string) *storage.Account {
	return &storage.Account{
		Sku: &storage.Sku{
			Name: storage.StandardLRS,
		},
		Kind:     storage.Storage,
		Name:     to.StringPtr(name),
		Type:     to.StringPtr("Microsoft.Storage/storageAccounts"),
		Location: to.StringPtr(g.cs.Location),
		Tags:     tags,
		AccountProperties: &storage.AccountProperties{
			EnableHTTPSTrafficOnly: to.BoolPtr(true),
		},
	}
}

func (g *simpleGenerator) nsgMaster() *network.SecurityGroup {
	return &network.SecurityGroup{
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &[]network.SecurityRule{
				{
					SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
						Description:              to.StringPtr("Allow SSH traffic"),
						Protocol:                 network.SecurityRuleProtocolTCP,
						SourcePortRange:          to.StringPtr("*"),
						DestinationPortRange:     to.StringPtr("22-22"),
						SourceAddressPrefixes:    to.StringSlicePtr(g.cs.Config.SSHSourceAddressPrefixes),
						DestinationAddressPrefix: to.StringPtr("*"),
						Access:                   network.SecurityRuleAccessAllow,
						Priority:                 to.Int32Ptr(101),
						Direction:                network.SecurityRuleDirectionInbound,
					},
					Name: to.StringPtr(arm.NsgMasterAllowSSHRuleName),
				},
				{
					SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
						Description:              to.StringPtr("Allow HTTPS traffic"),
						Protocol:                 network.SecurityRuleProtocolTCP,
						SourcePortRange:          to.StringPtr("*"),
						DestinationPortRange:     to.StringPtr("443-443"),
						SourceAddressPrefixes:    to.StringSlicePtr([]string{"0.0.0.0/0"}),
						DestinationAddressPrefix: to.StringPtr("*"),
						Access:                   network.SecurityRuleAccessAllow,
						Priority:                 to.Int32Ptr(102),
						Direction:                network.SecurityRuleDirectionInbound,
					},
					Name: to.StringPtr(arm.NsgMasterAllowHTTPSRuleName),
				},
			},
		},
		Name:     to.StringPtr(arm.NsgMasterName),
		Type:     to.StringPtr("Microsoft.Network/networkSecurityGroups"),
		Location: to.StringPtr(g.cs.Location),
	}
}

func (g *simpleGenerator) nsgWorker() *network.SecurityGroup {
	return &network.SecurityGroup{
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &[]network.SecurityRule{},
		},
		Name:     to.StringPtr(arm.NsgWorkerName),
		Type:     to.StringPtr("Microsoft.Network/networkSecurityGroups"),
		Location: to.StringPtr(g.cs.Location),
	}
}

func (g *simpleGenerator) Vmss(app *api.AgentPoolProfile, backupBlob, suffix string) (*compute.VirtualMachineScaleSet, error) {
	return vmss(g.cs, app, backupBlob, suffix, g.testConfig)
}

func vmss(cs *api.OpenShiftManagedCluster, app *api.AgentPoolProfile, backupBlob, suffix string, testConfig api.TestConfig) (*compute.VirtualMachineScaleSet, error) {
	sshPublicKey, err := tls.SSHPublicKeyAsString(&cs.Config.SSHKey.PublicKey)
	if err != nil {
		return nil, err
	}

	masterStartup, err := Asset("master-startup.sh")
	if err != nil {
		return nil, err
	}

	nodeStartup, err := Asset("node-startup.sh")
	if err != nil {
		return nil, err
	}

	var script string
	if app.Role == api.AgentPoolProfileRoleMaster {
		b, err := template.Template("master-startup.sh", string(masterStartup), nil, map[string]interface{}{
			"Config":         &cs.Config,
			"BackupBlobName": backupBlob,
		})
		if err != nil {
			return nil, err
		}
		script = base64.StdEncoding.EncodeToString(b)
	} else {
		b, err := template.Template("node-startup.sh", string(nodeStartup), nil, map[string]interface{}{
			"Config": &cs.Config,
			"Role":   app.Role,
		})
		if err != nil {
			return nil, err
		}
		script = base64.StdEncoding.EncodeToString(b)
	}

	vmss := &compute.VirtualMachineScaleSet{
		Sku: &compute.Sku{
			Name:     to.StringPtr(string(app.VMSize)),
			Tier:     to.StringPtr("Standard"),
			Capacity: to.Int64Ptr(app.Count),
		},
		Plan: &compute.Plan{
			Name:      to.StringPtr(cs.Config.ImageSKU),
			Publisher: to.StringPtr(cs.Config.ImagePublisher),
			Product:   to.StringPtr(cs.Config.ImageOffer),
		},
		VirtualMachineScaleSetProperties: &compute.VirtualMachineScaleSetProperties{
			UpgradePolicy: &compute.UpgradePolicy{
				AutomaticOSUpgradePolicy: &compute.AutomaticOSUpgradePolicy{
					DisableAutomaticRollback: to.BoolPtr(false),
				},
				Mode: compute.Manual,
			},
			VirtualMachineProfile: &compute.VirtualMachineScaleSetVMProfile{
				OsProfile: &compute.VirtualMachineScaleSetOSProfile{
					ComputerNamePrefix: to.StringPtr(names.GetHostnamePrefix(app, suffix)),
					AdminUsername:      to.StringPtr(arm.VmssAdminUsername),
					LinuxConfiguration: &compute.LinuxConfiguration{
						DisablePasswordAuthentication: to.BoolPtr(true),
						SSH: &compute.SSHConfiguration{
							PublicKeys: &[]compute.SSHPublicKey{
								{
									Path:    to.StringPtr("/home/" + arm.VmssAdminUsername + "/.ssh/authorized_keys"),
									KeyData: to.StringPtr(sshPublicKey),
								},
							},
						},
					},
				},
				StorageProfile: &compute.VirtualMachineScaleSetStorageProfile{
					ImageReference: &compute.ImageReference{
						Publisher: to.StringPtr(cs.Config.ImagePublisher),
						Offer:     to.StringPtr(cs.Config.ImageOffer),
						Sku:       to.StringPtr(cs.Config.ImageSKU),
						Version:   to.StringPtr(cs.Config.ImageVersion),
					},
					OsDisk: &compute.VirtualMachineScaleSetOSDisk{
						Caching:      compute.CachingTypesReadWrite,
						CreateOption: compute.DiskCreateOptionTypesFromImage,
						ManagedDisk: &compute.VirtualMachineScaleSetManagedDiskParameters{
							StorageAccountType: compute.StorageAccountTypesPremiumLRS,
						},
					},
				},
				NetworkProfile: &compute.VirtualMachineScaleSetNetworkProfile{
					NetworkInterfaceConfigurations: &[]compute.VirtualMachineScaleSetNetworkConfiguration{
						{
							Name: to.StringPtr(arm.VmssNicName),
							VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
								Primary: to.BoolPtr(true),
								IPConfigurations: &[]compute.VirtualMachineScaleSetIPConfiguration{
									{
										Name: to.StringPtr(arm.VmssIPConfigurationName),
										VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
											Subnet: &compute.APIEntityReference{
												ID: to.StringPtr(resourceid.ResourceID(
													cs.Properties.AzProfile.SubscriptionID,
													cs.Properties.AzProfile.ResourceGroup,
													"Microsoft.Network/virtualNetworks",
													arm.VnetName,
												) + "/subnets/" + arm.VnetSubnetName),
											},
											Primary: to.BoolPtr(true),
										},
									},
								},
								EnableIPForwarding: to.BoolPtr(true),
							},
						},
					},
				},
				DiagnosticsProfile: &compute.DiagnosticsProfile{
					BootDiagnostics: &compute.BootDiagnostics{
						Enabled:    to.BoolPtr(true),
						StorageURI: to.StringPtr(fmt.Sprintf("https://%s.blob.core.windows.net", cs.Config.ConfigStorageAccount)),
					},
				},
				ExtensionProfile: &compute.VirtualMachineScaleSetExtensionProfile{
					Extensions: &[]compute.VirtualMachineScaleSetExtension{
						{
							Name: to.StringPtr(arm.VmssCSEName),
							VirtualMachineScaleSetExtensionProperties: &compute.VirtualMachineScaleSetExtensionProperties{
								Publisher:               to.StringPtr("Microsoft.Azure.Extensions"),
								Type:                    to.StringPtr("CustomScript"),
								TypeHandlerVersion:      to.StringPtr("2.0"),
								AutoUpgradeMinorVersion: to.BoolPtr(true),
								Settings:                map[string]interface{}{},
								ProtectedSettings: map[string]interface{}{
									"script": script,
								},
							},
						},
					},
				},
			},
			SinglePlacementGroup: to.BoolPtr(false),
			Overprovision:        to.BoolPtr(false),
		},
		Name:     to.StringPtr(names.GetScalesetName(app, suffix)),
		Type:     to.StringPtr("Microsoft.Compute/virtualMachineScaleSets"),
		Location: to.StringPtr(cs.Location),
	}

	if app.Role == api.AgentPoolProfileRoleMaster {
		vmss.VirtualMachineProfile.StorageProfile.DataDisks = &[]compute.VirtualMachineScaleSetDataDisk{
			{
				Lun:          to.Int32Ptr(0),
				Caching:      compute.CachingTypesReadOnly,
				CreateOption: compute.DiskCreateOptionTypesEmpty,
				DiskSizeGB:   to.Int32Ptr(256),
			},
		}
		(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].PublicIPAddressConfiguration = &compute.VirtualMachineScaleSetPublicIPAddressConfiguration{
			Name: to.StringPtr(arm.VmssNicPublicIPConfigurationName),
			VirtualMachineScaleSetPublicIPAddressConfigurationProperties: &compute.VirtualMachineScaleSetPublicIPAddressConfigurationProperties{
				IdleTimeoutInMinutes: to.Int32Ptr(15),
			},
		}
		(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].LoadBalancerBackendAddressPools = &[]compute.SubResource{
			{
				ID: to.StringPtr(resourceid.ResourceID(
					cs.Properties.AzProfile.SubscriptionID,
					cs.Properties.AzProfile.ResourceGroup,
					"Microsoft.Network/loadBalancers",
					arm.LbAPIServerName,
				) + "/backendAddressPools/" + arm.LbAPIServerBackendPoolName),
			},
			{
				ID: to.StringPtr(resourceid.ResourceID(
					cs.Properties.AzProfile.SubscriptionID,
					cs.Properties.AzProfile.ResourceGroup,
					"Microsoft.Network/loadBalancers",
					arm.IlbAPIServerName,
				) + "/backendAddressPools/" + arm.LbAPIServerBackendPoolName),
			},
		}
		(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.NetworkSecurityGroup = &compute.SubResource{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				cs.Properties.AzProfile.ResourceGroup,
				"Microsoft.Network/networkSecurityGroups",
				arm.NsgMasterName,
			)),
		}
	} else {
		(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].LoadBalancerBackendAddressPools = &[]compute.SubResource{
			{
				ID: to.StringPtr(resourceid.ResourceID(
					cs.Properties.AzProfile.SubscriptionID,
					cs.Properties.AzProfile.ResourceGroup,
					"Microsoft.Network/loadBalancers",
					arm.LbKubernetesName,
				) + "/backendAddressPools/" + arm.LbKubernetesBackendPoolName),
			},
		}
		(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.NetworkSecurityGroup = &compute.SubResource{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				cs.Properties.AzProfile.ResourceGroup,
				"Microsoft.Network/networkSecurityGroups",
				arm.NsgWorkerName,
			)),
		}
	}

	if testConfig.ImageResourceName != "" {
		vmss.Plan = nil
		vmss.VirtualMachineScaleSetProperties.VirtualMachineProfile.StorageProfile.ImageReference = &compute.ImageReference{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				testConfig.ImageResourceGroup,
				"Microsoft.Compute/images",
				testConfig.ImageResourceName,
			)),
		}
	}

	return vmss, nil
}
