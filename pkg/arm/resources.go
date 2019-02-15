package arm

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-07-01/network"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2015-06-15/storage"
	"github.com/Azure/go-autorest/autorest/to"

	"github.com/openshift/openshift-azure/pkg/api"
	"github.com/openshift/openshift-azure/pkg/config"
	"github.com/openshift/openshift-azure/pkg/jsonpath"
	"github.com/openshift/openshift-azure/pkg/tls"
	"github.com/openshift/openshift-azure/pkg/util/resourceid"
	"github.com/openshift/openshift-azure/pkg/util/template"
)

const (
	VnetName                                      = "vnet"
	vnetSubnetName                                = "default"
	ipAPIServerName                               = "ip-apiserver"
	ipOutboundName                                = "ip-outbound"
	lbAPIServerName                               = "lb-apiserver"
	lbAPIServerFrontendConfigurationName          = "frontend"
	lbAPIServerBackendPoolName                    = "backend"
	lbAPIServerLoadBalancingRuleName              = "port-443"
	lbAPIServerProbeName                          = "port-443"
	lbKubernetesName                              = "kubernetes" // must match KubeCloudSharedConfiguration ClusterName
	lbKubernetesOutboundFrontendConfigurationName = "outbound"
	lbKubernetesOutboundRuleName                  = "outbound"
	lbKubernetesBackendPoolName                   = "kubernetes" // must match KubeCloudSharedConfiguration ClusterName
	nsgMasterName                                 = "nsg-master"
	nsgMasterAllowSSHRuleName                     = "allow_ssh"
	nsgMasterAllowHTTPSRuleName                   = "allow_https"
	nsgWorkerName                                 = "nsg-worker"
	vmssNicName                                   = "nic"
	vmssNicPublicIPConfigurationName              = "ip"
	vmssIPConfigurationName                       = "ipconfig"
	vmssCSEName                                   = "cse"
	vmssAdminUsername                             = "cloud-user"
)

// fixupAPIVersions inserts an apiVersion field into the ARM template for each
// resource (the field is missing from the internal Azure type).  The versions
// referenced here must be kept in lockstep with the imports above.
func fixupAPIVersions(template map[string]interface{}) {
	for _, resource := range jsonpath.MustCompile("$.resources.*").Get(template) {
		typ := jsonpath.MustCompile("$.type").MustGetString(resource)
		var apiVersion string
		switch typ {
		case "Microsoft.Compute/virtualMachineScaleSets":
			apiVersion = "2018-10-01"
		case "Microsoft.Network/loadBalancers",
			"Microsoft.Network/networkSecurityGroups",
			"Microsoft.Network/publicIPAddresses",
			"Microsoft.Network/virtualNetworks":
			apiVersion = "2018-07-01"
		case "Microsoft.Storage/storageAccounts":
			apiVersion = "2015-06-15"
		default:
			panic("unimplemented: " + typ)
		}
		jsonpath.MustCompile("$.apiVersion").Set(resource, apiVersion)
	}
}

// fixupDepends inserts a dependsOn field into the ARM template for each
// resource that needs it (the field is missing from the internal Azure type).
func fixupDepends(azProfile *api.AzProfile, template map[string]interface{}) {
	myResources := map[string]struct{}{}
	for _, resource := range jsonpath.MustCompile("$.resources.*").Get(template) {
		typ := jsonpath.MustCompile("$.type").MustGetString(resource)
		name := jsonpath.MustCompile("$.name").MustGetString(resource)

		myResources[resourceid.ResourceID(azProfile.SubscriptionID, azProfile.ResourceGroup, typ, name)] = struct{}{}
	}

	var recurse func(myResourceID string, i interface{}, dependsMap map[string]struct{})

	// walk the data structure collecting "id" fields whose values look like
	// Azure resource IDs.  Trim sub-resources from IDs.  Ignore IDs that are
	// self-referent
	recurse = func(myResourceID string, i interface{}, dependsMap map[string]struct{}) {
		switch i := i.(type) {
		case map[string]interface{}:
			if id, ok := i["id"]; ok {
				if id, ok := id.(string); ok {
					parts := strings.Split(id, "/")
					if len(parts) > 9 {
						parts = parts[:9]
					}
					if len(parts) == 9 {
						id = strings.Join(parts, "/")
						if id != myResourceID {
							dependsMap[id] = struct{}{}
						}
					}
				}
			}
			for _, v := range i {
				recurse(myResourceID, v, dependsMap)
			}
		case []interface{}:
			for _, v := range i {
				recurse(myResourceID, v, dependsMap)
			}
		}
	}

	for _, resource := range jsonpath.MustCompile("$.resources.*").Get(template) {
		typ := jsonpath.MustCompile("$.type").MustGetString(resource)
		name := jsonpath.MustCompile("$.name").MustGetString(resource)

		dependsMap := map[string]struct{}{}

		recurse(resourceid.ResourceID(azProfile.SubscriptionID, azProfile.ResourceGroup, typ, name), resource, dependsMap)

		depends := make([]string, 0, len(dependsMap))
		for k := range dependsMap {
			if _, found := myResources[k]; found {
				depends = append(depends, k)
			}
		}

		if len(depends) > 0 {
			sort.Strings(depends)

			jsonpath.MustCompile("$.dependsOn").Set(resource, depends)
		}
	}
}

func vnet(cs *api.OpenShiftManagedCluster) *network.VirtualNetwork {
	return &network.VirtualNetwork{
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{
					cs.Properties.NetworkProfile.VnetCIDR,
				},
			},
			Subnets: &[]network.Subnet{
				{
					SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
						AddressPrefix: to.StringPtr(cs.Properties.AgentPoolProfiles[0].SubnetCIDR),
					},
					Name: to.StringPtr(vnetSubnetName),
				},
			},
		},
		Name:     to.StringPtr(VnetName),
		Type:     to.StringPtr("Microsoft.Network/virtualNetworks"),
		Location: to.StringPtr(cs.Location),
	}
}

func ipAPIServer(cs *api.OpenShiftManagedCluster) *network.PublicIPAddress {
	return &network.PublicIPAddress{
		Sku: &network.PublicIPAddressSku{
			Name: network.PublicIPAddressSkuNameStandard,
		},
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			DNSSettings: &network.PublicIPAddressDNSSettings{
				DomainNameLabel: to.StringPtr(config.Derived.MasterLBCNamePrefix(cs)),
			},
			IdleTimeoutInMinutes: to.Int32Ptr(15),
		},
		Name:     to.StringPtr(ipAPIServerName),
		Type:     to.StringPtr("Microsoft.Network/publicIPAddresses"),
		Location: to.StringPtr(cs.Location),
	}
}

func ipOutbound(cs *api.OpenShiftManagedCluster) *network.PublicIPAddress {
	return &network.PublicIPAddress{
		Sku: &network.PublicIPAddressSku{
			Name: network.PublicIPAddressSkuNameStandard,
		},
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: network.Static,
			IdleTimeoutInMinutes:     to.Int32Ptr(15),
		},
		Name:     to.StringPtr(ipOutboundName),
		Type:     to.StringPtr("Microsoft.Network/publicIPAddresses"),
		Location: to.StringPtr(cs.Location),
	}
}

func lbAPIServer(pc *api.PluginConfig, cs *api.OpenShiftManagedCluster) *network.LoadBalancer {
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
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/publicIPAddresses",
								ipAPIServerName,
							)),
						},
					},
					Name: to.StringPtr(lbAPIServerFrontendConfigurationName),
				},
			},
			BackendAddressPools: &[]network.BackendAddressPool{
				{
					Name: to.StringPtr(lbAPIServerBackendPoolName),
				},
			},
			LoadBalancingRules: &[]network.LoadBalancingRule{
				{
					LoadBalancingRulePropertiesFormat: &network.LoadBalancingRulePropertiesFormat{
						FrontendIPConfiguration: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								lbAPIServerName,
							) + "/frontendIPConfigurations/" + lbAPIServerFrontendConfigurationName),
						},
						BackendAddressPool: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								lbAPIServerName,
							) + "/backendAddressPools/" + lbAPIServerBackendPoolName),
						},
						Probe: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								lbAPIServerName,
							) + "/probes/" + lbAPIServerProbeName),
						},
						Protocol:             network.TransportProtocolTCP,
						LoadDistribution:     network.Default,
						FrontendPort:         to.Int32Ptr(443),
						BackendPort:          to.Int32Ptr(443),
						IdleTimeoutInMinutes: to.Int32Ptr(15),
						EnableFloatingIP:     to.BoolPtr(false),
					},
					Name: to.StringPtr(lbAPIServerLoadBalancingRuleName),
				},
			},
			Probes: &[]network.Probe{
				{
					ProbePropertiesFormat: &network.ProbePropertiesFormat{
						Protocol:          network.ProbeProtocolHTTPS,
						Port:              to.Int32Ptr(443),
						IntervalInSeconds: to.Int32Ptr(5),
						NumberOfProbes:    to.Int32Ptr(2),
						RequestPath:       to.StringPtr("/healthz/ready"),
					},
					Name: to.StringPtr(lbAPIServerProbeName),
				},
			},
			InboundNatRules: &[]network.InboundNatRule{},
			InboundNatPools: &[]network.InboundNatPool{},
			OutboundRules:   &[]network.OutboundRule{},
		},
		Name:     to.StringPtr(lbAPIServerName),
		Type:     to.StringPtr("Microsoft.Network/loadBalancers"),
		Location: to.StringPtr(cs.Location),
	}

	if pc.TestConfig.RunningUnderTest {
		(*lb.LoadBalancingRules)[0].EnableTCPReset = to.BoolPtr(true)
	}

	return lb
}

func lbKubernetes(pc *api.PluginConfig, cs *api.OpenShiftManagedCluster) *network.LoadBalancer {
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
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/publicIPAddresses",
								ipOutboundName,
							)),
						},
					},
					Name: to.StringPtr(lbKubernetesOutboundFrontendConfigurationName),
				},
			},
			BackendAddressPools: &[]network.BackendAddressPool{
				{
					Name: to.StringPtr(lbKubernetesBackendPoolName),
				},
			},
			OutboundRules: &[]network.OutboundRule{
				{
					Name: to.StringPtr(lbKubernetesOutboundRuleName),
					OutboundRulePropertiesFormat: &network.OutboundRulePropertiesFormat{
						FrontendIPConfigurations: &[]network.SubResource{
							{
								ID: to.StringPtr(resourceid.ResourceID(
									cs.Properties.AzProfile.SubscriptionID,
									cs.Properties.AzProfile.ResourceGroup,
									"Microsoft.Network/loadBalancers",
									lbKubernetesName,
								) + "/frontendIPConfigurations/" + lbKubernetesOutboundFrontendConfigurationName),
							},
						},
						BackendAddressPool: &network.SubResource{
							ID: to.StringPtr(resourceid.ResourceID(
								cs.Properties.AzProfile.SubscriptionID,
								cs.Properties.AzProfile.ResourceGroup,
								"Microsoft.Network/loadBalancers",
								lbKubernetesName,
							) + "/backendAddressPools/" + lbKubernetesBackendPoolName),
						},
						Protocol:             network.Protocol1All,
						IdleTimeoutInMinutes: to.Int32Ptr(15),
					},
				},
			},
		},
		Name:     to.StringPtr(lbKubernetesName),
		Type:     to.StringPtr("Microsoft.Network/loadBalancers"),
		Location: to.StringPtr(cs.Location),
	}

	if pc.TestConfig.RunningUnderTest {
		(*lb.OutboundRules)[0].EnableTCPReset = to.BoolPtr(true)
	}

	return lb
}

func storageRegistry(cs *api.OpenShiftManagedCluster) *storage.Account {
	return &storage.Account{
		AccountProperties: &storage.AccountProperties{
			AccountType: storage.StandardLRS,
		},
		Name:     to.StringPtr(cs.Config.RegistryStorageAccount),
		Type:     to.StringPtr("Microsoft.Storage/storageAccounts"),
		Location: to.StringPtr(cs.Location),
	}
}

func storageConfig(cs *api.OpenShiftManagedCluster) *storage.Account {
	return &storage.Account{
		AccountProperties: &storage.AccountProperties{
			AccountType: storage.StandardLRS,
		},
		Name:     to.StringPtr(cs.Config.ConfigStorageAccount),
		Type:     to.StringPtr("Microsoft.Storage/storageAccounts"),
		Location: to.StringPtr(cs.Location),
		Tags: map[string]*string{
			// TODO: these should be consts
			"type": to.StringPtr("config"),
		},
	}
}

func nsgMaster(cs *api.OpenShiftManagedCluster) *network.SecurityGroup {
	return &network.SecurityGroup{
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &[]network.SecurityRule{
				{
					SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
						Description:              to.StringPtr("Allow SSH traffic"),
						Protocol:                 network.SecurityRuleProtocolTCP,
						SourcePortRange:          to.StringPtr("*"),
						DestinationPortRange:     to.StringPtr("22-22"),
						SourceAddressPrefix:      to.StringPtr("*"),
						DestinationAddressPrefix: to.StringPtr("*"),
						Access:                   network.SecurityRuleAccessAllow,
						Priority:                 to.Int32Ptr(101),
						Direction:                network.SecurityRuleDirectionInbound,
					},
					Name: to.StringPtr(nsgMasterAllowSSHRuleName),
				},
				{
					SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
						Description:              to.StringPtr("Allow HTTPS traffic"),
						Protocol:                 network.SecurityRuleProtocolTCP,
						SourcePortRange:          to.StringPtr("*"),
						DestinationPortRange:     to.StringPtr("443-443"),
						SourceAddressPrefix:      to.StringPtr("*"),
						DestinationAddressPrefix: to.StringPtr("*"),
						Access:                   network.SecurityRuleAccessAllow,
						Priority:                 to.Int32Ptr(102),
						Direction:                network.SecurityRuleDirectionInbound,
					},
					Name: to.StringPtr(nsgMasterAllowHTTPSRuleName),
				},
			},
		},
		Name:     to.StringPtr(nsgMasterName),
		Type:     to.StringPtr("Microsoft.Network/networkSecurityGroups"),
		Location: to.StringPtr(cs.Location),
	}
}

func nsgWorker(cs *api.OpenShiftManagedCluster) *network.SecurityGroup {
	return &network.SecurityGroup{
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &[]network.SecurityRule{},
		},
		Name:     to.StringPtr(nsgWorkerName),
		Type:     to.StringPtr("Microsoft.Network/networkSecurityGroups"),
		Location: to.StringPtr(cs.Location),
	}
}

func gzipBytes(data []byte) ([]byte, error) {
	var bufOut bytes.Buffer
	gw, err := gzip.NewWriterLevel(&bufOut, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	_, err = gw.Write(data)
	if err != nil {
		return nil, err
	}
	err = gw.Close()
	if err != nil {
		return nil, err
	}
	return bufOut.Bytes(), nil
}

func Vmss(pc *api.PluginConfig, cs *api.OpenShiftManagedCluster, app *api.AgentPoolProfile, backupBlob, suffix string) (*compute.VirtualMachineScaleSet, error) {
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
		b, err := template.Template(string(masterStartup), nil, cs, map[string]interface{}{
			"IsRecovery":     len(backupBlob) > 0,
			"BackupBlobName": backupBlob,
			"Role":           app.Role,
			"TestConfig":     pc.TestConfig,
		})
		if err != nil {
			return nil, err
		}

		compressed, err := gzipBytes(b)
		if err != nil {
			return nil, err
		}

		script = base64.StdEncoding.EncodeToString(compressed)
	} else {
		b, err := template.Template(string(nodeStartup), nil, cs, map[string]interface{}{
			"Role":       app.Role,
			"TestConfig": pc.TestConfig,
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
					ComputerNamePrefix: to.StringPtr(config.GetComputerNamePrefix(app, suffix)),
					AdminUsername:      to.StringPtr(vmssAdminUsername),
					LinuxConfiguration: &compute.LinuxConfiguration{
						DisablePasswordAuthentication: to.BoolPtr(true),
						SSH: &compute.SSHConfiguration{
							PublicKeys: &[]compute.SSHPublicKey{
								{
									Path:    to.StringPtr("/home/" + vmssAdminUsername + "/.ssh/authorized_keys"),
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
							Name: to.StringPtr(vmssNicName),
							VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
								Primary: to.BoolPtr(true),
								IPConfigurations: &[]compute.VirtualMachineScaleSetIPConfiguration{
									{
										Name: to.StringPtr(vmssIPConfigurationName),
										VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
											Subnet: &compute.APIEntityReference{
												ID: to.StringPtr(resourceid.ResourceID(
													cs.Properties.AzProfile.SubscriptionID,
													cs.Properties.AzProfile.ResourceGroup,
													"Microsoft.Network/virtualNetworks",
													VnetName,
												) + "/subnets/" + vnetSubnetName),
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
				ExtensionProfile: &compute.VirtualMachineScaleSetExtensionProfile{
					Extensions: &[]compute.VirtualMachineScaleSetExtension{
						{
							Name: to.StringPtr(vmssCSEName),
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
		Name:     to.StringPtr(config.GetScalesetName(app, suffix)),
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
			Name: to.StringPtr(vmssNicPublicIPConfigurationName),
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
					lbAPIServerName,
				) + "/backendAddressPools/" + lbAPIServerBackendPoolName),
			},
		}
		(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.NetworkSecurityGroup = &compute.SubResource{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				cs.Properties.AzProfile.ResourceGroup,
				"Microsoft.Network/networkSecurityGroups",
				nsgMasterName,
			)),
		}
	} else {
		(*(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.IPConfigurations)[0].LoadBalancerBackendAddressPools = &[]compute.SubResource{
			{
				ID: to.StringPtr(resourceid.ResourceID(
					cs.Properties.AzProfile.SubscriptionID,
					cs.Properties.AzProfile.ResourceGroup,
					"Microsoft.Network/loadBalancers",
					lbKubernetesName,
				) + "/backendAddressPools/" + lbKubernetesBackendPoolName),
			},
		}
		(*vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations)[0].VirtualMachineScaleSetNetworkConfigurationProperties.NetworkSecurityGroup = &compute.SubResource{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				cs.Properties.AzProfile.ResourceGroup,
				"Microsoft.Network/networkSecurityGroups",
				nsgWorkerName,
			)),
		}
	}

	if pc.TestConfig.ImageResourceName != "" {
		vmss.Plan = nil
		vmss.VirtualMachineScaleSetProperties.VirtualMachineProfile.StorageProfile.ImageReference = &compute.ImageReference{
			ID: to.StringPtr(resourceid.ResourceID(
				cs.Properties.AzProfile.SubscriptionID,
				pc.TestConfig.ImageResourceGroup,
				"Microsoft.Compute/images",
				pc.TestConfig.ImageResourceName,
			)),
		}
	}

	return vmss, nil
}
