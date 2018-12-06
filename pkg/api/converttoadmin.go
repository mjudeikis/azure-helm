package api

import (
	admin "github.com/openshift/openshift-azure/pkg/api/admin/api"
)

func ConvertToAdmin(cs *OpenShiftManagedCluster) *admin.OpenShiftManagedCluster {
	oc := &admin.OpenShiftManagedCluster{
		ID:       &cs.ID,
		Location: &cs.Location,
		Name:     &cs.Name,
		Type:     &cs.Type,
	}
	oc.Tags = make(map[string]*string, len(cs.Tags))
	for k := range cs.Tags {
		v := cs.Tags[k]
		oc.Tags[k] = &v
	}

	oc.Plan = &admin.ResourcePurchasePlan{
		Name:          &cs.Plan.Name,
		Product:       &cs.Plan.Product,
		PromotionCode: &cs.Plan.PromotionCode,
		Publisher:     &cs.Plan.Publisher,
	}

	provisioningState := admin.ProvisioningState(cs.Properties.ProvisioningState)
	oc.Properties = &admin.Properties{
		ProvisioningState: &provisioningState,
		OpenShiftVersion:  &cs.Properties.OpenShiftVersion,
		PublicHostname:    &cs.Properties.PublicHostname,
		FQDN:              &cs.Properties.FQDN,
	}

	oc.Properties.NetworkProfile = &admin.NetworkProfile{
		VnetCIDR:   &cs.Properties.NetworkProfile.VnetCIDR,
		PeerVnetID: &cs.Properties.NetworkProfile.PeerVnetID,
	}

	oc.Properties.RouterProfiles = make([]admin.RouterProfile, len(cs.Properties.RouterProfiles))
	for i := range cs.Properties.RouterProfiles {
		rp := cs.Properties.RouterProfiles[i]
		oc.Properties.RouterProfiles[i] = admin.RouterProfile{
			Name:            &rp.Name,
			PublicSubdomain: &rp.PublicSubdomain,
			FQDN:            &rp.FQDN,
		}
	}

	oc.Properties.AgentPoolProfiles = make([]admin.AgentPoolProfile, 0, len(cs.Properties.AgentPoolProfiles))
	for i := range cs.Properties.AgentPoolProfiles {
		app := cs.Properties.AgentPoolProfiles[i]
		vmSize := admin.VMSize(app.VMSize)
		osType := admin.OSType(app.OSType)
		role := admin.AgentPoolProfileRole(app.Role)

		oc.Properties.AgentPoolProfiles = append(oc.Properties.AgentPoolProfiles, admin.AgentPoolProfile{
			Name:       &app.Name,
			Count:      &app.Count,
			VMSize:     &vmSize,
			SubnetCIDR: &app.SubnetCIDR,
			OSType:     &osType,
			Role:       &role,
		})
	}

	oc.Properties.AuthProfile = &admin.AuthProfile{}
	oc.Properties.AuthProfile.IdentityProviders = make([]admin.IdentityProvider, len(cs.Properties.AuthProfile.IdentityProviders))
	for i := range cs.Properties.AuthProfile.IdentityProviders {
		ip := cs.Properties.AuthProfile.IdentityProviders[i]
		oc.Properties.AuthProfile.IdentityProviders[i].Name = &ip.Name
		switch provider := ip.Provider.(type) {
		case *AADIdentityProvider:
			oc.Properties.AuthProfile.IdentityProviders[i].Provider = &admin.AADIdentityProvider{
				Kind:     &provider.Kind,
				ClientID: &provider.ClientID,
				TenantID: &provider.TenantID,
			}

		default:
			panic("authProfile.identityProviders conversion failed")
		}
	}

	oc.Config = convertConfigToAdmin(&cs.Config)

	return oc
}

func convertConfigToAdmin(cs *Config) *admin.Config {
	return &admin.Config{
		ImageOffer:                       &cs.ImageOffer,
		ImagePublisher:                   &cs.ImagePublisher,
		ImageSKU:                         &cs.ImageSKU,
		ImageVersion:                     &cs.ImageVersion,
		ConfigStorageAccount:             &cs.ConfigStorageAccount,
		RegistryStorageAccount:           &cs.RegistryStorageAccount,
		Certificates:                     convertCertificateConfigToAdmin(cs.Certificates),
		Images:                           convertImageConfigToAdmin(cs.Images),
		ServiceCatalogClusterID:          &cs.ServiceCatalogClusterID,
		GenevaLoggingSector:              &cs.GenevaLoggingSector,
		GenevaLoggingAccount:             &cs.GenevaLoggingAccount,
		GenevaLoggingNamespace:           &cs.GenevaLoggingNamespace,
		GenevaLoggingControlPlaneAccount: &cs.GenevaLoggingControlPlaneAccount,
	}
}

func convertCertificateConfigToAdmin(in CertificateConfig) *admin.CertificateConfig {
	return &admin.CertificateConfig{
		EtcdCa:                  convertCertKeyPairToAdmin(in.EtcdCa),
		Ca:                      convertCertKeyPairToAdmin(in.Ca),
		FrontProxyCa:            convertCertKeyPairToAdmin(in.FrontProxyCa),
		ServiceSigningCa:        convertCertKeyPairToAdmin(in.ServiceSigningCa),
		ServiceCatalogCa:        convertCertKeyPairToAdmin(in.ServiceCatalogCa),
		EtcdServer:              convertCertKeyPairToAdmin(in.EtcdServer),
		EtcdPeer:                convertCertKeyPairToAdmin(in.EtcdPeer),
		EtcdClient:              convertCertKeyPairToAdmin(in.EtcdClient),
		MasterServer:            convertCertKeyPairToAdmin(in.MasterServer),
		OpenshiftConsole:        convertCertKeyPairToAdmin(in.OpenshiftConsole),
		Admin:                   convertCertKeyPairToAdmin(in.Admin),
		AggregatorFrontProxy:    convertCertKeyPairToAdmin(in.AggregatorFrontProxy),
		MasterKubeletClient:     convertCertKeyPairToAdmin(in.MasterKubeletClient),
		MasterProxyClient:       convertCertKeyPairToAdmin(in.MasterProxyClient),
		OpenShiftMaster:         convertCertKeyPairToAdmin(in.OpenShiftMaster),
		NodeBootstrap:           convertCertKeyPairToAdmin(in.NodeBootstrap),
		Registry:                convertCertKeyPairToAdmin(in.Registry),
		Router:                  convertCertKeyPairToAdmin(in.Router),
		ServiceCatalogServer:    convertCertKeyPairToAdmin(in.ServiceCatalogServer),
		ServiceCatalogAPIClient: convertCertKeyPairToAdmin(in.ServiceCatalogAPIClient),
		AzureClusterReader:      convertCertKeyPairToAdmin(in.AzureClusterReader),
		GenevaLogging:           convertCertKeyPairToAdmin(in.GenevaLogging),
	}
}

func convertCertKeyPairToAdmin(in CertKeyPair) *admin.Certificate {
	return &admin.Certificate{
		Cert: in.Cert,
	}
}

func convertImageConfigToAdmin(in ImageConfig) *admin.ImageConfig {
	return &admin.ImageConfig{
		Format:                       &in.Format,
		ClusterMonitoringOperator:    &in.ClusterMonitoringOperator,
		AzureControllers:             &in.AzureControllers,
		PrometheusOperatorBase:       &in.PrometheusOperatorBase,
		PrometheusBase:               &in.PrometheusBase,
		PrometheusConfigReloaderBase: &in.PrometheusConfigReloaderBase,
		ConfigReloaderBase:           &in.ConfigReloaderBase,
		AlertManagerBase:             &in.AlertManagerBase,
		NodeExporterBase:             &in.NodeExporterBase,
		GrafanaBase:                  &in.GrafanaBase,
		KubeStateMetricsBase:         &in.KubeStateMetricsBase,
		KubeRbacProxyBase:            &in.KubeRbacProxyBase,
		OAuthProxyBase:               &in.OAuthProxyBase,
		MasterEtcd:                   &in.MasterEtcd,
		ControlPlane:                 &in.ControlPlane,
		Node:                         &in.Node,
		ServiceCatalog:               &in.ServiceCatalog,
		Sync:                         &in.Sync,
		TemplateServiceBroker:        &in.TemplateServiceBroker,
		Registry:                     &in.Registry,
		Router:                       &in.Router,
		RegistryConsole:              &in.RegistryConsole,
		AnsibleServiceBroker:         &in.AnsibleServiceBroker,
		WebConsole:                   &in.WebConsole,
		Console:                      &in.Console,
		EtcdBackup:                   &in.EtcdBackup,
		GenevaLogging:                &in.GenevaLogging,
		GenevaTDAgent:                &in.GenevaTDAgent,
	}
}
