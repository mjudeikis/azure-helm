package config

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"

	"github.com/satori/go.uuid"
	"k8s.io/client-go/tools/clientcmd/api/v1"

	api "github.com/openshift/openshift-azure/pkg/api"
	pluginapi "github.com/openshift/openshift-azure/pkg/api/plugin/api"
	"github.com/openshift/openshift-azure/pkg/tls"
)

func (g *simpleGenerator) Generate(cs *api.OpenShiftManagedCluster, template *pluginapi.Config) (err error) {
	config := api.ConvertFromPlugin(template, &cs.Config)
	cs.Config = *config
	c := &cs.Config

	// Generate CAs
	cas := []struct {
		cn   string
		key  **rsa.PrivateKey
		cert **x509.Certificate
	}{
		{
			cn:   "etcd-signer",
			key:  &c.Certificates.EtcdCa.Key,
			cert: &c.Certificates.EtcdCa.Cert,
		},
		{
			cn:   "openshift-signer",
			key:  &c.Certificates.Ca.Key,
			cert: &c.Certificates.Ca.Cert,
		},
		{
			cn:   "openshift-frontproxy-signer",
			key:  &c.Certificates.FrontProxyCa.Key,
			cert: &c.Certificates.FrontProxyCa.Cert,
		},
		{
			cn:   "openshift-service-serving-signer",
			key:  &c.Certificates.ServiceSigningCa.Key,
			cert: &c.Certificates.ServiceSigningCa.Cert,
		},
		{
			cn:   "service-catalog-signer",
			key:  &c.Certificates.ServiceCatalogCa.Key,
			cert: &c.Certificates.ServiceCatalogCa.Cert,
		},
	}
	for _, ca := range cas {
		if *ca.key != nil && *ca.cert != nil {
			continue
		}
		if *ca.key, *ca.cert, err = tls.NewCA(ca.cn); err != nil {
			return
		}
	}

	certs := []struct {
		params tls.CertParams
		key    **rsa.PrivateKey
		cert   **x509.Certificate
	}{
		// Generate etcd certs
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "etcd-server",
				},
				DNSNames:    []string{"master-000000", "master-000001", "master-000002"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				SigningKey:  c.Certificates.EtcdCa.Key,
				SigningCert: c.Certificates.EtcdCa.Cert,
			},
			key:  &c.Certificates.EtcdServer.Key,
			cert: &c.Certificates.EtcdServer.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "etcd-peer",
				},
				DNSNames:    []string{"master-000000", "master-000001", "master-000002"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				SigningKey:  c.Certificates.EtcdCa.Key,
				SigningCert: c.Certificates.EtcdCa.Cert,
			},
			key:  &c.Certificates.EtcdPeer.Key,
			cert: &c.Certificates.EtcdPeer.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "etcd-client",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				SigningKey:  c.Certificates.EtcdCa.Key,
				SigningCert: c.Certificates.EtcdCa.Cert,
			},
			key:  &c.Certificates.EtcdClient.Key,
			cert: &c.Certificates.EtcdClient.Cert,
		},
		// Generate openshift master certs
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName:   "system:admin",
					Organization: []string{"system:cluster-admins", "system:masters"},
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.Admin.Key,
			cert: &c.Certificates.Admin.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "aggregator-front-proxy",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				SigningKey:  c.Certificates.FrontProxyCa.Key,
				SigningCert: c.Certificates.FrontProxyCa.Cert,
			},
			key:  &c.Certificates.AggregatorFrontProxy.Key,
			cert: &c.Certificates.AggregatorFrontProxy.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{CommonName: "system:openshift-node-admin",
					Organization: []string{"system:node-admins"},
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.MasterKubeletClient.Key,
			cert: &c.Certificates.MasterKubeletClient.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "system:master-proxy",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.MasterProxyClient.Key,
			cert: &c.Certificates.MasterProxyClient.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: cs.Properties.FQDN,
				},
				DNSNames: []string{
					cs.Properties.FQDN,
					"master-000000",
					"master-000001",
					"master-000002",
					"kubernetes",
					"kubernetes.default",
					"kubernetes.default.svc",
					"kubernetes.default.svc.cluster.local",
				},
				IPAddresses: []net.IP{net.ParseIP("172.30.0.1")},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			key:  &c.Certificates.MasterServer.Key,
			cert: &c.Certificates.MasterServer.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{CommonName: "system:openshift-master",
					Organization: []string{"system:cluster-admins", "system:masters"},
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.OpenShiftMaster.Key,
			cert: &c.Certificates.OpenShiftMaster.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "servicecatalog-api",
				},
				DNSNames: []string{
					"servicecatalog-api",
					"apiserver.kube-service-catalog.svc", // TODO: unclear how safe this is
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				SigningKey:  c.Certificates.ServiceCatalogCa.Key,
				SigningCert: c.Certificates.ServiceCatalogCa.Cert,
			},
			key:  &c.Certificates.ServiceCatalogServer.Key,
			cert: &c.Certificates.ServiceCatalogServer.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "system:serviceaccount:kube-service-catalog:service-catalog-apiserver",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.ServiceCatalogAPIClient.Key,
			cert: &c.Certificates.ServiceCatalogAPIClient.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "system:serviceaccount:openshift-infra:node-bootstrapper",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.NodeBootstrap.Key,
			cert: &c.Certificates.NodeBootstrap.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "system:serviceaccount:openshift-azure:azure-cluster-reader",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			key:  &c.Certificates.AzureClusterReader.Key,
			cert: &c.Certificates.AzureClusterReader.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: cs.Properties.RouterProfiles[0].PublicSubdomain,
				},
				DNSNames: []string{
					cs.Properties.RouterProfiles[0].PublicSubdomain,
					"*." + cs.Properties.RouterProfiles[0].PublicSubdomain,
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			key:  &c.Certificates.Router.Key,
			cert: &c.Certificates.Router.Cert,
		},
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: "docker-registry-default." + cs.Properties.RouterProfiles[0].PublicSubdomain,
				},
				DNSNames: []string{
					"docker-registry-default." + cs.Properties.RouterProfiles[0].PublicSubdomain,
					"docker-registry.default.svc",
					"docker-registry.default.svc.cluster.local",
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			key:  &c.Certificates.Registry.Key,
			cert: &c.Certificates.Registry.Cert,
		},
		// Do not attempt to make the OpenShift console certificate self-signed
		// if cs.Properties == cs.FQDN:
		// https://github.com/openshift/openshift-azure/issues/307
		{
			params: tls.CertParams{
				Subject: pkix.Name{
					CommonName: Derived.PublicHostname(cs),
				},
				DNSNames: []string{
					Derived.PublicHostname(cs),
				},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			key:  &c.Certificates.OpenShiftConsole.Key,
			cert: &c.Certificates.OpenShiftConsole.Cert,
		},
	}
	for _, cert := range certs {
		if cert.params.SigningKey == nil && cert.params.SigningCert == nil {
			cert.params.SigningKey, cert.params.SigningCert = c.Certificates.Ca.Key, c.Certificates.Ca.Cert
		}
		if !tls.CertMatchesParams(*cert.key, *cert.cert, &cert.params) {
			if *cert.key, *cert.cert, err = tls.NewCert(&cert.params); err != nil {
				return
			}
		}
	}

	secrets := []struct {
		secret *[]byte
		n      int
	}{
		{
			secret: &c.SessionSecretAuth,
			n:      24,
		},
		{
			secret: &c.SessionSecretEnc,
			n:      24,
		},
		{
			secret: &c.RegistryHTTPSecret,
		},
		{
			secret: &c.AlertManagerProxySessionSecret,
		},
		{
			secret: &c.AlertsProxySessionSecret,
		},
		{
			secret: &c.PrometheusProxySessionSecret,
		},
	}
	for _, s := range secrets {
		if len(*s.secret) != 0 {
			continue
		}
		if s.n == 0 {
			s.n = 32
		}
		if *s.secret, err = randomBytes(s.n); err != nil {
			return
		}
	}

	kubeconfigs := []struct {
		clientKey  *rsa.PrivateKey
		clientCert *x509.Certificate
		endpoint   string
		username   string
		namespace  string
		kubeconfig **v1.Config
	}{
		{
			clientKey:  c.Certificates.OpenShiftMaster.Key,
			clientCert: c.Certificates.OpenShiftMaster.Cert,
			endpoint:   cs.Properties.FQDN,
			username:   "system:openshift-master",
			kubeconfig: &c.MasterKubeconfig,
		},
		{
			clientKey:  c.Certificates.Admin.Key,
			clientCert: c.Certificates.Admin.Cert,
			endpoint:   cs.Properties.FQDN,
			username:   "system:admin",
			kubeconfig: &c.AdminKubeconfig,
		},
		{
			clientKey:  c.Certificates.NodeBootstrap.Key,
			clientCert: c.Certificates.NodeBootstrap.Cert,
			endpoint:   cs.Properties.FQDN,
			username:   "system:serviceaccount:openshift-infra:node-bootstrapper",
			kubeconfig: &c.NodeBootstrapKubeconfig,
			namespace:  "openshift-infra",
		},
		{
			clientKey:  c.Certificates.AzureClusterReader.Key,
			clientCert: c.Certificates.AzureClusterReader.Cert,
			endpoint:   cs.Properties.FQDN,
			username:   "system:serviceaccount:openshift-azure:azure-cluster-reader",
			kubeconfig: &c.AzureClusterReaderKubeconfig,
			namespace:  "openshift-azure",
		},
	}
	for _, kc := range kubeconfigs {
		if kc.namespace == "" {
			kc.namespace = "default"
		}
		if *kc.kubeconfig, err = makeKubeConfig(kc.clientKey, kc.clientCert, c.Certificates.Ca.Cert, kc.endpoint, kc.username, kc.namespace); err != nil {
			return
		}
	}

	if c.ServiceAccountKey == nil {
		if c.ServiceAccountKey, err = tls.NewPrivateKey(); err != nil {
			return
		}
	}

	if g.pluginConfig.TestConfig.RunningUnderTest {
		c.RunningUnderTest = true
	}

	if c.SSHKey == nil {
		if c.SSHKey, err = tls.NewPrivateKey(); err != nil {
			return
		}
	}

	if len(c.RegistryStorageAccount) == 0 {
		if c.RegistryStorageAccount, err = randomStorageAccountName(); err != nil {
			return
		}
	}

	if len(c.ConfigStorageAccount) == 0 {
		if c.ConfigStorageAccount, err = randomStorageAccountName(); err != nil {
			return
		}
	}

	if len(c.RegistryConsoleOAuthSecret) == 0 {
		var pass string
		if pass, err = randomString(64); err != nil {
			return err
		}
		c.RegistryConsoleOAuthSecret = fmt.Sprintf("user%s", pass)
	}

	if len(c.ConsoleOAuthSecret) == 0 {
		if c.ConsoleOAuthSecret, err = randomString(64); err != nil {
			return err
		}
	}

	if len(c.RouterStatsPassword) == 0 {
		if c.RouterStatsPassword, err = randomString(10); err != nil {
			return
		}
	}

	if uuid.Equal(c.ServiceCatalogClusterID, uuid.Nil) {
		c.ServiceCatalogClusterID = uuid.NewV4()
	}

	return
}

// InvalidateSecrets removes all non-ca certificates, private keys and secrets from an
// OpenShiftManagedCluster's Config
func (g *simpleGenerator) InvalidateSecrets(cs *api.OpenShiftManagedCluster) (err error) {
	cs.Config.Certificates.Admin = api.CertKeyPair{}
	cs.Config.Certificates.AggregatorFrontProxy = api.CertKeyPair{}
	cs.Config.Certificates.AzureClusterReader = api.CertKeyPair{}
	cs.Config.Certificates.EtcdClient = api.CertKeyPair{}
	cs.Config.Certificates.EtcdPeer = api.CertKeyPair{}
	cs.Config.Certificates.EtcdServer = api.CertKeyPair{}
	cs.Config.Certificates.GenevaLogging = api.CertKeyPair{}
	cs.Config.Certificates.GenevaMetrics = api.CertKeyPair{}
	cs.Config.Certificates.MasterKubeletClient = api.CertKeyPair{}
	cs.Config.Certificates.MasterProxyClient = api.CertKeyPair{}
	cs.Config.Certificates.MasterServer = api.CertKeyPair{}
	cs.Config.Certificates.NodeBootstrap = api.CertKeyPair{}
	cs.Config.Certificates.OpenShiftConsole = api.CertKeyPair{}
	cs.Config.Certificates.OpenShiftMaster = api.CertKeyPair{}
	cs.Config.Certificates.Registry = api.CertKeyPair{}
	cs.Config.Certificates.Router = api.CertKeyPair{}
	cs.Config.Certificates.ServiceCatalogAPIClient = api.CertKeyPair{}
	cs.Config.Certificates.ServiceCatalogServer = api.CertKeyPair{}

	cs.Config.SSHKey = nil
	cs.Config.RegistryHTTPSecret = nil
	cs.Config.RegistryConsoleOAuthSecret = ""
	cs.Config.ConsoleOAuthSecret = ""
	cs.Config.AlertManagerProxySessionSecret = nil
	cs.Config.AlertsProxySessionSecret = nil
	cs.Config.PrometheusProxySessionSecret = nil
	cs.Config.SessionSecretAuth = nil
	cs.Config.SessionSecretEnc = nil
	cs.Config.Images.GenevaImagePullSecret = nil

	return
}
