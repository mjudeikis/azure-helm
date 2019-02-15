package api

import (
	"crypto/rsa"
	"crypto/x509"
)

type Config struct {
	// ClusterVersion defines release version of the plugin used to build the cluster
	ClusterVersion string `json:"clusterVersion,omitempty"`
	// configuration of VMs in ARM template
	ImageOffer     string `json:"imageOffer,omitempty"`
	ImagePublisher string `json:"imagePublisher,omitempty"`
	ImageSKU       string `json:"imageSku,omitempty"`
	ImageVersion   string `json:"imageVersion,omitempty"`

	Certificates CertificateConfig `json:"certificates,omitempty"`
	Images       ImageConfig       `json:"images,omitempty"`

	// Geneva Metrics System (MDM) sector used for logging
	GenevaLoggingSector string `json:"genevaLoggingSector,omitempty"`
	// Geneva Metrics System (MDM) logging account
	GenevaLoggingAccount string `json:"genevaLoggingAccount,omitempty"`
	// Geneva Metrics System (MDM) logging namespace
	GenevaLoggingNamespace string `json:"genevaLoggingNamespace,omitempty"`
	// Geneva Metrics System (MDM) logging control plane parameters
	GenevaLoggingControlPlaneAccount     string `json:"genevaLoggingControlPlaneAccount,omitempty"`
	GenevaLoggingControlPlaneEnvironment string `json:"genevaLoggingControlPlaneEnvironment,omitempty"`
	GenevaLoggingControlPlaneRegion      string `json:"genevaLoggingControlPlaneRegion,omitempty"`
	// Geneva Metrics System (MDM) account name for metrics
	GenevaMetricsAccount string `json:"genevaMetricsAccount,omitempty"`
	// Geneva Metrics System (MDM) endpoint for metrics
	GenevaMetricsEndpoint string `json:"genevaMetricsEndpoint,omitempty"`
}

// ImageConfig contains all images for the pods
type ImageConfig struct {
	// Format of the pull spec that is going to be
	// used in the cluster.
	Format                       string `json:"format,omitempty"`
	ClusterMonitoringOperator    string `json:"clusterMonitoringOperator,omitempty"`
	AzureControllers             string `json:"azureControllers,omitempty"`
	PrometheusOperatorBase       string `json:"prometheusOperatorBase,omitempty"`
	PrometheusBase               string `json:"prometheusBase,omitempty"`
	PrometheusConfigReloaderBase string `json:"prometheusConfigReloaderBase,omitempty"`
	ConfigReloaderBase           string `json:"configReloaderBase,omitempty"`
	AlertManagerBase             string `json:"alertManagerBase,omitempty"`
	NodeExporterBase             string `json:"nodeExporterBase,omitempty"`
	GrafanaBase                  string `json:"grafanaBase,omitempty"`
	KubeStateMetricsBase         string `json:"kubeStateMetricsBase,omitempty"`
	KubeRbacProxyBase            string `json:"kubeRbacProxyBase,omitempty"`
	OAuthProxyBase               string `json:"oAuthProxyBase,omitempty"`

	MasterEtcd            string `json:"masterEtcd,omitempty"`
	ControlPlane          string `json:"controlPlane,omitempty"`
	Node                  string `json:"node,omitempty"`
	ServiceCatalog        string `json:"serviceCatalog,omitempty"`
	Sync                  string `json:"sync,omitempty"`
	TemplateServiceBroker string `json:"templateServiceBroker,omitempty"`
	Registry              string `json:"registry,omitempty"`
	Router                string `json:"router,omitempty"`
	RegistryConsole       string `json:"registryConsole,omitempty"`
	AnsibleServiceBroker  string `json:"ansibleServiceBroker,omitempty"`
	WebConsole            string `json:"webConsole,omitempty"`
	Console               string `json:"console,omitempty"`
	EtcdBackup            string `json:"etcdBackup,omitempty"`

	// GenevaImagePullSecret defines secret used to pull private Azure images
	GenevaImagePullSecret []byte `json:"genevaImagePullSecret,omitempty"`
	// Geneva integration images
	GenevaLogging string `json:"genevaLogging,omitempty"`
	GenevaTDAgent string `json:"genevaTDAgent,omitempty"`
	GenevaStatsd  string `json:"genevaStatsd,omitempty"`
	MetricsBridge string `json:"metricsBridge,omitempty"`

	// ImagePullSecret defines the secret used to pull from the private registries, used system-wide
	ImagePullSecret []byte `json:"imagePullSecret,omitempty"`
}

// CertificateConfig contains all certificate configuration for the cluster.
type CertificateConfig struct {
	// geneva integration certificates
	GenevaLogging CertKeyPair `json:"genevaLogging,omitempty"`
	GenevaMetrics CertKeyPair `json:"genevaMetrics,omitempty"`
}

// CertKeyPair is an rsa private key and x509 certificate pair.
type CertKeyPair struct {
	Key  *rsa.PrivateKey   `json:"key,omitempty"`
	Cert *x509.Certificate `json:"cert,omitempty"`
}
