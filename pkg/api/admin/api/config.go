package api

import (
	"crypto/x509"

	"github.com/satori/go.uuid"
)

type Config struct {
	// configuration of VMs in ARM template
	ImageOffer     *string `json:"imageOffer,omitempty"`
	ImagePublisher *string `json:"imagePublisher,omitempty"`
	ImageSKU       *string `json:"imageSku,omitempty"`
	ImageVersion   *string `json:"imageVersion,omitempty"`

	// configuration of other ARM resources
	ConfigStorageAccount   *string `json:"configStorageAccount,omitempty"`
	RegistryStorageAccount *string `json:"registryStorageAccount,omitempty"`

	Certificates *CertificateConfig `json:"certificates,omitempty"`
	Images       *ImageConfig       `json:"images,omitempty"`

	// misc infra configurables
	ServiceCatalogClusterID *uuid.UUID `json:"serviceCatalogClusterId,omitempty"`

	// geneva logging sector
	GenevaLoggingSector    *string `json:"genevaLoggingSector,omitempty"`
	GenevaLoggingAccount   *string `json:"genevaLoggingAccount,omitempty"`
	GenevaLoggingNamespace *string `json:"genevaLoggingNamespace,omitempty"`
}

// ImageConfig contains all images for the pods
type ImageConfig struct {
	// Format of the pull spec that is going to be
	// used in the cluster.
	Format *string `json:"format,omitempty"`

	ClusterMonitoringOperator    *string `json:"clusterMonitoringOperator,omitempty"`
	AzureControllers             *string `json:"azureControllers,omitempty"`
	PrometheusOperatorBase       *string `json:"prometheusOperatorBase,omitempty"`
	PrometheusBase               *string `json:"prometheusBase,omitempty"`
	PrometheusConfigReloaderBase *string `json:"prometheusConfigReloaderBase,omitempty"`
	ConfigReloaderBase           *string `json:"configReloaderBase,omitempty"`
	AlertManagerBase             *string `json:"alertManagerBase,omitempty"`
	NodeExporterBase             *string `json:"nodeExporterBase,omitempty"`
	GrafanaBase                  *string `json:"grafanaBase,omitempty"`
	KubeStateMetricsBase         *string `json:"kubeStateMetricsBase,omitempty"`
	KubeRbacProxyBase            *string `json:"kubeRbacProxyBase,omitempty"`
	OAuthProxyBase               *string `json:"oAuthProxyBase,omitempty"`

	MasterEtcd            *string `json:"masterEtcd,omitempty"`
	ControlPlane          *string `json:"controlPlane,omitempty"`
	Node                  *string `json:"node,omitempty"`
	ServiceCatalog        *string `json:"serviceCatalog,omitempty"`
	Sync                  *string `json:"sync,omitempty"`
	TemplateServiceBroker *string `json:"templateServiceBroker,omitempty"`
	Registry              *string `json:"registry,omitempty"`
	Router                *string `json:"router,omitempty"`
	RegistryConsole       *string `json:"registryConsole,omitempty"`
	AnsibleServiceBroker  *string `json:"ansibleServiceBroker,omitempty"`
	WebConsole            *string `json:"webConsole,omitempty"`
	Console               *string `json:"console,omitempty"`
	EtcdBackup            *string `json:"etcdBackup,omitempty"`

	// Geneva integration images
	GenevaLogging *string `json:"genevaLogging,omitempty"`
	GenevaTDAgent *string `json:"genevaTDAgent,omitempty"`
}

// CertificateConfig contains all certificate configuration for the cluster.
type CertificateConfig struct {
	// CAs
	EtcdCa           *Certificate `json:"etcdCa,omitempty"`
	Ca               *Certificate `json:"ca,omitempty"`
	FrontProxyCa     *Certificate `json:"frontProxyCa,omitempty"`
	ServiceSigningCa *Certificate `json:"serviceSigningCa,omitempty"`
	ServiceCatalogCa *Certificate `json:"serviceCatalogCa,omitempty"`

	// etcd certificates
	EtcdServer *Certificate `json:"etcdServer,omitempty"`
	EtcdPeer   *Certificate `json:"etcdPeer,omitempty"`
	EtcdClient *Certificate `json:"etcdClient,omitempty"`

	// control plane certificates
	MasterServer         *Certificate `json:"masterServer,omitempty"`
	OpenshiftConsole     *Certificate `json:"openshiftConsole,omitempty"`
	Admin                *Certificate `json:"admin,omitempty"`
	AggregatorFrontProxy *Certificate `json:"aggregatorFrontProxy,omitempty"`
	MasterKubeletClient  *Certificate `json:"masterKubeletClient,omitempty"`
	MasterProxyClient    *Certificate `json:"masterProxyClient,omitempty"`
	OpenShiftMaster      *Certificate `json:"openShiftMaster,omitempty"`
	NodeBootstrap        *Certificate `json:"nodeBootstrap,omitempty"`

	// infra certificates
	Registry                *Certificate `json:"registry,omitempty"`
	Router                  *Certificate `json:"router,omitempty"`
	ServiceCatalogServer    *Certificate `json:"serviceCatalogServer,omitempty"`
	ServiceCatalogAPIClient *Certificate `json:"serviceCatalogAPIClient,omitempty"`

	// misc certificates
	AzureClusterReader *Certificate `json:"azureClusterReader,omitempty"`

	// geneva integration certificates
	GenevaLogging *Certificate `json:"genevaLogging,omitempty"`
}

// Certificate is an x509 certificate.
type Certificate struct {
	Cert *x509.Certificate `json:"cert,omitempty"`
}
