// Package api defines the external API for the plugin.
package api

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
)

// ContextKey is a type for context property bag payload keys
type ContextKey string

const (
	ContextKeyClientID     ContextKey = "ClientID"
	ContextKeyClientSecret ContextKey = "ClientSecret"
	ContextKeyTenantID     ContextKey = "TenantID"
)

type PluginStep string

const (
	PluginStepDeploy                     PluginStep = "Deploy"
	PluginStepInitialize                 PluginStep = "Initialize"
	PluginStepHashScaleSets              PluginStep = "HashScaleSets"
	PluginStepInitializeUpdateBlob       PluginStep = "InitializeUpdateBlob"
	PluginStepClientCreation             PluginStep = "ClientCreation"
	PluginStepScaleSetDelete             PluginStep = "ScaleSetDelete"
	PluginStepDrain                      PluginStep = "Drain"
	PluginStepGenerateARM                PluginStep = "GenerateARM"
	PluginStepWaitForWaitForOpenShiftAPI PluginStep = "WaitForOpenShiftAPI"
	PluginStepWaitForNodes               PluginStep = "WaitForNodes"
	PluginStepWaitForConsoleHealth       PluginStep = "WaitForConsoleHealth"
	PluginStepWaitForInfraDaemonSets     PluginStep = "WaitForInfraDaemonSets"
	PluginStepWaitForInfraStatefulSets   PluginStep = "WaitForInfraStatefulSets"
	PluginStepWaitForInfraDeployments    PluginStep = "WaitForInfraDeployments"
	PluginStepUpdateInPlaceListVMs       PluginStep = "UpdateInPlaceListVMs"
	PluginStepUpdateInPlaceSortMasters   PluginStep = "UpdateInPlaceSortMasters"
	PluginStepUpdateInPlaceReadBlob      PluginStep = "UpdateInPlaceReadBlob"
	PluginStepUpdateInPlaceDrain         PluginStep = "UpdateInPlaceDrain"
	PluginStepUpdateInPlaceDeallocate    PluginStep = "UpdateInPlaceDeallocate"
	PluginStepUpdateInPlaceUpdateVMs     PluginStep = "UpdateInPlaceUpdateVMs"
	PluginStepUpdateInPlaceReimage       PluginStep = "UpdateInPlaceReimage"
	PluginStepUpdateInPlaceStart         PluginStep = "UpdateInPlaceStart"
	PluginStepUpdateInPlaceWaitForReady  PluginStep = "UpdateInPlaceWaitForReady"
	PluginStepUpdateInPlaceUpdateBlob    PluginStep = "UpdateInPlaceUpdateBlob"
	PluginStepUpdatePlusOneListVMs       PluginStep = "UpdatePlusOneListVMs"
	PluginStepUpdatePlusOneReadBlob      PluginStep = "UpdatePlusOneReadBlob"
	PluginStepUpdatePlusOneWaitForReady  PluginStep = "UpdatePlusOneWaitForReady"
	PluginStepUpdatePlusOneUpdateBlob    PluginStep = "UpdatePlusOneUpdateBlob"
	PluginStepUpdatePlusOneDeleteVMs     PluginStep = "UpdatePlusOneDeleteVMs"
	PluginStepDeleteBlob                 PluginStep = "DeleteBlob"
)

// PluginError error returned by CreateOrUpdate to specify the step that failed.
type PluginError struct {
	Err  error
	Step PluginStep
}

var _ error = &PluginError{}

func (pe *PluginError) Error() string {
	return string(pe.Step) + ": " + pe.Err.Error()
}

// DeployFn makes it possible to plug in different logic to the deploy.
// The implementor must initiate a deployment of the given template using
// mode resources.Incremental and wait for it to complete.
type DeployFn func(context.Context, map[string]interface{}) error

// PluginConfig is passed into NewPlugin
type PluginConfig struct {
	SyncImage       string
	AcceptLanguages []string
	GenevaConfig    GenevaConfig

	TestConfig TestConfig
}

// TestConfig holds all testing variables.  It should be empty in production.
type TestConfig struct {
	RunningUnderTest      bool
	ImageResourceGroup    string
	ImageResourceName     string
	ImageOffer            string
	ImageVersion          string
	DeployOS              string
	ORegURL               string
	EtcdBackupImage       string
	AzureControllersImage string
}

// GenevaConfig holds all configuration for Plugin integration with Azure
type GenevaConfig struct {
	// common values
	ImagePullSecret []byte

	// logging configuration
	LoggingCert                *x509.Certificate
	LoggingKey                 *rsa.PrivateKey
	LoggingSector              string
	LoggingControlPlaneAccount string
	LoggingAccount             string
	LoggingNamespace           string
	LoggingImage               string
	TDAgentImage               string

	// TODO: metrics configuration
}

// Plugin is the main interface to openshift-azure
type Plugin interface {
	// Validate exists (a) to be able to place validation logic in a
	// single place in the event of multiple external API versions, and (b) to
	// be able to compare a new API manifest against a pre-existing API manifest
	// (for update, upgrade, etc.)
	// externalOnly indicates that fields set by the RP (FQDN and routerProfile.FQDN)
	// should be excluded.
	Validate(ctx context.Context, new, old *OpenShiftManagedCluster, externalOnly bool) []error

	// GenerateConfig ensures all the necessary in-cluster config is generated
	// for an Openshift cluster.
	GenerateConfig(ctx context.Context, cs *OpenShiftManagedCluster) error

	GenerateARM(ctx context.Context, cs *OpenShiftManagedCluster, isUpdate bool) (map[string]interface{}, error)

	// CreateOrUpdate either deploys or runs the update depending on the isUpdate argument
	// this will call the deployer.
	CreateOrUpdate(ctx context.Context, cs *OpenShiftManagedCluster, azuretemplate map[string]interface{}, isUpdate bool, deployer DeployFn) *PluginError

	// RecoverEtcdCluster recovers the cluster's etcd using the backup specified in the pluginConfig
	RecoverEtcdCluster(ctx context.Context, cs *OpenShiftManagedCluster, deployer DeployFn, backupBlob string) *PluginError
}
