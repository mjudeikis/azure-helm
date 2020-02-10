package startup

//go:generate go get github.com/golang/mock/mockgen
//go:generate mockgen -destination=../util/mocks/mock_$GOPACKAGE/startup.go -package=mock_$GOPACKAGE -source startup.go
//go:generate gofmt -s -l -w ../util/mocks/mock_$GOPACKAGE/startup.go
//go:generate go get golang.org/x/tools/cmd/goimports
//go:generate goimports -local=github.com/openshift/openshift-azure -e -w ../util/mocks/mock_$GOPACKAGE/startup.go

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/openshift/openshift-azure/pkg/api"
	v10 "github.com/openshift/openshift-azure/pkg/startup/v10"
	v12 "github.com/openshift/openshift-azure/pkg/startup/v12"
	v14 "github.com/openshift/openshift-azure/pkg/startup/v14"
	v15 "github.com/openshift/openshift-azure/pkg/startup/v15"
	v71 "github.com/openshift/openshift-azure/pkg/startup/v71"
)

// Interface is a singleton interface to interact with startup
type Interface interface {
	WriteFiles(ctx context.Context) error
	Hash(role api.AgentPoolProfileRole) ([]byte, error)
	GetWorkerCs() *api.OpenShiftManagedCluster
	// currently only implemented in v15 only
	WriteSearchDomain(ctx context.Context, log *logrus.Entry, role api.AgentPoolProfileRole) error
}

// New returns a new startup Interface according to the cluster version running
func New(log *logrus.Entry, cs *api.OpenShiftManagedCluster, testConfig api.TestConfig) (Interface, error) {
	switch cs.Config.PluginVersion {
	case "v7.1":
		return v71.New(log, cs, testConfig), nil
	case "v10.0", "v10.1", "v10.2":
		return v10.New(log, cs, testConfig), nil
	case "v12.0", "v12.1", "v12.2":
		return v12.New(log, cs, testConfig), nil
	case "v14.0", "v14.1":
		return v14.New(log, cs, testConfig), nil
	case "v15.0":
		return v15.New(log, cs, testConfig), nil
	}

	return nil, fmt.Errorf("version %q not found", cs.Config.PluginVersion)
}
