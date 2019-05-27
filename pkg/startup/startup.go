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
	v3 "github.com/openshift/openshift-azure/pkg/startup/v3"
	v4 "github.com/openshift/openshift-azure/pkg/startup/v4"
	v5 "github.com/openshift/openshift-azure/pkg/startup/v5"
	v6 "github.com/openshift/openshift-azure/pkg/startup/v6"

	v7 "github.com/openshift/openshift-azure/pkg/startup/v7"
)

// Interface is a singleton interface to interact with startup
type Interface interface {
	WriteFiles(ctx context.Context) error
	Hash(role api.AgentPoolProfileRole) ([]byte, error)
}

// New returns a new startup Interface according to the cluster version running
func New(log *logrus.Entry, cs *api.OpenShiftManagedCluster, testConfig api.TestConfig) (Interface, error) {
	switch cs.Config.PluginVersion {
	case "v3.2":
		return v3.New(log, cs, testConfig), nil
	case "v4.2", "v4.3", "v4.4":
		return v4.New(log, cs, testConfig), nil
	case "v5.1":
		return v5.New(log, cs, testConfig), nil
	case "v6.0":
		return v6.New(log, cs, testConfig), nil
	case "v7.0":
		return v7.New(log, cs, testConfig), nil
	}

	return nil, fmt.Errorf("version %q not found", cs.Config.PluginVersion)
}
