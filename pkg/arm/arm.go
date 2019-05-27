package arm

//go:generate go get github.com/golang/mock/mockgen
//go:generate mockgen -destination=../util/mocks/mock_$GOPACKAGE/arm.go -package=mock_$GOPACKAGE -source arm.go
//go:generate gofmt -s -l -w ../util/mocks/mock_$GOPACKAGE/arm.go
//go:generate go get golang.org/x/tools/cmd/goimports
//go:generate goimports -local=github.com/openshift/openshift-azure -e -w ../util/mocks/mock_$GOPACKAGE/arm.go

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
	"github.com/sirupsen/logrus"

	"github.com/openshift/openshift-azure/pkg/api"
	v3 "github.com/openshift/openshift-azure/pkg/arm/v3"
	v4 "github.com/openshift/openshift-azure/pkg/arm/v4"
	v5 "github.com/openshift/openshift-azure/pkg/arm/v5"
	v6 "github.com/openshift/openshift-azure/pkg/arm/v6"

	// v4.2
	v7 "github.com/openshift/openshift-azure/pkg/arm/v7"
)

type Interface interface {
	Generate(ctx context.Context, backupBlob string, isUpdate bool, suffix string) (map[string]interface{}, error)
	Vmss(app *api.AgentPoolProfile, backupBlob, suffix string) (*compute.VirtualMachineScaleSet, error)
	Hash(app *api.AgentPoolProfile) ([]byte, error)
}

func New(ctx context.Context, log *logrus.Entry, cs *api.OpenShiftManagedCluster, testConfig api.TestConfig) (Interface, error) {
	switch cs.Config.PluginVersion {
	case "v3.2":
		return v3.New(ctx, log, cs, testConfig), nil
	case "v4.2", "v4.3", "v4.4":
		return v4.New(ctx, log, cs, testConfig), nil
	case "v5.1":
		return v5.New(ctx, log, cs, testConfig), nil
	case "v6.0":
		return v6.New(ctx, log, cs, testConfig), nil
	case "v7.0":
		return v7.New(ctx, log, cs, testConfig), nil
	}

	return nil, fmt.Errorf("version %q not found", cs.Config.PluginVersion)
}
