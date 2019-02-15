package standard

import (
	"context"

	"github.com/sirupsen/logrus"

	internalapi "github.com/openshift/openshift-azure/pkg/api"
	shared "github.com/openshift/openshift-azure/pkg/fakerp/shared"
	"github.com/openshift/openshift-azure/pkg/util/randomstring"
	"github.com/openshift/openshift-azure/test/clients/openshift"
	testlogger "github.com/openshift/openshift-azure/test/util/log"
)

type TestError struct {
	Bucket string
	Err    error
}

var _ error = &TestError{}

func (te *TestError) Error() string {
	return te.Bucket + ": " + te.Err.Error()
}

type DeepTestInterface interface {
	CreateTestApp(ctx context.Context) (interface{}, []*TestError)
	ValidateTestApp(ctx context.Context, cookie interface{}) []*TestError
	ValidateCluster(ctx context.Context) []*TestError
	DeleteTestApp(ctx context.Context, cookie interface{}) []*TestError
}

type SanityChecker struct {
	log    *logrus.Entry
	cs     *internalapi.OpenShiftManagedCluster
	Client *openshift.ClientSet
}

var _ DeepTestInterface = &SanityChecker{}

// NewSanityChecker creates a new deep test sanity checker for OpenshiftManagedCluster resources.
func NewSanityChecker(log *logrus.Entry, cs *internalapi.OpenShiftManagedCluster) (*SanityChecker, error) {
	scc := &SanityChecker{
		log: log,
		cs:  cs,
	}
	var err error
	scc.Client, err = openshift.NewClientSet(cs)
	if err != nil {
		return nil, err
	}
	return scc, nil
}

func NewDefaultSanityChecker() (*SanityChecker, error) {
	log := testlogger.GetTestLogger()
	cs, err := shared.DiscoverInternalConfig()
	if err != nil {
		return nil, err
	}
	return NewSanityChecker(log, cs)
}

func (sc *SanityChecker) CreateTestApp(ctx context.Context) (interface{}, []*TestError) {
	var errs []*TestError
	sc.log.Debugf("creating openshift project for test apps")
	namespace, err := sc.createProject(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "createProject"})
		return nil, errs
	}
	sc.log.Debugf("creating stateful test app in %s", namespace)
	err = sc.createStatefulApp(ctx, namespace)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "createStatefulApp"})
	}
	return namespace, errs
}

func (sc *SanityChecker) ValidateTestApp(ctx context.Context, cookie interface{}) (errs []*TestError) {
	namespace := cookie.(string)
	sc.log.Debugf("validating stateful test app in %s", namespace)
	err := sc.validateStatefulApp(ctx, namespace)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "validateStatefulApp"})
	}
	return
}

func (sc *SanityChecker) ValidateCluster(ctx context.Context) (errs []*TestError) {
	sc.log.Debugf("validating that nodes are labelled correctly")
	err := sc.checkNodesLabelledCorrectly(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "checkNodesLabelledCorrectly"})
	}
	sc.log.Debugf("validating that all monitoring components are healthy")
	err = sc.checkMonitoringStackHealth(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "checkMonitoringStackHealth"})
	}
	sc.log.Debugf("validating that pod disruption budgets are immutable")
	err = sc.checkDisallowsPdbMutations(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "checkDisallowsPdbMutations"})
	}
	sc.log.Debugf("validating that an end user cannot access infrastructure components")
	err = sc.checkCannotAccessInfraResources(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "checkCannotAccessInfraResources"})
	}
	sc.log.Debugf("validating that the cluster can pull redhat.io images")
	err = sc.checkCanDeployRedhatIoImages(ctx)
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "checkCanDeployRedhatIoImages"})
	}
	return
}

func (sc *SanityChecker) DeleteTestApp(ctx context.Context, cookie interface{}) []*TestError {
	var errs []*TestError
	sc.log.Debugf("deleting openshift project for test apps")
	err := sc.deleteProject(ctx, cookie.(string))
	if err != nil {
		sc.log.Error(err)
		errs = append(errs, &TestError{Err: err, Bucket: "deleteProject"})
	}
	return errs
}

func (sc *SanityChecker) createProject(ctx context.Context) (string, error) {
	template, err := randomstring.RandomString("abcdefghijklmnopqrstuvwxyz0123456789", 5)
	if err != nil {
		return "", err
	}
	namespace := "e2e-test-" + template
	err = sc.Client.EndUser.CreateProject(namespace)
	if err != nil {
		return "", err
	}
	return namespace, nil
}

func (sc *SanityChecker) deleteProject(ctx context.Context, namespace string) error {
	err := sc.Client.EndUser.CleanupProject(namespace)
	if err != nil {
		return err
	}
	return nil
}
