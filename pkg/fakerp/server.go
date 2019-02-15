package fakerp

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-05-01/resources"
	"github.com/ghodss/yaml"
	"github.com/go-chi/chi"
	"github.com/sirupsen/logrus"

	"github.com/openshift/openshift-azure/pkg/api"
	internalapi "github.com/openshift/openshift-azure/pkg/api"
	v20180930preview "github.com/openshift/openshift-azure/pkg/api/2018-09-30-preview/api"
	admin "github.com/openshift/openshift-azure/pkg/api/admin/api"
	pluginapi "github.com/openshift/openshift-azure/pkg/api/plugin/api"
	"github.com/openshift/openshift-azure/pkg/fakerp/shared"
	"github.com/openshift/openshift-azure/pkg/plugin"
)

var once sync.Once

type Server struct {
	router *chi.Mux
	// the server will not process more than a single
	// PUT request at all times.
	inProgress chan struct{}

	gc resources.GroupsClient

	sync.RWMutex
	state internalapi.ProvisioningState
	cs    *internalapi.OpenShiftManagedCluster

	log      *logrus.Entry
	address  string
	basePath string

	plugin         internalapi.Plugin
	pluginConfig   *api.PluginConfig
	pluginTemplate *pluginapi.Config
}

func NewServer(log *logrus.Entry, resourceGroup, address string) *Server {
	s := &Server{
		router:     chi.NewRouter(),
		inProgress: make(chan struct{}, 1),
		log:        log,
		address:    address,
		basePath:   "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{provider}/openShiftManagedClusters/{resourceName}",
	}
	var err error
	var errs []error
	s.pluginConfig, err = GetPluginConfig()
	if err != nil {
		s.log.Fatal(err)
	}
	s.plugin, errs = plugin.NewPlugin(s.log, s.pluginConfig)
	if len(errs) > 0 {
		s.log.Fatal(errs)
	}
	s.pluginTemplate, err = GetPluginTemplate()
	if err != nil {
		s.log.Fatal(err)
	}
	// We need to restore the internal cluster state into memory for GETs
	// and DELETEs to work appropriately.
	if _, err := s.load(); err != nil {
		s.log.Fatal(err)
	}
	return s
}

func (s *Server) Run() {
	s.SetupRoutes()
	s.log.Infof("starting server on %s", s.address)
	s.log.WithError(http.ListenAndServe(s.address, s.router)).Warn("Server exited.")
}

// The way we run the fake RP during development cannot really
// be consistent with how the RP runs in production so we need
// to restore the internal state of the cluster from the
// filesystem. Whether the file that holds the state exists or
// not is returned and any other error that was encountered.
func (s *Server) load() (bool, error) {
	dataDir, err := shared.FindDirectory(shared.DataDirectory)
	if err != nil {
		return false, err
	}
	csFile := filepath.Join(dataDir, "containerservice.yaml")
	if _, err = os.Stat(csFile); err != nil {
		return false, nil
	}
	data, err := ioutil.ReadFile(csFile)
	if err != nil {
		return true, err
	}
	var cs *internalapi.OpenShiftManagedCluster
	if err := yaml.Unmarshal(data, &cs); err != nil {
		return true, err
	}
	s.write(cs)
	return true, nil
}

func (s *Server) read20180930previewRequest(body io.ReadCloser) (*v20180930preview.OpenShiftManagedCluster, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	var oc *v20180930preview.OpenShiftManagedCluster
	if err := yaml.Unmarshal(data, &oc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	return oc, nil
}

func (s *Server) readAdminRequest(body io.ReadCloser) (*admin.OpenShiftManagedCluster, error) {
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	var oc *admin.OpenShiftManagedCluster
	if err := yaml.Unmarshal(data, &oc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %v", err)
	}
	return oc, nil
}

func (s *Server) write(cs *internalapi.OpenShiftManagedCluster) {
	s.Lock()
	defer s.Unlock()
	s.cs = cs
}

func (s *Server) read() *internalapi.OpenShiftManagedCluster {
	s.RLock()
	defer s.RUnlock()
	return s.cs
}

func (s *Server) writeState(state internalapi.ProvisioningState) {
	s.Lock()
	defer s.Unlock()
	s.state = state
}

func (s *Server) readState() internalapi.ProvisioningState {
	s.RLock()
	defer s.RUnlock()
	return s.state
}
