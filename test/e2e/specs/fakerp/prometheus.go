package fakerp

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/openshift-azure/pkg/api"
	"github.com/openshift/openshift-azure/pkg/fakerp/shared"
	"github.com/openshift/openshift-azure/pkg/util/managedcluster"
	"github.com/openshift/openshift-azure/test/e2e/standard"
)

type target struct {
	DiscoveredLabels map[string]string `json:"discoveredLabels"`
	Labels           map[string]string `json:"labels"`
	ScrapeURL        string            `json:"scrapeURL"`
	LastError        string            `json:"lastError"`
	LastScrape       string            `json:"lastScrape"`
	Health           string            `json:"health"`
}

type targetsResponse struct {
	Status string `json:"status"`
	Data   struct {
		ActiveTargets  []target `json:"activeTargets"`
		DroppedTargets []target `json:"droppedTargets"`
	} `json:"data"`
}

var _ = Describe("Prometheus E2E tests [Prometheus][EveryPR]", func() {
	var (
		cli *standard.SanityChecker
		cs  *api.OpenShiftManagedCluster
	)

	BeforeEach(func() {
		var err error
		cli, err = standard.NewDefaultSanityChecker()
		Expect(err).NotTo(HaveOccurred())
		Expect(cli).NotTo(BeNil())

		dataDir, err := shared.FindDirectory(shared.DataDirectory)
		Expect(err).NotTo(HaveOccurred())
		cs, err = managedcluster.ReadConfig(filepath.Join(dataDir, "containerservice.yaml"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should register all the necessary prometheus targets", func() {
		token, err := cli.Client.Admin.GetServiceAccountToken("openshift-monitoring", "prometheus-k8s")
		Expect(err).NotTo(HaveOccurred())

		route, err := cli.Client.Admin.RouteV1.Routes("openshift-monitoring").Get("prometheus-k8s", meta_v1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		req, err := http.NewRequest(http.MethodGet, "https://"+route.Spec.Host+"/api/v1/targets", nil)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Add("Authorization", "Bearer "+string(token))

		cli := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		resp, err := cli.Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))

		var tr targetsResponse
		d := json.NewDecoder(resp.Body)
		err = d.Decode(&tr)
		Expect(err).NotTo(HaveOccurred())

		healthyTargets := map[string]int{}
		for _, t := range tr.Data.ActiveTargets {
			if t.Health == "up" {
				healthyTargets[t.Labels["job"]]++
			}
		}

		nodes, masters := 0, 0
		for _, app := range cs.Properties.AgentPoolProfiles {
			if app.Role == api.AgentPoolProfileRoleMaster {
				masters = int(app.Count)
			}
			nodes += int(app.Count)
		}

		Expect(healthyTargets).To(Equal(map[string]int{
			"alertmanager-main": 3,
			"apiserver":         masters,
			// TODO: enable once https://github.com/openshift/cluster-monitoring-operator/pull/230 is backported
			// "kube-controllers": masters,
			"kube-state-metrics":  2,
			"kubelet":             nodes * 2,
			"node-exporter":       nodes,
			"prometheus-k8s":      2,
			"prometheus-operator": 1,
		}))
	})
})
