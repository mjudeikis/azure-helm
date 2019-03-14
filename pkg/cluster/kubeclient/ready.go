package kubeclient

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/openshift/openshift-azure/pkg/api"
	"github.com/openshift/openshift-azure/pkg/util/ready"
	"github.com/openshift/openshift-azure/pkg/util/wait"
)

var deploymentWhitelist = []struct {
	Name      string
	Namespace string
}{
	{
		Name:      "registry-console",
		Namespace: "default",
	},
	{
		Name:      "customer-admin-controller",
		Namespace: "openshift-infra",
	},
	{
		Name:      "asb",
		Namespace: "openshift-ansible-service-broker",
	},
	{
		Name:      "webconsole",
		Namespace: "openshift-web-console",
	},
	{
		Name:      "console",
		Namespace: "openshift-console",
	},
	{
		Name:      "branding",
		Namespace: "openshift-azure-branding",
	},
}

var daemonsetWhitelist = []struct {
	Name      string
	Namespace string
}{
	{
		Name:      "docker-registry",
		Namespace: "default",
	},
	{
		Name:      "router",
		Namespace: "default",
	},
	{
		Name:      "apiserver",
		Namespace: "kube-service-catalog",
	},
	{
		Name:      "controller-manager",
		Namespace: "kube-service-catalog",
	},
	{
		Name:      "apiserver",
		Namespace: "openshift-template-service-broker",
	},
	{
		Name:      "mdsd",
		Namespace: "openshift-azure-logging",
	},
	{
		Name:      "etcd-metrics",
		Namespace: "openshift-azure-monitoring",
	},
}

var statefulsetWhitelist = []struct {
	Name      string
	Namespace string
}{
	{
		Name:      "bootstrap-autoapprover",
		Namespace: "openshift-infra",
	},
}

func (u *kubeclient) WaitForInfraServices(ctx context.Context) *api.PluginError {
	for _, app := range daemonsetWhitelist {
		u.log.Infof("checking daemonset %s/%s", app.Namespace, app.Name)

		err := wait.PollImmediateUntil(time.Second, ready.DaemonSetIsReady(u.client.AppsV1().DaemonSets(app.Namespace), app.Name), ctx.Done())
		if err != nil {
			return &api.PluginError{Err: err, Step: api.PluginStepWaitForInfraDaemonSets}
		}
	}

	for _, app := range statefulsetWhitelist {
		u.log.Infof("checking statefulset %s/%s", app.Namespace, app.Name)

		err := wait.PollImmediateUntil(time.Second, ready.StatefulSetIsReady(u.client.AppsV1().StatefulSets(app.Namespace), app.Name), ctx.Done())
		if err != nil {
			return &api.PluginError{Err: err, Step: api.PluginStepWaitForInfraStatefulSets}
		}
	}

	for _, app := range deploymentWhitelist {
		u.log.Infof("checking deployment %s/%s", app.Namespace, app.Name)

		err := wait.PollImmediateUntil(time.Second, ready.DeploymentIsReady(u.client.AppsV1().Deployments(app.Namespace), app.Name), ctx.Done())
		if err != nil {
			return &api.PluginError{Err: err, Step: api.PluginStepWaitForInfraDeployments}
		}
	}

	return nil
}

func (u *kubeclient) WaitForReadyMaster(ctx context.Context, hostname string) error {
	return wait.PollImmediateUntil(time.Second, func() (bool, error) { return u.masterIsReady(hostname) }, ctx.Done())
}

func (u *kubeclient) masterIsReady(hostname string) (bool, error) {
	r, err := ready.NodeIsReady(u.client.CoreV1().Nodes(), hostname)()
	if !r || err != nil {
		return r, err
	}

	r, err = ready.PodIsReady(u.client.CoreV1().Pods("kube-system"), "master-etcd-"+hostname)()
	if !r || err != nil {
		return r, err
	}

	r, err = ready.PodIsReady(u.client.CoreV1().Pods("kube-system"), "master-api-"+hostname)()
	if !r || err != nil {
		return r, err
	}

	return ready.PodIsReady(u.client.CoreV1().Pods("kube-system"), "controllers-"+hostname)()
}

func (u *kubeclient) WaitForReadyWorker(ctx context.Context, hostname string) error {
	return wait.PollImmediateUntil(time.Second, ready.NodeIsReady(u.client.CoreV1().Nodes(), hostname), ctx.Done())
}

func (u *kubeclient) WaitForReadySyncPod(ctx context.Context) error {
	return wait.PollImmediateUntil(time.Second,
		func() (bool, error) {
			// can't check the pod status - health checks don't exist for
			// static/mirror pods
			result := u.client.CoreV1().RESTClient().Get().
				Namespace("kube-system").
				Resource("pods").
				Name("sync-master-000000").
				SubResource("proxy").
				Suffix("/healthz/ready").
				Do()

			err := result.Error()
			switch {
			case err == nil:
				return true, nil
			case errors.IsServiceUnavailable(err):
				return false, nil
			default:
				return false, err
			}
		},
		ctx.Done())
}
