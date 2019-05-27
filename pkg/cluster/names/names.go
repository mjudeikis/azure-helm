package names

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/openshift/openshift-azure/pkg/api"
)

//MasterScalesetName contains the name of the master VMs scaleset
const MasterScalesetName = "ss-master"

// GetVMName returns the VMS name for a given AgentPoolProfile
func GetVMName(app *api.AgentPoolProfile, suffix string) string {
	return app.Name + "-" + suffix
}

// GetScalesetName returns the VMSS name for a given AgentPoolProfile
func GetScalesetName(app *api.AgentPoolProfile, suffix string) string {
	if app.Role == api.AgentPoolProfileRoleMaster {
		return MasterScalesetName
	}
	return "ss-" + app.Name + "-" + suffix
}

// GetHostnamePrefix returns the computer name prefix for a given
// AgentPoolProfile
func GetHostnamePrefix(app *api.AgentPoolProfile, suffix string) string {
	if app.Role == api.AgentPoolProfileRoleMaster {
		return app.Name + "-"
	}
	return app.Name + "-" + suffix + "-"
}

// GetHostname returns the hostname of a given instance in an AgentPoolProfile
func GetHostname(app *api.AgentPoolProfile, suffix string, instance int64) string {
	return GetHostnamePrefix(app, suffix) + fmt.Sprintf("%06s", strconv.FormatInt(instance, 36))
}

// GetScaleSetNameAndInstanceID parses a hostname, e.g. master-000000 or
// infra-1234567890-00000a, and returns the corresponding scaleset name and
// instance ID, e.g. ss-master, 0 or ss-infra-1234567890, 10
func GetScaleSetNameAndInstanceID(hostname string) (string, string, error) {
	i := strings.LastIndexByte(hostname, '-')
	if i == -1 {
		return "", "", fmt.Errorf("invalid hostname %q", hostname)
	}

	if len(hostname[i+1:]) != 6 {
		return "", "", fmt.Errorf("invalid hostname %q", hostname)
	}

	instanceID, err := strconv.ParseUint(hostname[i+1:], 36, 64)
	if err != nil {
		return "", "", fmt.Errorf("invalid hostname %q", hostname)
	}

	return "ss-" + hostname[:i], fmt.Sprintf("%d", instanceID), nil
}

// GetAgentRole parses a hostname, e.g. master-000000 or infra-12345-000000
// and returns the lowercase role name ("master", "infra" or "compute")
func GetAgentRole(hostname string) api.AgentPoolProfileRole {
	switch strings.Split(hostname, "-")[0] {
	case "master":
		return api.AgentPoolProfileRoleMaster
	case "infra":
		return api.AgentPoolProfileRoleInfra
	default:
		return api.AgentPoolProfileRoleCompute
	}
}
