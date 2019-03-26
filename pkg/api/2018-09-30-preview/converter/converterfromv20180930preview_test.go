package converter

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/go-test/deep"

	"github.com/openshift/openshift-azure/pkg/api"
	v20180930preview "github.com/openshift/openshift-azure/pkg/api/2018-09-30-preview/api"
	"github.com/openshift/openshift-azure/test/util/populate"
)

func v20180930previewManagedCluster() *v20180930preview.OpenShiftManagedCluster {
	// use populate.Walk to generate a fully populated
	// v20180930preview.OpenShiftManagedCluster

	prepare := func(v reflect.Value) {
		switch v.Interface().(type) {
		case []v20180930preview.IdentityProvider:
			// set the Provider to AADIdentityProvider
			v.Set(reflect.ValueOf([]v20180930preview.IdentityProvider{{Provider: &v20180930preview.AADIdentityProvider{Kind: to.StringPtr("AADIdentityProvider")}}}))
		}
	}

	omc := v20180930preview.OpenShiftManagedCluster{}
	populate.Walk(&omc, prepare)

	return &omc
}

func TestConvertFromV20180930preview(t *testing.T) {
	tests := []struct {
		name           string
		input          *v20180930preview.OpenShiftManagedCluster
		base           *api.OpenShiftManagedCluster
		expectedChange func(*api.OpenShiftManagedCluster)
		err            error
	}{
		{
			name:  "create",
			input: v20180930previewManagedCluster(),
		},
		{
			name: "router profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					RouterProfiles: []v20180930preview.RouterProfile{
						{
							Name:            to.StringPtr("Properties.RouterProfiles[0].Name"),
							PublicSubdomain: to.StringPtr("NewPublicSubdomain"),
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			expectedChange: func(expectedCs *api.OpenShiftManagedCluster) {
				expectedCs.Properties.RouterProfiles[0].PublicSubdomain = "NewPublicSubdomain"
			},
		},
		{
			name: "missing name in router profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					RouterProfiles: []v20180930preview.RouterProfile{
						{
							PublicSubdomain: to.StringPtr("NewPublicSubdomain"),
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			err:  errors.New("invalid router profile - name is missing"),
		},
		{
			name: "new agent pool profile",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					AgentPoolProfiles: []v20180930preview.AgentPoolProfile{
						{
							Name:       to.StringPtr("NewName"),
							Count:      to.Int64Ptr(2),
							VMSize:     (*v20180930preview.VMSize)(to.StringPtr("NewVMSize")),
							SubnetCIDR: to.StringPtr("NewSubnetCIDR"),
							OSType:     (*v20180930preview.OSType)(to.StringPtr("NewOSType")),
							Role:       (*v20180930preview.AgentPoolProfileRole)(to.StringPtr("NewRole")),
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			expectedChange: func(expectedCs *api.OpenShiftManagedCluster) {
				expectedCs.Properties.AgentPoolProfiles = append(expectedCs.Properties.AgentPoolProfiles,
					api.AgentPoolProfile{
						Name:       "NewName",
						Count:      2,
						VMSize:     api.VMSize("NewVMSize"),
						SubnetCIDR: "NewSubnetCIDR",
						OSType:     api.OSType("NewOSType"),
						Role:       api.AgentPoolProfileRole("NewRole"),
					})
			},
		},
		{
			name: "missing name in agent pool profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					AgentPoolProfiles: []v20180930preview.AgentPoolProfile{
						{
							Count:      to.Int64Ptr(2),
							VMSize:     (*v20180930preview.VMSize)(to.StringPtr("NewVMSize")),
							SubnetCIDR: to.StringPtr("NewSubnetCIDR"),
							OSType:     (*v20180930preview.OSType)(to.StringPtr("NewOSType")),
							Role:       (*v20180930preview.AgentPoolProfileRole)(to.StringPtr("NewRole")),
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			err:  errors.New("invalid agent pool profile - name is missing"),
		},
		{
			name: "auth profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					AuthProfile: &v20180930preview.AuthProfile{
						IdentityProviders: []v20180930preview.IdentityProvider{
							{
								Name: to.StringPtr("Properties.AuthProfile.IdentityProviders[0].Name"),
								Provider: &v20180930preview.AADIdentityProvider{
									Secret: to.StringPtr("NewSecret"),
								},
							},
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			expectedChange: func(expectedCs *api.OpenShiftManagedCluster) {
				expectedCs.Properties.AuthProfile = api.AuthProfile{
					IdentityProviders: []api.IdentityProvider{
						{
							Name: "Properties.AuthProfile.IdentityProviders[0].Name",
							Provider: &api.AADIdentityProvider{
								Kind:     "AADIdentityProvider",
								ClientID: "Properties.AuthProfile.IdentityProviders[0].Provider.ClientID",
								Secret:   "NewSecret",
								TenantID: "Properties.AuthProfile.IdentityProviders[0].Provider.TenantID",
							},
						},
					},
				}
			},
		},
		{
			name: "invalid auth profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					AuthProfile: &v20180930preview.AuthProfile{
						IdentityProviders: []v20180930preview.IdentityProvider{
							{
								Name: to.StringPtr("Properties.AuthProfile.IdentityProviders[0].Name"),
								Provider: &v20180930preview.AADIdentityProvider{
									Kind: to.StringPtr("Kind"),
								},
							},
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			err:  errors.New("cannot update the kind of the identity provider"),
		},
		{
			name: "missing name in auth profile update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Properties: &v20180930preview.Properties{
					AuthProfile: &v20180930preview.AuthProfile{
						IdentityProviders: []v20180930preview.IdentityProvider{
							{
								Provider: &v20180930preview.AADIdentityProvider{
									Kind: to.StringPtr("Kind"),
								},
							},
						},
					},
				},
			},
			base: api.GetInternalMockCluster(),
			err:  errors.New("invalid identity provider - name is missing"),
		},
		{
			name: "nil ResourcePurchasPlan update",
			input: &v20180930preview.OpenShiftManagedCluster{
				Plan: nil,
			},
			base: api.GetInternalMockCluster(),
			expectedChange: func(expectedCs *api.OpenShiftManagedCluster) {
			},
		},
	}

	for _, test := range tests {
		expected := api.GetInternalMockCluster()
		if test.expectedChange != nil {
			test.expectedChange(expected)
		}

		output, err := ConvertFromV20180930preview(test.input, test.base)
		if !reflect.DeepEqual(err, test.err) {
			t.Errorf("%s: expected error: %v, got error: %v", test.name, test.err, err)
		}
		if err == nil {
			if !reflect.DeepEqual(output, expected) {
				t.Errorf("%s: unexpected diff %s", test.name, deep.Equal(output, expected))
			}
		}
	}
}

func TestRoundTripV20180930preview(t *testing.T) {
	start := v20180930previewManagedCluster()
	internal, err := ConvertFromV20180930preview(start, nil)
	if err != nil {
		t.Error(err)
	}
	end := ConvertToV20180930preview(internal)
	if !reflect.DeepEqual(start, end) {
		t.Errorf("unexpected diff %s", deep.Equal(start, end))
	}
}
