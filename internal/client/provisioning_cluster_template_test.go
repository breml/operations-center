package client_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/FuturFusion/operations-center/internal/client"
	"github.com/FuturFusion/operations-center/internal/domain"
	"github.com/FuturFusion/operations-center/internal/provisioning"
	"github.com/FuturFusion/operations-center/internal/provisioning/repo/sqlite/entities"
	"github.com/FuturFusion/operations-center/shared/api"
)

func Test_GetClusterTemplates(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T, result []api.ClusterTemplate)
	}{
		{
			name:       "success - empty list",
			client:     d.socketClient,
			dbSeedFunc: noop,

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result []api.ClusterTemplate) {
				t.Helper()

				require.Empty(t, result)
			},
		},
		{
			name:   "success - one record",
			client: d.socketClient,

			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "foo",
				})
				require.NoError(t, err)
			},

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result []api.ClusterTemplate) {
				t.Helper()

				require.Len(t, result, 1)
				require.Equal(t, "foo", result[0].Name)
			},
		},
		{
			name:       "success - authorized with TLS client certificate",
			client:     d.authorizedHTTPClient,
			dbSeedFunc: noop,

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result []api.ClusterTemplate) {
				t.Helper()

				require.Len(t, result, 1)
				require.Equal(t, "foo", result[0].Name)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: func(t *testing.T, result []api.ClusterTemplate) {
				t.Helper()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			result, err := tc.client.GetClusterTemplates(t.Context())

			tc.assertErr(t, err)
			tc.assertFunc(t, result)
		})
	}
}

func Test_GetClusterTemplate(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg string

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T, result api.ClusterTemplate)
	}{
		{
			name:   "success - one record",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "foo",
				})
				require.NoError(t, err)
			},

			tcNameArg: "foo",

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result api.ClusterTemplate) {
				t.Helper()

				require.Equal(t, "foo", result.Name)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: "foo",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: func(t *testing.T, result api.ClusterTemplate) {
				t.Helper()
			},
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "unknown",

			assertErr: func(t require.TestingT, err error, a ...any) {
				require.ErrorIs(t, err, domain.ErrNotFound)
			},
			assertFunc: func(t *testing.T, result api.ClusterTemplate) {
				t.Helper()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			result, err := tc.client.GetClusterTemplate(t.Context(), tc.tcNameArg)

			tc.assertErr(t, err)
			tc.assertFunc(t, result)
		})
	}
}

func Test_CreateClusterTemplate(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		clusterTemplate api.ClusterTemplatePost

		assertErr require.ErrorAssertionFunc
	}{
		{
			name:       "success",
			client:     d.socketClient,
			dbSeedFunc: noop,

			clusterTemplate: api.ClusterTemplatePost{
				Name: "new-cluster-template",
				ClusterTemplatePut: api.ClusterTemplatePut{
					Description: "description",
				},
			},

			assertErr: require.NoError,
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
		},
		{
			name:       "error - validation",
			client:     d.socketClient,
			dbSeedFunc: noop,

			clusterTemplate: api.ClusterTemplatePost{
				Name: "", // invalid no name provided
				ClusterTemplatePut: api.ClusterTemplatePut{
					Description: "description",
				},
			},

			assertErr: require.Error,
		},
		{
			name:   "error - confilict",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "foo",
				})
				require.NoError(t, err)
			},

			clusterTemplate: api.ClusterTemplatePost{
				Name: "foo", // already exists
			},

			assertErr: require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			err := tc.client.CreateClusterTemplate(t.Context(), tc.clusterTemplate)

			tc.assertErr(t, err)
		})
	}
}

func Test_UpdateClusterTemplate(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg       string
		clusterTemplate api.ClusterTemplatePut

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T)
	}{
		{
			name:   "success",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name:        "foo",
					Description: "description",
				})
				require.NoError(t, err)
			},

			tcNameArg: "foo",
			clusterTemplate: api.ClusterTemplatePut{
				Description:           "updated description",
				ServiceConfigTemplate: "service: @variable@",
				Variables: api.ClusterTemplateVariables{
					"variable": api.ClusterTemplateVariable{
						Description: "a variable",
					},
				},
			},

			assertErr: require.NoError,
			assertFunc: func(t *testing.T) {
				t.Helper()

				clusterTemplate, err := d.socketClient.GetClusterTemplate(t.Context(), "foo")
				require.NoError(t, err)
				require.Equal(t, "updated description", clusterTemplate.Description)
				require.Equal(t, "service: @variable@", clusterTemplate.ServiceConfigTemplate)
				require.Contains(t, clusterTemplate.Variables, "variable")
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: "foo",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: noop,
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "unknown",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotFound)
			},
			assertFunc: noop,
		},
		{
			name:       "error - validation",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "foo",
			clusterTemplate: api.ClusterTemplatePut{
				// Invalid, the variable is not used in any of the templates.
				Variables: api.ClusterTemplateVariables{
					"unused": api.ClusterTemplateVariable{},
				},
			},

			assertErr:  require.Error,
			assertFunc: noop,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			err := tc.client.UpdateClusterTemplate(t.Context(), tc.tcNameArg, tc.clusterTemplate)

			tc.assertErr(t, err)
			tc.assertFunc(t)
		})
	}
}

func Test_RenameClusterTemplate(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg string
		tcNewName string

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T)
	}{
		{
			name:   "success",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "foo",
				})
				require.NoError(t, err)
			},

			tcNameArg: "foo",
			tcNewName: "bar",

			assertErr: require.NoError,
			assertFunc: func(t *testing.T) {
				t.Helper()

				clusterTemplate, err := d.socketClient.GetClusterTemplate(t.Context(), "bar")
				require.NoError(t, err)
				require.Equal(t, "bar", clusterTemplate.Name)

				_, err = d.socketClient.GetClusterTemplate(t.Context(), "foo")
				require.ErrorIs(t, err, domain.ErrNotFound)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: "bar",
			tcNewName: "baz",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: noop,
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "unknown",
			tcNewName: "baz",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotFound)
			},
			assertFunc: noop,
		},
		{
			name:       "error - new name is empty",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "bar",
			tcNewName: "",

			assertErr:  require.Error,
			assertFunc: noop,
		},
		{
			name:   "error - conflict",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "conflicting",
				})
				require.NoError(t, err)
			},

			tcNameArg: "bar",
			tcNewName: "conflicting", // already exists

			assertErr:  require.Error,
			assertFunc: noop,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			err := tc.client.RenameClusterTemplate(t.Context(), tc.tcNameArg, tc.tcNewName)

			tc.assertErr(t, err)
			tc.assertFunc(t)
		})
	}
}

func Test_DeleteClusterTemplate(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg string

		assertErr require.ErrorAssertionFunc
	}{
		{
			name:   "success - one record",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				_, err := entities.CreateClusterTemplate(t.Context(), d.db, provisioning.ClusterTemplate{
					Name: "foo",
				})
				require.NoError(t, err)
			},

			tcNameArg: "foo",

			assertErr: require.NoError,
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: "foo",

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "unknown",

			assertErr: func(t require.TestingT, err error, a ...any) {
				require.ErrorIs(t, err, domain.ErrNotFound)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			err := tc.client.DeleteClusterTemplate(t.Context(), tc.tcNameArg)

			tc.assertErr(t, err)
		})
	}
}
