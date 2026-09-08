package client_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/FuturFusion/operations-center/internal/client"
	"github.com/FuturFusion/operations-center/internal/domain"
	"github.com/FuturFusion/operations-center/internal/util/testing/uuidgen"
	"github.com/FuturFusion/operations-center/internal/warning"
	warningEntities "github.com/FuturFusion/operations-center/internal/warning/repo/sqlite/entities"
	"github.com/FuturFusion/operations-center/shared/api"
)

func Test_GetWarnings(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T, result []api.Warning)
	}{
		{
			name:       "success - empty list",
			client:     d.socketClient,
			dbSeedFunc: noop,

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result []api.Warning) {
				t.Helper()

				require.Empty(t, result)
			},
		},
		{
			name:   "success - one record",
			client: d.socketClient,

			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				seedWarning(t, d, uuidgen.FromPattern(t, "1"), "serverOne", api.WarningStatusNew)
			},

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result []api.Warning) {
				t.Helper()

				require.Len(t, result, 1)
				require.Equal(t, uuidgen.FromPattern(t, "1"), result[0].UUID)
				require.Equal(t, api.WarningTypeUnreachable, result[0].Type)
				require.Equal(t, "serverOne", result[0].Scope.Entity)
				require.Equal(t, api.WarningStatusNew, result[0].Status)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: func(t *testing.T, result []api.Warning) {
				t.Helper()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			result, err := tc.client.GetWarnings(t.Context())

			tc.assertErr(t, err)
			tc.assertFunc(t, result)
		})
	}
}

func Test_GetWarning(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg string

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T, result api.Warning)
	}{
		{
			name:   "success - one record",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				seedWarning(t, d, uuidgen.FromPattern(t, "1"), "serverOne", api.WarningStatusNew)
			},

			tcNameArg: uuidgen.FromPattern(t, "1").String(),

			assertErr: require.NoError,
			assertFunc: func(t *testing.T, result api.Warning) {
				t.Helper()

				require.Equal(t, uuidgen.FromPattern(t, "1"), result.UUID)
				require.Equal(t, "serverOne", result.Scope.Entity)
				require.Equal(t, []string{"Server is unreachable"}, result.Messages)
				require.Equal(t, 1, result.Count)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: uuidgen.FromPattern(t, "1").String(),

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: func(t *testing.T, result api.Warning) {
				t.Helper()
			},
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: uuidgen.FromPattern(t, "2").String(),

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotFound)
			},
			assertFunc: func(t *testing.T, result api.Warning) {
				t.Helper()
			},
		},
		{
			name:       "error - invalid uuid",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "not-a-uuid",

			assertErr: require.Error,
			assertFunc: func(t *testing.T, result api.Warning) {
				t.Helper()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			result, err := tc.client.GetWarning(t.Context(), tc.tcNameArg)

			tc.assertErr(t, err)
			tc.assertFunc(t, result)
		})
	}
}

func Test_UpdateWarningStatus(t *testing.T) {
	d := daemonSetup(t)

	tests := []struct {
		name       string
		client     client.OperationsCenterClient
		dbSeedFunc func(t *testing.T)

		tcNameArg string
		status    api.WarningStatus

		assertErr  require.ErrorAssertionFunc
		assertFunc func(t *testing.T)
	}{
		{
			name:   "success - acknowledge warning",
			client: d.socketClient,
			dbSeedFunc: func(t *testing.T) {
				t.Helper()

				seedWarning(t, d, uuidgen.FromPattern(t, "1"), "serverOne", api.WarningStatusNew)
			},

			tcNameArg: uuidgen.FromPattern(t, "1").String(),
			status:    api.WarningStatusAcknowledged,

			assertErr: require.NoError,
			assertFunc: func(t *testing.T) {
				t.Helper()

				updatedWarning, err := d.socketClient.GetWarning(t.Context(), uuidgen.FromPattern(t, "1").String())
				require.NoError(t, err)
				require.Equal(t, api.WarningStatusAcknowledged, updatedWarning.Status)
			},
		},
		{
			name:       "error - not authorized",
			client:     d.unauthorizedHTTPClient,
			dbSeedFunc: noop,

			tcNameArg: uuidgen.FromPattern(t, "1").String(),
			status:    api.WarningStatusAcknowledged,

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotAuthenticated)
			},
			assertFunc: noop,
		},
		{
			name:       "error - not found",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: uuidgen.FromPattern(t, "2").String(),
			status:    api.WarningStatusAcknowledged,

			assertErr: func(tt require.TestingT, err error, a ...any) {
				require.ErrorIs(tt, err, domain.ErrNotFound)
			},
			assertFunc: noop,
		},
		{
			name:       "error - invalid uuid",
			client:     d.socketClient,
			dbSeedFunc: noop,

			tcNameArg: "not-a-uuid",
			status:    api.WarningStatusAcknowledged,

			assertErr:  require.Error,
			assertFunc: noop,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.dbSeedFunc(t)

			err := tc.client.UpdateWarningStatus(t.Context(), tc.tcNameArg, tc.status)

			tc.assertErr(t, err)
			tc.assertFunc(t)
		})
	}
}

func seedWarning(t *testing.T, d testDaemon, id uuid.UUID, entity string, status api.WarningStatus) {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)

	_, err := warningEntities.CreateOrReplaceWarning(t.Context(), d.db, warning.Warning{
		UUID:            id,
		Type:            api.WarningTypeUnreachable,
		Scope:           "provisioning",
		EntityType:      "server",
		Entity:          entity,
		Status:          status,
		FirstOccurrence: now,
		LastOccurrence:  now,
		LastUpdated:     now,
		Messages:        []string{"Server is unreachable"},
		Count:           1,
	})
	require.NoError(t, err)
}
