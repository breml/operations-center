package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Advangage of Go:
//   * Use concurrency, e.g. for setup of the 3 incus instances

// Should this be implemented using `go test`? Advantages:
//   * simple selection of the tests to be executed
//   * Error reporting of tests is in the expected format
//   * require can be used to ensure assertions
// How to model dependencies?
//   * Base setup with Operations Center Setup
//   * Incus Instances created and registered in Operations Center

func TestE2E(t *testing.T) {
	e2eTest := os.Getenv("OPERATIONS_CENTER_E2E_TEST")
	if e2eTest == "" {
		t.Skip("OPERATIONS_CENTER_E2E_TEST env var not set, skipping end 2 end tests.")
	}

	tests := []struct {
		name string
	}{
		{
			name: "test",
		},
	}

	preCheck(t)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	// We don't use the system /tmp, because we need to download large ISO files,
	// which might exceed the available space in /tmp.
	// tmpDir, err := os.MkdirTemp(homeDir, "tmp-e2e-*") // TODO: enable
	tmpDir := filepath.Join(homeDir, "tmp-e2e")
	err = os.MkdirAll(tmpDir, 0o700)
	require.NoError(t, err)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup(t, tmpDir)
		})
	}
}
