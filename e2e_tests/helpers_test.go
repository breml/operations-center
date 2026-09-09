package e2e

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Prevent functions from being seen as unused.
var _ = runWithTimeout

func Test_cmd(t *testing.T) {
	tests := []struct {
		name string
		cmd  string

		wantSuccess bool
		wantOutput  string
	}{
		{
			name: "true",
			cmd:  "true",

			wantSuccess: true,
		},
		{
			name: "false",
			cmd:  "false",

			wantSuccess: false,
		},
		{
			name: "pipefail",
			cmd:  "false | true",

			wantSuccess: false,
		},
		{
			name: "echo with arguments",
			cmd:  "echo -n foo bar baz",

			wantSuccess: true,
			wantOutput:  "foo bar baz",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := run(t, `%s`, tc.cmd)
			require.NoError(t, resp.err)

			require.Equal(t, tc.wantSuccess, resp.Success())
			require.Equal(t, tc.wantOutput, resp.Output())
		})
	}
}

func Test_isTransientStorageError(t *testing.T) {
	tests := []struct {
		name   string
		output string

		want bool
	}{
		{
			name:   "empty",
			output: "",

			want: false,
		},
		{
			name:   "failed to deactivate zvol",
			output: "Error: Failed unmounting instance: Failed to deactivate zvol after 5m0s\nTry `incus info --show-log IncusOS02` for more info\n",

			want: true,
		},
		{
			name:   "failed to activate volume",
			output: "Error: Failed to activate volume: Failed to locate zvol for default/virtual-machines/IncusOS01\n",

			want: true,
		},
		{
			name:   "dataset is busy",
			output: "Error: Failed to delete the instance: cannot destroy 'default/virtual-machines/IncusOS01': dataset is busy\n",

			want: true,
		},
		{
			name:   "device or resource busy",
			output: "Error: Failed to unmount: umount: /var/lib/incus/storage-pools/default: device or resource busy\n",

			want: true,
		},
		{
			name:   "instance not found",
			output: "Error: Instance not found\n",

			want: false,
		},
		{
			name:   "instance is already stopped",
			output: "Error: The instance is already stopped\n",

			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := cmdResponse{
				output: bytes.NewBufferString(tc.output),
			}

			require.Equal(t, tc.want, isTransientStorageError(resp))
		})
	}
}
