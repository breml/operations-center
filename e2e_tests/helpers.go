package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	shellwords "github.com/mattn/go-shellwords"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return false
	}

	if info.IsDir() || !info.Mode().Type().IsRegular() {
		return false
	}

	return true
}

// isExecutable checks if path is an executable file that the current user can run.
func isExecutable(t *testing.T, path string) bool {
	t.Helper()

	info, err := os.Stat(path)
	require.NoErrorf(t, err, "file %q", path)

	// Check if it's a regular file.
	if !info.Mode().IsRegular() {
		return false
	}

	// Check if it has execute permission.
	mode := info.Mode()
	if mode&0o111 == 0 {
		return false // No execute bit set
	}

	// Check if current user can actually execute it.
	stat := info.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())

	// Owner execute permission.
	if stat.Uid == uid && mode&0o100 != 0 {
		return true
	}

	// Group execute permission.
	if stat.Gid == gid && mode&0o010 != 0 {
		return true
	}

	// Others execute permission.
	if mode&0o001 != 0 {
		return true
	}

	// Check supplementary groups.
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if uint32(g) == stat.Gid && mode&0o010 != 0 {
			return true
		}
	}

	return false
}

type cmdResponse struct {
	output   bytes.Buffer
	exitCode int
}

func (c cmdResponse) Success() bool {
	return c.exitCode == 0
}

// run executes a command silently and fails on error. In this case, the output
// is reported.
func run(t *testing.T, command string, args ...any) cmdResponse {
	t.Helper()

	resp := cmdWithContext(t.Context(), t, command, args...)
	if !resp.Success() {
		t.Fatalf("run: %q failed with:\n%s", command, resp.output.String())
	}

	return resp
}

func runWithTimeout(t *testing.T, command string, timeout time.Duration, args ...any) cmdResponse {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	resp := cmdWithContext(ctx, t, command, args...)
	if !resp.Success() {
		t.Fatalf("run: %q failed with:\n%s", command, resp.output.String())
	}

	return resp
}

func cmd(t *testing.T, command string, args ...any) cmdResponse {
	t.Helper()

	return cmdWithContext(t.Context(), t, command, args...)
}

func cmdWithTimeout(t *testing.T, command string, timeout time.Duration, args ...any) cmdResponse {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	return cmdWithContext(ctx, t, command, args...)
}

func cmdWithContext(ctx context.Context, t *testing.T, command string, args ...any) cmdResponse {
	t.Helper()

	shellArgs, err := shellwords.Parse(fmt.Sprintf(command, args...))
	require.NoError(t, err)

	name := shellArgs[0]
	if len(shellArgs) > 1 {
		shellArgs = shellArgs[1:]
	}

	resp := cmdResponse{}

	cmd := exec.CommandContext(t.Context(), name, shellArgs...)
	cmd.Stdout = &resp.output
	cmd.Stderr = &resp.output

	err = cmd.Run()
	if err != nil {
		exitErr := &exec.ExitError{}
		if !errors.As(err, &exitErr) {
			require.NoError(t, err)
		}

		resp.exitCode = exitErr.ExitCode()
	}

	return resp
}

func waitAgentRunning(t *testing.T, vm string) {
	t.Helper()

	waitAgentRunningWithContext(t.Context(), t, vm)
}

func waitAgentRunningWithTimeout(t *testing.T, vm string, timeout time.Duration) {
	t.Helper()

	timeoutCtx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	waitAgentRunningWithContext(timeoutCtx, t, vm)
}

func waitAgentRunningWithContext(ctx context.Context, t *testing.T, vm string) {
	t.Helper()

	for {
		resp := cmd(t, `incus exec %s true`, vm)
		if resp.Success() {
			break
		}

		fmt.Print(".")

		select {
		case <-ctx.Done():
			t.Fatalf("context done: %v", t.Context().Err())

		case <-time.After(time.Second):
		}
	}

	fmt.Println()
}

func waitExpectedLog(t *testing.T, vm string, unit string, want string) {
	t.Helper()

	waitExpectedLogWithContext(t.Context(), t, vm, unit, want, false)
}

func waitExpectedLogRegex(t *testing.T, vm string, unit string, want string) {
	t.Helper()

	waitExpectedLogWithContext(t.Context(), t, vm, unit, want, true)
}

func waitExpectedLogWithTimeout(t *testing.T, vm string, unit string, want string, timeout time.Duration) {
	t.Helper()

	timeoutCtx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	waitExpectedLogWithContext(timeoutCtx, t, vm, unit, want, false)
}

func waitExpectedLogWithContext(ctx context.Context, t *testing.T, vm string, unit string, want string, isRegex bool) {
	t.Helper()

	for {
		resp := run(t, `incus exec %s -- bash -c "journalctl -b -u %s"`, vm, unit)
		if isRegex {
			if regexp.MustCompile(want).MatchString(resp.output.String()) {
				break
			}
		} else {
			if strings.Contains(resp.output.String(), want) {
				break
			}
		}

		fmt.Print(".")

		select {
		case <-ctx.Done():
			t.Fatalf("context done: %v", t.Context().Err())

		case <-time.After(time.Second):
		}
	}

	fmt.Println()
}

func waitUpdatesReady(t *testing.T) {
	t.Helper()

	for {
		resp := run(t, `../bin/operations-center.linux.amd64 provisioning update list -f json`)
		if gjson.Get(resp.output.String(), `@values:#(status=="ready")|#`).Int() > 0 {
			break
		}

		fmt.Print(".")

		select {
		case <-t.Context().Done():
			t.Fatalf("context done: %v", t.Context().Err())

		case <-time.After(time.Second):
		}
	}

	fmt.Println()
}

func indent(in string, prefix string) string {
	buf := strings.Builder{}

	for line := range strings.Lines(in) {
		buf.WriteString(prefix)
		buf.WriteString(line)
	}

	return buf.String()
}
