package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func preCheck(t *testing.T) {
	executables := []string{
		"../bin/operations-center.linux.amd64",
		"../bin/operations-centerd",
		"/usr/bin/incus",
	}

	for _, executable := range executables {
		if !isExecutable(t, executable) {
			t.Fatalf("%q is not executable by the current user", executable)
		}
	}
}

const (
	diskSize   = "50GiB"
	memorySize = "2GiB"
	cpuCount   = 1
)

func setup(t *testing.T, tmpDir string) {
	t.Helper()

	// FIXME: Check, if snapshots exist, if so restore snapshots and exit.

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	if !isFile(filepath.Join(homeDir, ".config/incus/client.crt")) {
		t.Log("====[ Generate client certificate ]====")
		cmd(t, `incus remote generate-certificate`)
	}

	clientCertificate, err := os.ReadFile(filepath.Join(homeDir, ".config/incus/client.crt"))
	require.NoError(t, err)

	if !isFile(filepath.Join(tmpDir, "IncusOS_OperationsCenter.iso")) {
		t.Log("====[ Create IncusOS ISO for Operations Center installation ]====")

		clientCertificateJSONString, err := json.Marshal(string(clientCertificate))
		require.NoError(t, err)

		operationsCenterSeed := replacePlaceholders(operationsCenterSeedTemplate,
			map[string]string{
				"$CLIENT_CERTIFICATE$": string(clientCertificateJSONString),
			},
		)

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://incusos-customizer.linuxcontainers.org/1.0/images", bytes.NewBuffer(operationsCenterSeed))
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		imagesData, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		err = resp.Body.Close()
		require.NoError(t, err)

		imageDownloadURL := gjson.GetBytes(imagesData, "metadata.image").String()

		run(t, `curl -o %s --compressed https://incusos-customizer.linuxcontainers.org%s`, filepath.Join(tmpDir, "IncusOS_OperationsCenter.iso"), imageDownloadURL)
	}

	storageVolumes := run(t, "incus storage volume list default -f compact")
	if !strings.Contains(storageVolumes.output.String(), "IncusOS_OperationsCenter.iso") {
		t.Log("====[ Import Operations Center ISO into Incus ]====")
		run(t, `incus storage volume import default %s IncusOS_OperationsCenter.iso --type=iso`, filepath.Join(tmpDir, "IncusOS_OperationsCenter.iso"))
	}

	incusInstanceList := run(t, "incus list -f compact")
	if !regexp.MustCompile(`OperationsCenter\s+RUNNING`).MatchString(incusInstanceList.output.String()) {
		t.Log("====[ Install Operations Center in a VM ]====")
		run(t, `incus init --empty --vm OperationsCenter -c security.secureboot=false -c limits.cpu=%d -c limits.memory=%s -d root,size=%s`, cpuCount, memorySize, diskSize)
		run(t, `incus config device add OperationsCenter vtpm tpm`)
		run(t, `incus config device add OperationsCenter boot-media disk pool=default source=IncusOS_OperationsCenter.iso boot.priority=10`)
		run(t, `incus start OperationsCenter`)

		t.Log("====[ Waiting for Operations Center to complete installation ]====")
		waitAgentRunning(t, "OperationsCenter")
		waitExpectedLog(t, "OperationsCenter", "incus-osd", "IncusOS was successfully installed")
	}

	instanceHasBootMedia := run(t, "incus config device list OperationsCenter")
	if strings.Contains(instanceHasBootMedia.output.String(), "boot-media") {
		t.Log("====[ Removing boot media from Operations Center VM ]====")
		cmd(t, `incus stop OperationsCenter`)
		run(t, `incus config device remove OperationsCenter boot-media`)
		run(t, `incus start OperationsCenter`)
	}

	t.Log("====[ Waiting for Operations Center to be ready ]====")
	waitAgentRunning(t, "OperationsCenter")
	waitExpectedLog(t, "OperationsCenter", "incus-osd", "System is ready")

	t.Log("====[ Replacing operations-center binary with latest build ]====")
	run(t, `incus exec OperationsCenter -- bash -c "systemctl stop operations-center"`)
	run(t, `incus file push ../bin/operations-centerd OperationsCenter/root/operations-centerd`)
	run(t, `incus exec OperationsCenter -- bash -c "mount -o bind /root/operations-centerd /usr/local/bin/operations-centerd && systemctl start operations-center"`)

	t.Log("====[ Preparing local configuration for operations-center CLI ]====")
	err = os.MkdirAll(filepath.Join(homeDir, ".config/operations-center"), 0o700)
	require.NoError(t, err)
	run(t, `bash -c "cp %[1]s/.config/incus/client.* %[1]s/.config/operations-center/"`, homeDir)

	t.Log("====[ Adding Operations Center instance as remote ]====")
	incusInstanceList = run(t, `incus list -f json`)
	operationsCenterIPAddress := gjson.Get(incusInstanceList.output.String(), `@values:#(name=="OperationsCenter")|0.state.network.@values.#(addresses.#>0).addresses.#(scope=="global")#|#(family=="inet").address`).String()

	operationsCenterCetificate := run(t, `bash -c "openssl s_client -connect %s:8443 </dev/null 2>/dev/null | openssl x509 -outform PEM | sed 's/^/      /'"`, operationsCenterIPAddress)

	operationsCenterConfigYAML := replacePlaceholders(operationsCenterConfigYAMLTemplate,
		map[string]string{
			"$OPERATIONS_CENTER_IPADDRESS$":   operationsCenterIPAddress,
			"$OPERATIONS_CENTER_CERTIFICATE$": operationsCenterCetificate.output.String(),
		},
	)

	err = os.WriteFile(filepath.Join(homeDir, ".config/operations-center/config.yml"), operationsCenterConfigYAML, 0o600)
	require.NoError(t, err)

	tokenResp := run(t, `../bin/operations-center.linux.amd64 provisioning token list -f json`)
	token := gjson.Get(tokenResp.output.String(), "0.uuid").String()
	if token == "" {
		t.Log("====[ Creating provisioning token for IncusOS installation ]====")
		run(t, `../bin/operations-center.linux.amd64 provisioning token add --description "test" --uses 50`)
		tokenResp := run(t, `../bin/operations-center.linux.amd64 provisioning token list -f json`)
		token = gjson.Get(tokenResp.output.String(), "0.uuid").String()
	}

	t.Log("====[ Waiting for updates to be available in Operations Center ]====")
	waitUpdatesReady(t)

	incusOSPreseededISOFilename := fmt.Sprintf("IncusOS-preseeded-%[1]s.iso", token)
	if !isFile(filepath.Join(tmpDir, incusOSPreseededISOFilename)) {
		t.Log("====[ Create IncusOS ISO for Incus installation with preseeded client certificate ]====")

		incusOSSeedFileYAML := replacePlaceholders(incusOSSeedFileYAMLTemplate,
			map[string]string{
				"$CLIENT_CERTIFICATE$": indent(string(clientCertificate), strings.Repeat(" ", 10)),
			},
		)

		err = os.WriteFile(filepath.Join(tmpDir, "incusos_seed.yaml"), incusOSSeedFileYAML, 0o600)
		require.NoError(t, err)

		run(t, `../bin/operations-center.linux.amd64 provisioning token get-image %[1]s %[2]s/%[3]s %[2]s/incusos_seed.yaml`, token, tmpDir, incusOSPreseededISOFilename)
	}

	storageVolumes = run(t, "incus storage volume list default -f compact")
	if !strings.Contains(storageVolumes.output.String(), incusOSPreseededISOFilename) {
		t.Log("====[ Import IncusOS into Incus ]====")

		run(t, `incus storage volume import default %[2]s/%[3]s %[3]s --type=iso`, token, tmpDir, incusOSPreseededISOFilename)
	}

	// TODO: loop 3 incus os instances
}
