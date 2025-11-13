package e2e

import (
	"bytes"
)

var (
	operationsCenterSeedTemplate = []byte(`{
  "seeds": {
    "install": {
      "version": "1",
      "force_install": false,
      "force_reboot": false
    },
    "applications": {
      "version": "1",
      "applications": [
        {
          "name": "operations-center"
        }
      ]
    },
    "operations-center": {
      "version": "1",
      "trusted_client_certificates": [
        $CLIENT_CERTIFICATE$
      ]
    }
  },
  "type": "iso",
  "architecture": "x86_64"
}
`)

	operationsCenterConfigYAMLTemplate = []byte(`---
default_remote: test
remotes:
  test:
    addr: https://$OPERATIONS_CENTER_IPADDRESS$:8443/
    auth_type: tls
    server_cert: |
$OPERATIONS_CENTER_CERTIFICATE$
`)

	incusOSSeedFileYAMLTemplate = []byte(`---
applications:
  version: 1
  applications:
    - name: incus
incus:
  version: 1
  preseed:
    certificates:
      - name: local-client
        type: client
        certificate: |
$CLIENT_CERTIFICATE$
        description: Local client certificate
`)
)

func replacePlaceholders(in []byte, vars map[string]string) []byte {
	for key, value := range vars {
		in = bytes.ReplaceAll(in, []byte(key), []byte(value))
	}

	return in
}
