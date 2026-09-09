package incus_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	incusosapi "github.com/lxc/incus-os/incus-osd/api"
	incustls "github.com/lxc/incus/v7/shared/tls"
	"github.com/stretchr/testify/require"

	"github.com/FuturFusion/operations-center/internal/adapter/incus"
	"github.com/FuturFusion/operations-center/internal/provisioning"
	"github.com/FuturFusion/operations-center/internal/provisioning/adapter/scriptlet"
	"github.com/FuturFusion/operations-center/internal/util/testing/queue"
	"github.com/FuturFusion/operations-center/shared/api"
)

type clientPort interface {
	provisioning.ServerClientPort
	provisioning.ClusterClientPort
	scriptlet.ScriptletClientPort

	GetOSService(ctx context.Context, server provisioning.Server, name string) (map[string]any, error)
	GetOSServiceCeph(ctx context.Context, server provisioning.Server) (incusosapi.ServiceCeph, error)
	GetOSServiceLinstor(ctx context.Context, server provisioning.Server) (incusosapi.ServiceLinstor, error)
	GetOSServiceLVM(ctx context.Context, server provisioning.Server) (incusosapi.ServiceLVM, error)
	GetOSServiceOVN(ctx context.Context, server provisioning.Server) (incusosapi.ServiceOVN, error)
	GetOSServiceTailscale(ctx context.Context, server provisioning.Server) (incusosapi.ServiceTailscale, error)
	GetOSServiceUSBIP(ctx context.Context, server provisioning.Server) (incusosapi.ServiceUSBIP, error)
}

type methodTestSetEndpoint struct {
	name       string
	clientCall func(ctx context.Context, client clientPort, endpoint provisioning.Endpoint) (any, error)

	testCases []methodTestCase
}

type methodTestSetServer struct {
	name       string
	clientCall func(ctx context.Context, client clientPort, endpoint provisioning.Server) (any, error)

	testCases []methodTestCase
}

type methodTestCase struct {
	name     string
	response []queue.Item[response]

	assertErr    require.ErrorAssertionFunc
	wantPaths    []string
	assertBodies func(t *testing.T, gotBodies []string)
	assertResult func(t *testing.T, res any)
}

type response struct {
	statusCode   int
	responseBody []byte
}

func noResult(t *testing.T, res any) {
	t.Helper()
}

func TestClient_Endpoint(t *testing.T) {
	caPool, certPEM, keyPEM := setupCerts(t)

	methods := []methodTestSetEndpoint{
		{
			name: "Ping",
			clientCall: func(ctx context.Context, c clientPort, endpoint provisioning.Endpoint) (any, error) {
				return nil, c.Ping(ctx, endpoint)
			},
			testCases: []methodTestCase{
				{
					name: "success",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": {}
}`),
							},
						},
					},

					assertErr: require.NoError,
					wantPaths: []string{"GET /"},
				},
				{
					name: "error - unexpected http status code",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusInternalServerError,
							},
						},
					},

					assertErr: require.Error,
					wantPaths: []string{"GET /"},
				},
			},
		},

		{
			name: "GetClusterNodeNames",
			clientCall: func(ctx context.Context, client clientPort, endpoint provisioning.Endpoint) (any, error) {
				return client.GetClusterNodeNames(ctx, endpoint)
			},
			testCases: []methodTestCase{
				{
					name: "success",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": [ "https://127.0.0.1/cluster/members/one" ]
}`),
							},
						},
					},

					assertErr: require.NoError,
					assertResult: func(t *testing.T, res any) {
						t.Helper()
						require.Len(t, res, 1)
					},
					wantPaths: []string{"GET /1.0/cluster/members"},
				},
				{
					name: "error - unexpected http status code",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusInternalServerError,
							},
						},
					},

					assertErr:    require.Error,
					assertResult: noResult,
					wantPaths:    []string{"GET /1.0/cluster/members"},
				},
			},
		},
		{
			name: "GetClusterJoinToken",
			clientCall: func(ctx context.Context, client clientPort, endpoint provisioning.Endpoint) (any, error) {
				return client.GetClusterJoinToken(ctx, endpoint, "server1")
			},
			testCases: []methodTestCase{
				{
					name: "success",
					response: []queue.Item[response]{
						// GET /1.0/events
						{
							Value: response{
								statusCode:   http.StatusForbidden,
								responseBody: []byte(`{"type": "error", "error_code": 403, "error": "websocket forbidden"}`), // Prevent the websocket listener.
							},
						},
						// POST /1.0/cluster/members
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": {
    "metadata": {
      "serverName": "server1",
      "secret": "secret",
      "fingerprint": "fingerprint",
      "addresses": ["1.0.0.1", "1.0.0.2"],
      "expiresAt": "2025-06-17T15:39:19.0Z"
    }
  }
}`),
							},
						},
					},

					assertErr: require.NoError,
					wantPaths: []string{"GET /1.0/events", "POST /1.0/cluster/members"},
					assertResult: func(t *testing.T, res any) {
						t.Helper()
						// base64 encoded token from response body metadata.metadata.
						wantToken := "eyJzZXJ2ZXJfbmFtZSI6InNlcnZlcjEiLCJmaW5nZXJwcmludCI6ImZpbmdlcnByaW50IiwiYWRkcmVzc2VzIjpbIjEuMC4wLjEiLCIxLjAuMC4yIl0sInNlY3JldCI6InNlY3JldCIsImV4cGlyZXNfYXQiOiIyMDI1LTA2LTE3VDE1OjM5OjE5WiJ9"
						require.Equal(t, wantToken, res)
					},
				},
				{
					name: "error - CreateClusterMember - unexpected status code",
					response: []queue.Item[response]{
						// GET /1.0/events
						{
							Value: response{
								statusCode:   http.StatusForbidden,
								responseBody: []byte(`{"type": "error", "error_code": 403, "error": "websocket forbidden"}`), // Prevent the websocket listener.
							},
						},
						// POST /1.0/cluster/members
						{
							Value: response{
								statusCode: http.StatusInternalServerError,
							},
						},
					},

					assertErr:    require.Error,
					wantPaths:    []string{"GET /1.0/events", "POST /1.0/cluster/members"},
					assertResult: noResult,
				},
				{
					name: "error - invalid cluster join token",
					response: []queue.Item[response]{
						// GET /1.0/events
						{
							Value: response{
								statusCode:   http.StatusForbidden,
								responseBody: []byte(`{"type": "error", "error_code": 403, "error": "websocket forbidden"}`), // Prevent the websocket listener.
							},
						},
						// POST /1.0/cluster/members
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": {
    "metadata": {
    }
  }
}`), // Join token content
							},
						},
					},

					assertErr: func(tt require.TestingT, err error, a ...any) {
						require.ErrorContains(tt, err, "Failed converting token operation to join token")
					},
					wantPaths:    []string{"GET /1.0/events", "POST /1.0/cluster/members"},
					assertResult: noResult,
				},
			},
		},
		{
			name: "UpdateClusterCertificate",
			clientCall: func(ctx context.Context, client clientPort, endpoint provisioning.Endpoint) (any, error) {
				return nil, client.UpdateClusterCertificate(ctx, endpoint, "new cert", "new key")
			},
			testCases: []methodTestCase{
				{
					name: "success",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": {}
}`),
							},
						},
					},

					assertErr: require.NoError,
					wantPaths: []string{"PUT /1.0/cluster/certificate"},
				},
				{
					name: "error - unexpected http status code",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusInternalServerError,
							},
						},
					},

					assertErr: require.Error,
					wantPaths: []string{"PUT /1.0/cluster/certificate"},
				},
			},
		},
		{
			name: "SystemFactoryReset",
			clientCall: func(ctx context.Context, c clientPort, endpoint provisioning.Endpoint) (any, error) {
				return nil, c.SystemFactoryReset(
					ctx,
					endpoint,
					false,
					provisioning.TokenImageSeedConfigs{
						Install: api.SeedInstall{
							Version: "1",
						},
						Network: api.SeedNetwork{
							Version: "1",
						},
						Update: api.SeedUpdate{
							Version: "1",
						},
					},
					api.TokenProviderConfig{},
				)
			},
			testCases: []methodTestCase{
				{
					name: "success",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusOK,
								responseBody: []byte(`{
  "metadata": {}
}`),
							},
						},
					},

					assertErr: require.NoError,
					wantPaths: []string{"POST /os/1.0/system/:factory-reset"},
				},
				{
					name: "error - unexpected http status code",
					response: []queue.Item[response]{
						{
							Value: response{
								statusCode: http.StatusInternalServerError,
							},
						},
					},

					assertErr: require.Error,
					wantPaths: []string{"POST /os/1.0/system/:factory-reset"},
				},
			},
		},
	}

	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			ctx := context.Background()

			// endpointGetClientErr error - invalid key pair
			endpointGetClientErr(t, method, caPool, certPEM)

			// run regular test cases
			for _, tc := range method.testCases {
				t.Run(tc.name, func(t *testing.T) {
					// Setup
					var gotPaths []string
					var gotBodies []string
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						gotPaths = append(gotPaths, fmt.Sprintf("%s %s", r.Method, r.URL.String()))

						body, _ := io.ReadAll(r.Body)
						gotBodies = append(gotBodies, string(body))

						response, _ := queue.Pop(t, &tc.response)
						w.WriteHeader(response.statusCode)
						_, _ = w.Write(response.responseBody)
					}))
					server.TLS = &tls.Config{
						NextProtos: []string{"h2", "http/1.1"},
						ClientAuth: tls.RequireAndVerifyClientCert,
						ClientCAs:  caPool,
					}

					server.StartTLS()
					defer server.Close()

					client := incus.New(certPEM, keyPEM, incus.WithSkipGetServer(true))

					serverCert := pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: server.Certificate().Raw,
					})

					target := provisioning.Server{
						ConnectionURL: server.URL,
						Certificate:   new(string(serverCert)),
					}

					// Run test
					retValue, err := method.clientCall(ctx, client, target)

					// Assert
					tc.assertErr(t, err)

					require.Equal(t, tc.wantPaths, gotPaths)

					if tc.assertResult != nil || retValue != nil {
						tc.assertResult(t, retValue)
					}

					if tc.assertBodies != nil {
						tc.assertBodies(t, gotBodies)
					}

					require.Empty(t, tc.response)
				})
			}
		})
	}
}

func endpointGetClientErr(t *testing.T, method methodTestSetEndpoint, caPool *x509.CertPool, certPEM string) {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}

	server.StartTLS()
	defer server.Close()

	client := incus.New(certPEM, certPEM, incus.WithSkipGetServer(true)) // invalid key

	serverCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})

	target := provisioning.Server{
		ConnectionURL: server.URL,
		Certificate:   new(string(serverCert)),
	}

	_, err := method.clientCall(context.Background(), client, target)
	require.Error(t, err)
}

func setupCerts(t *testing.T) (caPool *x509.CertPool, certPEM string, keyPEM string) {
	t.Helper()

	certPEMByte, keyPEMByte, err := incustls.GenerateMemCert(true, false)
	require.NoError(t, err)

	caPool = x509.NewCertPool()
	caPool.AppendCertsFromPEM(certPEMByte)

	return caPool, string(certPEMByte), string(keyPEMByte)
}

func TestClient_input_validation(t *testing.T) {
	client := incus.New("", "", incus.WithSkipGetServer(true))

	_, err := client.GetSystem(t.Context(), provisioning.Server{}, "invalid/resource")
	require.ErrorContains(t, err, "must not contain forward slashes")

	err = client.UpdateSystem(t.Context(), provisioning.Server{}, "invalid/resource", nil)
	require.ErrorContains(t, err, "must not contain forward slashes")

	err = client.TriggerSystemAction(t.Context(), provisioning.Server{}, "invalid/resource", "action", nil)
	require.ErrorContains(t, err, "must not contain forward slashes")
	err = client.TriggerSystemAction(t.Context(), provisioning.Server{}, "resource", "invalid/action", nil)
	require.ErrorContains(t, err, "must not contain forward slashes")
}
