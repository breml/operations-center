package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	incustls "github.com/lxc/incus/v7/shared/tls"
	"github.com/stretchr/testify/require"

	"github.com/FuturFusion/operations-center/internal/client"
	"github.com/FuturFusion/operations-center/internal/security/authn"
	authntls "github.com/FuturFusion/operations-center/internal/security/authn/tls"
	authnunixsocket "github.com/FuturFusion/operations-center/internal/security/authn/unixsocket"
	"github.com/FuturFusion/operations-center/shared/api"
)

func Test_api10Get_starting(t *testing.T) {
	t.Parallel()

	startingAuthenticator := func(string) authn.Authenticator {
		return authn.New([]authn.Auther{authnunixsocket.UnixSocket{}}, authn.WithStarting())
	}

	loadedAuthenticator := func(trustedFingerprint string) authn.Authenticator {
		return authn.New([]authn.Auther{authnunixsocket.UnixSocket{}, authntls.New([]string{trustedFingerprint})})
	}

	withClientCertificate := func(cert *incustls.CertInfo) []client.Option {
		return []client.Option{client.WithClientCertificate(cert)}
	}

	withoutClientCertificate := func(*incustls.CertInfo) []client.Option {
		return nil
	}

	tests := []struct {
		name             string
		newAuthenticator func(trustedFingerprint string) authn.Authenticator
		clientOptions    func(cert *incustls.CertInfo) []client.Option

		assertErr require.ErrorAssertionFunc
		wantAuth  string
	}{
		{
			name:             "starting - trusted client certificate",
			newAuthenticator: startingAuthenticator,
			clientOptions:    withClientCertificate,

			assertErr: func(tt require.TestingT, err error, _ ...any) {
				require.ErrorContains(tt, err, "Operations Center is still starting", "expect a retryable error instead of untrusted")
				require.True(tt, api.StatusErrorCheck(err, http.StatusTooEarly), "expect 425 Too Early")
			},
			wantAuth: "",
		},
		{
			name:             "starting - without client certificate",
			newAuthenticator: startingAuthenticator,
			clientOptions:    withoutClientCertificate,

			assertErr: require.NoError,
			wantAuth:  api.AuthenticationUntrusted,
		},
		{
			name:             "loaded - trusted client certificate",
			newAuthenticator: loadedAuthenticator,
			clientOptions:    withClientCertificate,

			assertErr: require.NoError,
			wantAuth:  api.AuthenticationMethodTLS,
		},
		{
			name:             "loaded - without client certificate",
			newAuthenticator: loadedAuthenticator,
			clientOptions:    withoutClientCertificate,

			assertErr: require.NoError,
			wantAuth:  api.AuthenticationUntrusted,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			cert := newTestClientCertificate(t)
			authenticator := tc.newAuthenticator(cert.Fingerprint())
			ocClient := newAPI10TestServer(t, authenticator, tc.clientOptions(cert)...)

			// Run test
			serverInfo, err := ocClient.GetAPIServerInfo(t.Context())

			// Assert
			tc.assertErr(t, err)
			require.Equal(t, tc.wantAuth, serverInfo.Auth, "unexpected authentication method reported by GET /1.0")
		})
	}
}

func Test_api10Get_startingRetry(t *testing.T) {
	t.Parallel()

	// Setup
	cert := newTestClientCertificate(t)
	authenticator := authn.New([]authn.Auther{authnunixsocket.UnixSocket{}}, authn.WithStarting())
	ocClient := newAPI10TestServer(t, authenticator, client.WithClientCertificate(cert))

	// Run test
	_, errStarting := ocClient.GetAPIServerInfo(t.Context())
	authenticator.Replace(authn.New([]authn.Auther{authntls.New([]string{cert.Fingerprint()})}))
	serverInfo, errLoaded := ocClient.GetAPIServerInfo(t.Context())

	// Assert
	require.ErrorContains(t, errStarting, "Operations Center is still starting", "expect a retryable error before the security configuration is loaded")
	require.True(t, api.StatusErrorCheck(errStarting, http.StatusTooEarly), "expect 425 Too Early before the security configuration is loaded")
	require.NoError(t, errLoaded, "expect the retry to succeed after the security configuration is loaded")
	require.Equal(t, api.AuthenticationMethodTLS, serverInfo.Auth, "expect the client to be trusted after the security configuration is loaded")
}

func newTestClientCertificate(t *testing.T) *incustls.CertInfo {
	t.Helper()

	certPEM, keyPEM, err := incustls.GenerateMemCert(true, false)
	require.NoError(t, err)

	cert, err := incustls.KeyPairFromRaw(certPEM, keyPEM)
	require.NoError(t, err)

	return cert
}

// newAPI10TestServer serves GET /1.0 like the daemon, exempt from authentication.
func newAPI10TestServer(t *testing.T, authenticator authn.Authenticator, opts ...client.Option) client.OperationsCenterClient {
	t.Helper()

	serveMux := http.NewServeMux()
	router := newRouter(serveMux).SubGroup("/1.0").AddMiddlewares(authenticator.Middleware(
		authn.WithIsAuthenticationRequired(func(r *http.Request) bool {
			return r.Method != http.MethodGet || r.URL.Path != "/1.0"
		}),
		authn.WithIsAuthenticationReported(func(r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == "/1.0"
		}),
	))
	registerAPI10Handler(router)

	server := httptest.NewUnstartedServer(serveMux)
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)

	ocClient, err := client.New(server.URL, append(opts, client.WithTrustedServerCertificate(server.Certificate()))...)
	require.NoError(t, err)

	return ocClient
}
