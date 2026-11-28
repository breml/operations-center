package authn_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/FuturFusion/operations-center/internal/security/authn"
)

type trustedAuther struct{}

func (trustedAuther) Auth(w http.ResponseWriter, r *http.Request) (bool, string, string, error) {
	return true, "testuser", "testprotocol", nil
}

func TestAuthenticator_Middleware_crossOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  string
		headers map[string]string

		wantStatusCode int
	}{
		{
			name:   "success - POST without browser headers",
			method: http.MethodPost,
			headers: map[string]string{
				"Content-Type": "application/json",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:   "success - POST with Sec-Fetch-Site same-origin",
			method: http.MethodPost,
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Content-Type":   "application/json",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:   "success - POST with Sec-Fetch-Site none",
			method: http.MethodPost,
			headers: map[string]string{
				"Sec-Fetch-Site": "none",
				"Content-Type":   "application/json",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:   "success - POST with Origin matching Host",
			method: http.MethodPost,
			headers: map[string]string{
				"Origin":       "https://oc.example:8443",
				"Content-Type": "application/json",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:   "success - GET with Sec-Fetch-Site cross-site",
			method: http.MethodGet,
			headers: map[string]string{
				"Sec-Fetch-Site": "cross-site",
				"Origin":         "https://attacker.example",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:   "error - POST with Sec-Fetch-Site cross-site",
			method: http.MethodPost,
			headers: map[string]string{
				"Sec-Fetch-Site": "cross-site",
				"Origin":         "https://attacker.example",
				"Content-Type":   "text/plain",
			},

			wantStatusCode: http.StatusForbidden,
		},
		{
			name:   "error - PUT with Sec-Fetch-Site same-site",
			method: http.MethodPut,
			headers: map[string]string{
				"Sec-Fetch-Site": "same-site",
				"Origin":         "https://other.oc.example",
			},

			wantStatusCode: http.StatusForbidden,
		},
		{
			name:   "error - DELETE with foreign Origin and without Sec-Fetch-Site",
			method: http.MethodDelete,
			headers: map[string]string{
				"Origin": "https://attacker.example",
			},

			wantStatusCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			authenticator := authn.New([]authn.Auther{trustedAuther{}})
			handler := authenticator.Middleware()(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(tc.method, "https://oc.example:8443/internal/sql", http.NoBody)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			rec := httptest.NewRecorder()

			// Run test
			handler(rec, req)

			// Assert
			require.Equal(t, tc.wantStatusCode, rec.Code, "unexpected status code, body: %s", rec.Body.String())
		})
	}
}

func TestAuthenticator_Middleware_contentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opts       []authn.MiddlewareOption
		remoteAddr string
		headers    map[string]string

		wantStatusCode int
	}{
		{
			name:       "success - POST with application/json",
			opts:       nil,
			remoteAddr: "192.0.2.1:1234",
			headers: map[string]string{
				"Content-Type": "application/json",
			},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:       "success - POST without Content-Type through unix socket",
			opts:       nil,
			remoteAddr: "@",
			headers:    map[string]string{},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name: "success - POST without Content-Type for exempt request",
			opts: []authn.MiddlewareOption{
				authn.WithIsContentTypeCheckExempt(func(r *http.Request) bool { return true }),
			},
			remoteAddr: "192.0.2.1:1234",
			headers:    map[string]string{},

			wantStatusCode: http.StatusNoContent,
		},
		{
			name:       "error - POST without Content-Type",
			opts:       nil,
			remoteAddr: "192.0.2.1:1234",
			headers:    map[string]string{},

			wantStatusCode: http.StatusUnsupportedMediaType,
		},
		{
			name:       "error - POST with text/plain",
			opts:       nil,
			remoteAddr: "192.0.2.1:1234",
			headers: map[string]string{
				"Content-Type": "text/plain",
			},

			wantStatusCode: http.StatusUnsupportedMediaType,
		},
		{
			name: "error - POST with text/plain for request not exempt",
			opts: []authn.MiddlewareOption{
				authn.WithIsContentTypeCheckExempt(func(r *http.Request) bool { return false }),
			},
			remoteAddr: "192.0.2.1:1234",
			headers: map[string]string{
				"Content-Type": "text/plain",
			},

			wantStatusCode: http.StatusUnsupportedMediaType,
		},
		{
			name:       "error - cross-origin POST with text/plain is rejected by the cross-origin check first",
			opts:       nil,
			remoteAddr: "192.0.2.1:1234",
			headers: map[string]string{
				"Content-Type":   "text/plain",
				"Sec-Fetch-Site": "cross-site",
				"Origin":         "https://attacker.example",
			},

			wantStatusCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			authenticator := authn.New([]authn.Auther{trustedAuther{}})
			handler := authenticator.Middleware(tc.opts...)(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodPost, "https://oc.example:8443/internal/sql", http.NoBody)
			req.RemoteAddr = tc.remoteAddr
			req.TLS = nil
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			rec := httptest.NewRecorder()

			// Run test
			handler(rec, req)

			// Assert
			require.Equal(t, tc.wantStatusCode, rec.Code, "unexpected status code, body: %s", rec.Body.String())
		})
	}
}

type headerAuther struct{}

func (headerAuther) Auth(_ http.ResponseWriter, r *http.Request) (bool, string, string, error) {
	return r.Header.Get("X-Trusted") != "", "user", "test", nil
}

func TestAuthenticator_Middleware_starting(t *testing.T) {
	t.Parallel()

	authenticationRequired := func(*http.Request) bool { return true }
	authenticationExempt := func(*http.Request) bool { return false }
	authenticationReported := func(*http.Request) bool { return true }
	authenticationNotReported := func(*http.Request) bool { return false }

	withTrusted := func(r *http.Request) { r.Header.Set("X-Trusted", "1") }
	withoutCredentials := func(*http.Request) {}
	withClientCertificate := func(r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	}

	withAuthorizationHeader := func(r *http.Request) { r.Header.Set("Authorization", "Bearer token") }
	withOIDCCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: authn.OIDCAccessCookieName, Value: "token"}) }

	const (
		nextHandlerCalled = "next handler called"
		tooEarlyBody      = `"error_code":425,"error":"Operations Center is still starting"`
		unauthorizedBody  = `"error_code":401,"error":"Unauthorized"`
	)

	tests := []struct {
		name                     string
		opts                     []authn.Option
		isAuthenticationRequired func(*http.Request) bool
		isAuthenticationReported func(*http.Request) bool
		prepareRequest           func(r *http.Request)

		wantStatusCode int
		wantBody       string
	}{
		{
			name:                     "starting - authentication required - trusted",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationRequired,
			isAuthenticationReported: authenticationNotReported,
			prepareRequest:           withTrusted,

			wantStatusCode: http.StatusOK,
			wantBody:       nextHandlerCalled,
		},
		{
			name:                     "starting - authentication required - no credentials",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationRequired,
			isAuthenticationReported: authenticationNotReported,
			prepareRequest:           withoutCredentials,

			wantStatusCode: http.StatusTooEarly,
			wantBody:       tooEarlyBody,
		},
		{
			name:                     "starting - authentication exempt - reported - no credentials",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest:           withoutCredentials,

			wantStatusCode: http.StatusOK,
			wantBody:       nextHandlerCalled,
		},
		{
			name:                     "starting - authentication exempt - reported - trusted with client certificate",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest: func(r *http.Request) {
				withTrusted(r)
				withClientCertificate(r)
			},

			wantStatusCode: http.StatusOK,
			wantBody:       nextHandlerCalled,
		},
		{
			name:                     "starting - authentication exempt - reported - client certificate",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest:           withClientCertificate,

			wantStatusCode: http.StatusTooEarly,
			wantBody:       tooEarlyBody,
		},
		{
			name:                     "starting - authentication exempt - reported - authorization header",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest:           withAuthorizationHeader,

			wantStatusCode: http.StatusTooEarly,
			wantBody:       tooEarlyBody,
		},
		{
			name:                     "starting - authentication exempt - reported - OIDC cookie",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest:           withOIDCCookie,

			wantStatusCode: http.StatusTooEarly,
			wantBody:       tooEarlyBody,
		},
		{
			name:                     "starting - authentication exempt - not reported - client certificate",
			opts:                     []authn.Option{authn.WithStarting()},
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationNotReported,
			prepareRequest:           withClientCertificate,

			wantStatusCode: http.StatusOK,
			wantBody:       nextHandlerCalled,
		},
		{
			name:                     "started - authentication required - no credentials",
			opts:                     nil,
			isAuthenticationRequired: authenticationRequired,
			isAuthenticationReported: authenticationNotReported,
			prepareRequest:           withoutCredentials,

			wantStatusCode: http.StatusUnauthorized,
			wantBody:       unauthorizedBody,
		},
		{
			name:                     "started - authentication exempt - reported - client certificate",
			opts:                     nil,
			isAuthenticationRequired: authenticationExempt,
			isAuthenticationReported: authenticationReported,
			prepareRequest:           withClientCertificate,

			wantStatusCode: http.StatusOK,
			wantBody:       nextHandlerCalled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup
			authenticator := authn.New([]authn.Auther{headerAuther{}}, tc.opts...)
			handler := authenticator.Middleware(
				authn.WithIsAuthenticationRequired(tc.isAuthenticationRequired),
				authn.WithIsAuthenticationReported(tc.isAuthenticationReported),
			)(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(nextHandlerCalled))
			})

			r := httptest.NewRequest(http.MethodGet, "/1.0", http.NoBody)
			tc.prepareRequest(r)

			w := httptest.NewRecorder()

			// Run test
			handler(w, r)

			// Assert
			require.Equal(t, tc.wantStatusCode, w.Code, "unexpected status code, body: %s", w.Body.String())
			require.Contains(t, w.Body.String(), tc.wantBody, "unexpected response body")
		})
	}
}

func TestAuthenticator_Replace_concurrent(t *testing.T) {
	authenticator := authn.New([]authn.Auther{headerAuther{}}, authn.WithStarting())
	handler := authenticator.Middleware()(func(w http.ResponseWriter, r *http.Request) {})

	done := make(chan struct{})
	go func() {
		defer close(done)

		for range 100 {
			authenticator.Replace(authn.New([]authn.Auther{headerAuther{}}))
		}
	}()

	for range 100 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Trusted", "1")

		w := httptest.NewRecorder()
		handler(w, r)
		require.Equal(t, http.StatusOK, w.Code)
	}

	<-done

	// After the replacement, the authenticator is no longer starting.
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
