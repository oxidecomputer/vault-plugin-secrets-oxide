package oxidesecrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDeviceToken(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/device/auth":
			if !assert.NoError(t, r.ParseForm()) {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			assert.Equal(t, url.Values{
				"client_id":   {clientID},
				"ttl_seconds": {"123"},
			}, r.PostForm)
			fmt.Fprint(w, `{"device_code":"test-device-code","user_code":"test-user-code"}`)
		case "/device/confirm":
			assert.Equal(t, "Bearer test-principal-token", r.Header.Get("Authorization"))
			var body map[string]string
			if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&body)) {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			assert.Equal(t, map[string]string{"user_code": "test-user-code"}, body)
			w.WriteHeader(http.StatusNoContent)
		case "/device/token":
			if !assert.NoError(t, r.ParseForm()) {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			assert.Equal(t, url.Values{
				"client_id":   {clientID},
				"device_code": {"test-device-code"},
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			}, r.PostForm)
			fmt.Fprint(w, `{
				"access_token":"test-access-token",
				"token_type":"bearer",
				"token_id":"test-token-id",
				"time_expires":"2026-09-17T12:02:03Z"
			}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fakeServer.Close)

	token, err := createDeviceToken(t.Context(), &oxidePrincipal{
		Host:  fakeServer.URL,
		Token: "test-principal-token",
	}, 123*time.Second)
	require.NoError(t, err)
	expiresAt := time.Date(2026, time.September, 17, 12, 2, 3, 0, time.UTC)
	require.Equal(t, &deviceTokenResp{
		AccessToken: "test-access-token",
		TokenType:   "bearer",
		TokenID:     "test-token-id",
		TimeExpires: &expiresAt,
	}, token)
}
