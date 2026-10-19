package keyservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signedTicket(t *testing.T, state *State, claims map[string]any, algorithm string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, state.TicketSecret)
	_, _ = mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestHTTPSKeyDeliveryRequiresValidShortLivedTicket(t *testing.T) {
	state, err := Initialize(filepath.Join(t.TempDir(), "state"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	base := func() map[string]any {
		return map[string]any{"iss": state.TicketIssuer, "aud": "familychat-keyserver", "sub": "fd134a54-1e31-4cf1-839f-4058ed14c6f5", "key_id": state.KeyID, "iat": now, "exp": now + 120}
	}
	server := httptest.NewTLSServer(NewHandler(state))
	defer server.Close()
	cases := []struct {
		name   string
		mutate func(map[string]any)
		alg    string
		status int
	}{
		{"valid", func(map[string]any) {}, "HS256", 200},
		{"expired", func(c map[string]any) { c["iat"] = now - 180; c["exp"] = now - 1 }, "HS256", 401},
		{"future", func(c map[string]any) { c["iat"] = now + 120; c["exp"] = now + 240 }, "HS256", 401},
		{"long lifetime", func(c map[string]any) { c["exp"] = now + 301 }, "HS256", 401},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "other family" }, "HS256", 401},
		{"wrong audience", func(c map[string]any) { c["aud"] = "mainserver" }, "HS256", 401},
		{"wrong key", func(c map[string]any) { c["key_id"] = "other" }, "HS256", 401},
		{"empty subject", func(c map[string]any) { c["sub"] = "" }, "HS256", 401},
		{"wrong algorithm", func(map[string]any) {}, "none", 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			tc.mutate(claims)
			req, _ := http.NewRequest("GET", server.URL+"/api/v1/keys/current", nil)
			req.Header.Set("Authorization", "Bearer "+signedTicket(t, state, claims, tc.alg))
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.status {
				t.Fatalf("status %d body %s", res.StatusCode, body)
			}
			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("response is cacheable")
			}
			if tc.status == 200 {
				var key struct {
					Scheme  string `json:"scheme"`
					KeyID   string `json:"key_id"`
					Private []byte `json:"private_key"`
					Public  []byte `json:"public_key"`
				}
				if err := json.Unmarshal(body, &key); err != nil {
					t.Fatal(err)
				}
				if key.Scheme != "fc1" || key.KeyID != state.KeyID || string(key.Private) != string(state.PrivateKey) || string(key.Public) != string(state.PublicKey) {
					t.Fatal("wrong client key material")
				}
			} else if strings.Contains(string(body), base64.StdEncoding.EncodeToString(state.PrivateKey)) {
				t.Fatal("unauthorized response leaked key")
			}
		})
	}
	for _, auth := range []string{"", "Bearer main-session-token", "Bearer " + signedTicket(t, state, base(), "HS256") + "x"} {
		req, _ := http.NewRequest("GET", server.URL+"/api/v1/keys/current", nil)
		req.Header.Set("Authorization", auth)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatalf("invalid authorization accepted: %d", res.StatusCode)
		}
	}
}

func TestReadinessContainsNoSecretsAndMethodRestricted(t *testing.T) {
	state, err := Initialize(filepath.Join(t.TempDir(), "state"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(state)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/health/ready", 200}, {"POST", "/api/v1/keys/current", 405}, {"GET", "/unknown", 404}} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(tc.method, tc.path, nil))
		if r.Code != tc.status {
			t.Fatalf("%s %s: %d", tc.method, tc.path, r.Code)
		}
		if strings.Contains(r.Body.String(), "private_key") || strings.Contains(r.Body.String(), "ticket_secret") {
			t.Fatal("secret in non-key endpoint")
		}
	}
}

func TestUnauthorizedRequestsAreRateLimited(t *testing.T) {
	state, err := Initialize(filepath.Join(t.TempDir(), "state"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(state)
	limited := false
	for i := 0; i < 100; i++ {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", "/api/v1/keys/current", nil))
		if r.Code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unbounded authentication attempts")
	}
}
