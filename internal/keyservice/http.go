package keyservice

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

const maxRequestBytes = 8192

// strictJSON rejects unknown fields, repeated fields, null and trailing JSON.
// All protocol fields are scalar; nested values are rejected by typed decoding.
func strictJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("expected JSON object")
	}
	seen := make(map[string]bool)
	fields := reflect.TypeOf(out).Elem()
	allowed := make(map[string]bool, fields.NumField())
	for i := 0; i < fields.NumField(); i++ {
		allowed[strings.Split(fields.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] || !allowed[key] {
			return errors.New("duplicate or invalid JSON key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
func readJSON(w http.ResponseWriter, r *http.Request, out any) error {
	if r.URL.RawQuery != "" {
		return errors.New("unexpected query")
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err != nil {
		return err
	}
	return strictJSON(raw, out)
}
func rpcAuthorized(s *State, r *http.Request) bool {
	if len(r.Header.Values("Authorization")) != 1 || len(r.Header.Values("X-FamilyChat-Issuer")) != 1 {
		return false
	}
	expected := "Bearer " + base64.StdEncoding.EncodeToString(s.TicketSecret)
	return hmac.Equal([]byte(r.Header.Get("Authorization")), []byte(expected)) && hmac.Equal([]byte(r.Header.Get("X-FamilyChat-Issuer")), []byte(s.TicketIssuer))
}
func failJSON(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}

type rateEntry struct {
	window int64
	count  int
}
type limiter struct {
	mu      sync.Mutex
	clients map[string]rateEntry
	global  rateEntry
}

func (l *limiter) allow(addr string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	second := now.Unix()
	if l.global.window != second {
		l.global = rateEntry{window: second}
	}
	l.global.count++
	if l.global.count > 60 {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	minute := second / 60
	entry, found := l.clients[host]
	if !found && len(l.clients) >= 4096 {
		for key, value := range l.clients {
			if value.window < minute {
				delete(l.clients, key)
			}
		}
		if len(l.clients) >= 4096 {
			return false
		}
	}
	if entry.window != minute {
		entry = rateEntry{window: minute}
	}
	entry.count++
	l.clients[host] = entry
	return entry.count <= 30
}

func NewHandler(s *State, store *GrantStore) http.Handler {
	l := &limiter{clients: make(map[string]rateEntry)}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.URL.Path != "/health/ready" && r.URL.Path != KeyPath && r.URL.Path != GrantPath {
			failJSON(w, 404, "not_found")
			return
		}
		method := http.MethodPost
		if r.URL.Path == "/health/ready" {
			method = http.MethodGet
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			failJSON(w, 405, "method_not_allowed")
			return
		}
		if r.URL.Path == "/health/ready" {
			if !store.ready() {
				failJSON(w, 503, "store_unavailable")
				return
			}
			_, _ = w.Write([]byte("{\"status\":\"ready\",\"key_delivery\":\"device-grant-v1\"}\n"))
			return
		}
		if !l.allow(r.RemoteAddr, time.Now()) {
			w.Header().Set("Retry-After", "60")
			failJSON(w, 429, "too_many_requests")
			return
		}
		if r.URL.Path == GrantPath {
			if !rpcAuthorized(s, r) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="familychat-keyserver"`)
				failJSON(w, 401, "unauthorized")
				return
			}
			var grant DeviceGrant
			if readJSON(w, r, &grant) != nil {
				failJSON(w, 400, "invalid_grant")
				return
			}
			switch err := store.Register(grant, s.KeyID); {
			case err == nil:
				w.WriteHeader(204)
			case errors.Is(err, errInvalidGrant):
				failJSON(w, 400, "invalid_grant")
			case errors.Is(err, errGrantConflict):
				failJSON(w, 409, "grant_conflict")
			default:
				failJSON(w, 503, "store_unavailable")
			}
			return
		}
		var proof DeviceProof
		if readJSON(w, r, &proof) != nil {
			failJSON(w, 400, "invalid_request")
			return
		}
		if err := store.Consume(proof, s.KeyID); err != nil {
			switch {
			case errors.Is(err, errInvalidGrant):
				failJSON(w, 401, "invalid_grant")
			case errors.Is(err, errGrantConsumed):
				failJSON(w, 409, "grant_consumed")
			default:
				failJSON(w, 503, "store_unavailable")
			}
			return
		}
		// Never log the proof or this response. Consumption has already been fsynced.
		_ = json.NewEncoder(w).Encode(struct {
			Scheme  string `json:"scheme"`
			KeyID   string `json:"key_id"`
			Public  []byte `json:"public_key"`
			Private []byte `json:"private_key"`
		}{Scheme, s.KeyID, s.PublicKey, s.PrivateKey})
	})
}
func (s *GrantStore) ready() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.unavailable && s.lock != nil
}
