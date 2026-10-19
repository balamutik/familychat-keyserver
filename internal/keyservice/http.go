package keyservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ticketAudience = "familychat-keyserver"

func (s *State) authorize(token string, now time.Time) error {
	invalid := errors.New("invalid authorization ticket")
	if len(token) > 4096 {
		return invalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalid
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return invalid
	}
	var h struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if json.Unmarshal(header, &h) != nil || h.Algorithm != "HS256" || h.Type != "JWT" {
		return invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalid
	}
	mac := hmac.New(sha256.New, s.TicketSecret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return invalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return invalid
	}
	var claims struct {
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		KeyID    string `json:"key_id"`
		Issued   int64  `json:"iat"`
		Expires  int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return invalid
	}
	seconds := now.Unix()
	if claims.Issuer != s.TicketIssuer || claims.Audience != ticketAudience || claims.KeyID != s.KeyID || strings.TrimSpace(claims.Subject) == "" || len(claims.Subject) > 128 || claims.Issued <= 0 || claims.Issued > seconds+30 || claims.Expires <= seconds || claims.Expires <= claims.Issued || claims.Expires-claims.Issued > 300 || claims.Issued < seconds-300 {
		return invalid
	}
	return nil
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

func NewHandler(s *State) http.Handler {
	l := &limiter{clients: make(map[string]rateEntry)}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.URL.Path != "/health/ready" && r.URL.Path != KeyPath {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health/ready" {
			_, _ = w.Write([]byte("{\"status\":\"ready\"}\n"))
			return
		}
		if !l.allow(r.RemoteAddr, time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.RawQuery != "" {
			http.Error(w, `{"error":"unexpected request body or query"}`, http.StatusBadRequest)
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || s.authorize(strings.TrimPrefix(authorization, "Bearer "), time.Now()) != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="familychat-keyserver"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		// Never log the request authorization or this response payload.
		_ = json.NewEncoder(w).Encode(struct {
			Scheme  string `json:"scheme"`
			KeyID   string `json:"key_id"`
			Public  []byte `json:"public_key"`
			Private []byte `json:"private_key"`
		}{Scheme, s.KeyID, s.PublicKey, s.PrivateKey})
	})
}
