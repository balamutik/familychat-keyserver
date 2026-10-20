package keyservice

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testUser = "fd134a54-1e31-4cf1-839f-4058ed14c6f5"
const testDevice = "0bf77d2e-3afd-47df-bf75-b9000b82ec1a"
const otherDevice = "5ec89c82-173d-48f5-b26e-a0f744a18407"
const otherUser = "82c94188-bd19-4d2b-9133-7abe554d1c53"

type grantFixture struct {
	request DeviceGrant
	private *ecdsa.PrivateKey
}

func newGrantFixture(t *testing.T, state *State, device string) grantFixture {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return grantFixture{DeviceGrant{Version: 1, GrantID: hex.EncodeToString(id), UserID: testUser, DeviceID: device, DevicePublicKey: base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), private.X, private.Y)), KeyID: state.KeyID, ExpiresAt: time.Now().Unix() + 120}, private}
}
func (f grantFixture) proof(t *testing.T) DeviceProof {
	t.Helper()
	message := "familychat-device-grant-v1\n" + f.request.KeyID + "\n" + f.request.UserID + "\n" + f.request.DeviceID + "\n" + f.request.GrantID
	digest := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, f.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return DeviceProof{Version: 1, UserID: f.request.UserID, DeviceID: f.request.DeviceID, GrantID: f.request.GrantID, Signature: base64.StdEncoding.EncodeToString(signature)}
}
func testHandler(t *testing.T) (*State, *GrantStore, http.Handler) {
	t.Helper()
	state, err := Initialize(filepath.Join(t.TempDir(), "state"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenGrantStore(filepath.Join(t.TempDir(), "grants"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return state, store, NewHandler(state, store)
}
func serveJSON(t *testing.T, h http.Handler, state *State, path string, body any, authorize bool) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	if authorize {
		r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(state.TicketSecret))
		r.Header.Set("X-FamilyChat-Issuer", state.TicketIssuer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
}
func requireKey(t *testing.T, w *httptest.ResponseRecorder, state *State) {
	t.Helper()
	requireStatus(t, w, 200)
	var got struct {
		Scheme  string `json:"scheme"`
		KeyID   string `json:"key_id"`
		Public  []byte `json:"public_key"`
		Private []byte `json:"private_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scheme != "fc1" || got.KeyID != state.KeyID || !bytes.Equal(got.Public, state.PublicKey) || !bytes.Equal(got.Private, state.PrivateKey) {
		t.Fatal("content key changed")
	}
}

func TestTwoDevicesOfSameUserReceiveIndependentOneTimeGrants(t *testing.T) {
	state, _, h := testHandler(t)
	for _, device := range []string{testDevice, otherDevice} {
		f := newGrantFixture(t, state, device)
		requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
		requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
		proof := f.proof(t)
		requireKey(t, serveJSON(t, h, state, KeyPath, proof, false), state)
		requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
		w := serveJSON(t, h, state, KeyPath, proof, false)
		requireStatus(t, w, 409)
		if !strings.Contains(w.Body.String(), "grant_consumed") {
			t.Fatal(w.Body.String())
		}
	}
}
func TestWrongProofOrBindingDoesNotConsumeGrant(t *testing.T) {
	for _, which := range []string{"signature", "user", "device", "unknown", "message newline", "message key"} {
		t.Run(which, func(t *testing.T) {
			state, _, h := testHandler(t)
			f := newGrantFixture(t, state, testDevice)
			requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
			proof := f.proof(t)
			switch which {
			case "signature":
				proof.Signature = base64.StdEncoding.EncodeToString([]byte("bad"))
			case "user":
				proof.UserID = otherUser
			case "device":
				proof.DeviceID = otherDevice
			case "unknown":
				proof.GrantID = strings.Repeat("a", 64)
			case "message newline", "message key":
				message := "familychat-device-grant-v1\n" + f.request.KeyID + "\n" + f.request.UserID + "\n" + f.request.DeviceID + "\n" + f.request.GrantID
				if which == "message newline" {
					message += "\n"
				} else {
					message = strings.Replace(message, state.KeyID, strings.Repeat("b", 64), 1)
				}
				d := sha256.Sum256([]byte(message))
				sig, err := ecdsa.SignASN1(rand.Reader, f.private, d[:])
				if err != nil {
					t.Fatal(err)
				}
				proof.Signature = base64.StdEncoding.EncodeToString(sig)
			}
			w := serveJSON(t, h, state, KeyPath, proof, false)
			requireStatus(t, w, 401)
			if strings.Contains(w.Body.String(), "private_key") {
				t.Fatal("invalid proof leaked private material")
			}
			requireKey(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), state)
		})
	}
}
func TestDeviceBindingRejectsReplacementKeyAndConflictingGrantID(t *testing.T) {
	state, _, h := testHandler(t)
	f := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	conflict := f.request
	conflict.ExpiresAt++
	requireStatus(t, serveJSON(t, h, state, GrantPath, conflict, true), 409)
	other := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, other.request, true), 409)
	other.request.UserID = otherUser
	requireStatus(t, serveJSON(t, h, state, GrantPath, other.request, true), 204)
	requireKey(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), state)
}
func TestConcurrentConsumptionAndLostResponseRequireNewGrant(t *testing.T) {
	state, _, h := testHandler(t)
	f := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	p := f.proof(t)
	const clients = 16
	results := make(chan int, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- serveJSON(t, h, state, KeyPath, p, false).Code }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for status := range results {
		if status == 200 {
			successes++
		} else if status != 409 {
			t.Fatalf("unexpected concurrent status%d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("private key released %d times", successes)
	}
	requireStatus(t, serveJSON(t, h, state, KeyPath, p, false), 409)
	next := f
	next.request.GrantID = strings.Repeat("b", 64)
	requireStatus(t, serveJSON(t, h, state, GrantPath, next.request, true), 204)
	requireKey(t, serveJSON(t, h, state, KeyPath, next.proof(t), false), state)
}
func TestGrantExpiryAndMaximumTTL(t *testing.T) {
	state, store, h := testHandler(t)
	now := time.Now().Unix()
	store.now = func() time.Time { return time.Unix(now, 0) }
	f := newGrantFixture(t, state, testDevice)
	for _, expires := range []int64{now - 1, now, now + 301} {
		f.request.ExpiresAt = expires
		requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 400)
	}
	f.request.ExpiresAt = now + 120
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	// Move the store's clock past expiry without wall-clock sleeps.
	store.now = func() time.Time { return time.Unix(now+121, 0) }
	requireStatus(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), 401)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 400)
}
func TestRestartPersistsConsumptionAndDeviceBinding(t *testing.T) {
	state, store, h := testHandler(t)
	f := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	requireKey(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), state)
	pending := newGrantFixture(t, state, otherDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, pending.request, true), 204)
	dir := store.dir
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := OpenGrantStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	restarted := NewHandler(state, again)
	requireStatus(t, serveJSON(t, restarted, state, GrantPath, f.request, true), 204)
	requireStatus(t, serveJSON(t, restarted, state, KeyPath, f.proof(t), false), 409)
	requireKey(t, serveJSON(t, restarted, state, KeyPath, pending.proof(t), false), state)
	replacement := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, restarted, state, GrantPath, replacement.request, true), 409)
	raw, err := os.ReadFile(filepath.Join(dir, "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(f.request.GrantID)) {
		t.Fatal("stored raw bearer grant ID")
	}
	info, err := os.Stat(filepath.Join(dir, "grants.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("grant store is not mode0600")
	}
}
func TestRPCAuthenticationAndStrictGrantValidation(t *testing.T) {
	state, _, h := testHandler(t)
	f := newGrantFixture(t, state, testDevice)
	raw, _ := json.Marshal(f.request)
	for _, which := range []string{"missing", "secret", "issuer", "jwt"} {
		r := httptest.NewRequest("POST", GrantPath, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(state.TicketSecret))
		r.Header.Set("X-FamilyChat-Issuer", state.TicketIssuer)
		switch which {
		case "missing":
			r.Header.Del("Authorization")
		case "secret":
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 44))
		case "issuer":
			r.Header.Set("X-FamilyChat-Issuer", "wrong")
		case "jwt":
			r.Header.Set("Authorization", "Bearer "+signedTicket(t, state))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		requireStatus(t, w, 401)
	}
	for _, which := range []string{"version", "user", "device", "grant", "upper", "key", "public", "base64", "compressed"} {
		bad := f.request
		switch which {
		case "version":
			bad.Version = 2
		case "user":
			bad.UserID = "not-uuid"
		case "device":
			bad.DeviceID = ""
		case "grant":
			bad.GrantID = "123"
		case "upper":
			bad.UserID = strings.ToUpper(testUser)
		case "key":
			bad.KeyID = strings.Repeat("a", 64)
		case "public":
			bad.DevicePublicKey = base64.StdEncoding.EncodeToString(make([]byte, 65))
		case "base64":
			bad.DevicePublicKey += "\n"
		case "compressed":
			bad.DevicePublicKey = base64.StdEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), f.private.X, f.private.Y))
		}
		requireStatus(t, serveJSON(t, h, state, GrantPath, bad, true), 400)
	}
	for _, body := range []string{`{}`, `null`, string(raw) + `{}`, strings.TrimSuffix(string(raw), "}") + `,"extra":1}`, strings.TrimSuffix(string(raw), "}") + `,"version":1}`, strings.Replace(string(raw), `"version"`, `"VERSION"`, 1), strings.TrimSuffix(string(raw), "}") + `,"VERSION":1}`, string(raw[:10]), strings.Repeat(" ", 8193)} {
		r := httptest.NewRequest("POST", GrantPath, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(state.TicketSecret))
		r.Header.Set("X-FamilyChat-Issuer", state.TicketIssuer)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		requireStatus(t, w, 400)
	}
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
}
func signedTicket(t *testing.T, state *State) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	raw, _ := json.Marshal(map[string]any{"iss": state.TicketIssuer, "aud": "familychat-keyserver", "sub": testUser, "key_id": state.KeyID, "iat": time.Now().Unix(), "exp": time.Now().Unix() + 120})
	body := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, state.TicketSecret)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func TestOldJWTAndGetNeverReleasePrivateKey(t *testing.T) {
	state, _, h := testHandler(t)
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, KeyPath, nil)
		r.Header.Set("Authorization", "Bearer "+signedTicket(t, state))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 200 || strings.Contains(w.Body.String(), "private_key") {
			t.Fatal("legacy JWT released private key")
		}
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	res, err := server.Client().Get(server.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(raw), `"key_delivery":"device-grant-v1"`) {
		t.Fatal(string(raw))
	}
}
func TestReadinessContainsNoSecretsAndMethodRestricted(t *testing.T) {
	state, _, h := testHandler(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/health/ready", 200}, {"GET", KeyPath, 405}, {"GET", GrantPath, 405}, {"POST", "/health/ready", 405}, {"GET", "/unknown", 404}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		requireStatus(t, w, tc.status)
		if strings.Contains(w.Body.String(), "private_key") || strings.Contains(w.Body.String(), "ticket_secret") {
			t.Fatal("secret leaked")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("response is cacheable")
		}
	}
	_ = state
}
func TestUnauthorizedRequestsAreRateLimited(t *testing.T) {
	_, _, h := testHandler(t)
	limited := false
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", KeyPath, strings.NewReader(`{}`)))
		if w.Code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unbounded authentication attempts")
	}
}
func TestStoreFailureNeverReleasesPrivateMaterial(t *testing.T) {
	state, store, h := testHandler(t)
	f := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	if err := os.Rename(store.dir, store.dir+"-removed"); err != nil {
		t.Fatal(err)
	}
	w := serveJSON(t, h, state, KeyPath, f.proof(t), false)
	requireStatus(t, w, 503)
	if strings.Contains(w.Body.String(), "private_key") || strings.Contains(w.Body.String(), base64.StdEncoding.EncodeToString(state.PrivateKey)) {
		t.Fatal("persistence failure leaked private key")
	}
}
func TestStoreExclusiveLockCorruptionAndCloseFailClosed(t *testing.T) {
	state, store, h := testHandler(t)
	if other, err := OpenGrantStore(store.dir); err == nil {
		other.Close()
		t.Fatal("two writers opened store")
	}
	f := newGrantFixture(t, state, testDevice)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), 503)
	if err := os.WriteFile(filepath.Join(store.dir, "grants.json"), []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenGrantStore(store.dir); err == nil {
		other.Close()
		t.Fatal("corrupt store accepted")
	}
}
func TestGrantCapacityCleansExpiredWithoutResurrectingGrant(t *testing.T) {
	state, store, h := testHandler(t)
	now := time.Now().Unix()
	store.maxGrants = 2
	first := newGrantFixture(t, state, testDevice)
	first.request.ExpiresAt = now + 120
	requireStatus(t, serveJSON(t, h, state, GrantPath, first.request, true), 204)
	second := newGrantFixture(t, state, otherDevice)
	second.request.ExpiresAt = now + 200
	requireStatus(t, serveJSON(t, h, state, GrantPath, second.request, true), 204)
	third := first
	third.request.GrantID = fmt.Sprintf("%064x", 3)
	third.request.ExpiresAt = now + 200
	requireStatus(t, serveJSON(t, h, state, GrantPath, third.request, true), 503)
	store.now = func() time.Time { return time.Unix(now+121, 0) }
	requireStatus(t, serveJSON(t, h, state, GrantPath, third.request, true), 204)
	requireStatus(t, serveJSON(t, h, state, GrantPath, first.request, true), 400)
}

func TestExpiredDeviceBindingAllowsRenewalAfterRestart(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(fmt.Sprintf("consumed=%v", consumed), func(t *testing.T) {
			state, store, h := testHandler(t)
			now := time.Now().Unix()
			store.now = func() time.Time { return time.Unix(now, 0) }
			first := newGrantFixture(t, state, testDevice)
			first.request.ExpiresAt = now + 120
			requireStatus(t, serveJSON(t, h, state, GrantPath, first.request, true), 204)
			if consumed {
				requireKey(t, serveJSON(t, h, state, KeyPath, first.proof(t), false), state)
			}
			renewal := newGrantFixture(t, state, testDevice)
			renewal.request.ExpiresAt = now + 240
			requireStatus(t, serveJSON(t, h, state, GrantPath, renewal.request, true), 409)
			dir := store.dir
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := OpenGrantStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			restarted.now = func() time.Time { return time.Unix(now+121, 0) }
			nextHandler := NewHandler(state, restarted)
			requireStatus(t, serveJSON(t, nextHandler, state, GrantPath, renewal.request, true), 204)
			requireStatus(t, serveJSON(t, nextHandler, state, KeyPath, first.proof(t), false), 401)
			requireKey(t, serveJSON(t, nextHandler, state, KeyPath, renewal.proof(t), false), state)
			if len(restarted.disk.Devices) != 1 || len(restarted.disk.Grants) != 1 {
				t.Fatalf("expired binding retained: devices=%d grants=%d", len(restarted.disk.Devices), len(restarted.disk.Grants))
			}
		})
	}
}

func TestHistoricalDeviceCountDoesNotPermanentlyBlockEnrollment(t *testing.T) {
	state, store, _ := testHandler(t)
	dir := store.dir
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	f := newGrantFixture(t, state, testDevice)
	legacy := grantDisk{Version: 1, Grants: map[string]grantRecord{}, Devices: map[string]string{}}
	for i := 0; i < 10000; i++ {
		device := fmt.Sprintf("%08x-2222-4222-8222-222222222222", i)
		legacy.Devices[deviceRecordID(testUser, device)] = f.request.DevicePublicKey
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "grants.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenGrantStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	h := NewHandler(state, restarted)
	requireStatus(t, serveJSON(t, h, state, GrantPath, f.request, true), 204)
	if len(restarted.disk.Devices) != 1 {
		t.Fatalf("historical bindings not reclaimed: %d", len(restarted.disk.Devices))
	}
	requireKey(t, serveJSON(t, h, state, KeyPath, f.proof(t), false), state)
}
