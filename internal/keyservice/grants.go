package keyservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const GrantPath = "/api/v1/device-grants"
const maxStoredGrants = 10000

var (
	errInvalidGrant     = errors.New("invalid device grant")
	errGrantConflict    = errors.New("conflicting device grant or device key")
	errGrantConsumed    = errors.New("device grant already consumed")
	errStoreUnavailable = errors.New("grant store unavailable")
)

// DeviceGrant is an authenticated main-server authorization for one device.
// TicketSecret authenticates only this RPC; it never authorizes key delivery.
type DeviceGrant struct {
	Version         int    `json:"version"`
	GrantID         string `json:"grant_id"`
	UserID          string `json:"user_id"`
	DeviceID        string `json:"device_id"`
	DevicePublicKey string `json:"device_public_key"`
	KeyID           string `json:"key_id"`
	ExpiresAt       int64  `json:"expires_at"`
}

// DeviceProof proves possession of the private device signing key.
type DeviceProof struct {
	Version   int    `json:"version"`
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	GrantID   string `json:"grant_id"`
	Signature string `json:"signature"`
}

type grantRecord struct {
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"device_public_key"`
	KeyID     string `json:"key_id"`
	ExpiresAt int64  `json:"expires_at"`
	Consumed  bool   `json:"consumed"`
}

type grantDisk struct {
	Version int                    `json:"version"`
	Grants  map[string]grantRecord `json:"grants"`
	Devices map[string]string      `json:"devices"`
}

// GrantStore owns an exclusive process lock. Every mutation is durably written
// before becoming visible; a write failure makes the store fail closed.
type GrantStore struct {
	mu          sync.Mutex
	dir         string
	lock        *os.File
	disk        grantDisk
	unavailable bool
	now         func() time.Time
	maxGrants   int
}

// OpenGrantStore opens the required persistent store; there is no volatile mode.
func OpenGrantStore(dir string) (*GrantStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "grants.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	fresh := err == nil
	if errors.Is(err, os.ErrExist) {
		lock, err = os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	}
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	info, err := lock.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("grant lock must be a restricted regular file")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.New("grant store already locked or locking unavailable")
	}
	store := &GrantStore{dir: dir, lock: lock, now: time.Now, maxGrants: maxStoredGrants}
	raw, err := restrictedRead(filepath.Join(dir, "grants.json"), 16*1024*1024)
	if errors.Is(err, os.ErrNotExist) && fresh {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.Name() != "grants.lock" {
				return nil, errors.New("grant data missing from nonempty directory")
			}
		}
		store.disk = grantDisk{Version: 1, Grants: make(map[string]grantRecord), Devices: make(map[string]string)}
		if err = store.persist(store.disk); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read persistent grant store: %w", err)
	} else {
		if err := strictJSON(raw, &store.disk); err != nil {
			return nil, errors.New("invalid persistent grant JSON")
		}
		if err := store.disk.validate(); err != nil {
			return nil, err
		}
	}
	success = true
	return store, nil
}

func (s *GrantStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unavailable = true
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func canonicalHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func canonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return value != "00000000-0000-0000-0000-000000000000"
}
func decodeStandardBase64(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errInvalidGrant
	}
	return raw, nil
}
func signingPublicKey(value string) (*ecdsa.PublicKey, error) {
	raw, err := decodeStandardBase64(value)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, errInvalidGrant
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return nil, errInvalidGrant
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}
func grantHash(id string) string                { sum := sha256.Sum256([]byte(id)); return hex.EncodeToString(sum[:]) }
func deviceRecordID(user, device string) string { return user + "/" + device }
func recordOf(g DeviceGrant) grantRecord {
	return grantRecord{UserID: g.UserID, DeviceID: g.DeviceID, PublicKey: g.DevicePublicKey, KeyID: g.KeyID, ExpiresAt: g.ExpiresAt}
}
func (d grantDisk) validate() error {
	if d.Version != 1 || d.Grants == nil || d.Devices == nil || len(d.Grants) > maxStoredGrants {
		return errors.New("invalid persistent grant store")
	}
	for id, pub := range d.Devices {
		parts := strings.Split(id, "/")
		if len(parts) != 2 || !canonicalUUID(parts[0]) || !canonicalUUID(parts[1]) {
			return errors.New("invalid stored device")
		}
		if _, err := signingPublicKey(pub); err != nil {
			return errors.New("invalid stored device key")
		}
	}
	for hash, record := range d.Grants {
		if !canonicalHex(hash, 64) || !canonicalUUID(record.UserID) || !canonicalUUID(record.DeviceID) || !canonicalHex(record.KeyID, 64) || record.ExpiresAt <= 0 || d.Devices[deviceRecordID(record.UserID, record.DeviceID)] != record.PublicKey {
			return errors.New("invalid stored grant")
		}
	}
	return nil
}
func (s *GrantStore) persist(next grantDisk) error {
	raw, err := json.Marshal(next)
	if err == nil {
		err = writeAtomic(filepath.Join(s.dir, "grants.json"), append(raw, '\n'), true)
	}
	if err != nil {
		s.unavailable = true
		return errStoreUnavailable
	}
	return nil
}
func (s *GrantStore) clone() grantDisk {
	next := grantDisk{Version: 1, Grants: make(map[string]grantRecord, len(s.disk.Grants)), Devices: make(map[string]string, len(s.disk.Devices))}
	for k, v := range s.disk.Grants {
		next.Grants[k] = v
	}
	for k, v := range s.disk.Devices {
		next.Devices[k] = v
	}
	return next
}

// Register is idempotent for an identical, live grant and preserves consumed state.
// Expired payloads are rejected before lookup. Device bindings persist only while
// a grant for that device is unexpired, so historical enrollment has no quota.
func (s *GrantStore) Register(g DeviceGrant, keyID string) error {
	if s == nil {
		return errStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unavailable || s.lock == nil {
		return errStoreUnavailable
	}
	now := s.now().Unix()
	if g.Version != 1 || !canonicalUUID(g.UserID) || !canonicalUUID(g.DeviceID) || !canonicalHex(g.GrantID, 64) || g.KeyID != keyID || !canonicalHex(g.KeyID, 64) || g.ExpiresAt <= now || g.ExpiresAt > now+300 {
		return errInvalidGrant
	}
	if _, err := signingPublicKey(g.DevicePublicKey); err != nil {
		return errInvalidGrant
	}
	hash := grantHash(g.GrantID)
	record := recordOf(g)
	if previous, exists := s.disk.Grants[hash]; exists {
		previous.Consumed = false
		if previous != record {
			return errGrantConflict
		}
		return nil
	}
	next := s.clone()
	next.Devices = make(map[string]string)
	for id, record := range next.Grants {
		if record.ExpiresAt <= now {
			delete(next.Grants, id)
			continue
		}
		next.Devices[deviceRecordID(record.UserID, record.DeviceID)] = record.PublicKey
	}
	device := deviceRecordID(g.UserID, g.DeviceID)
	if pub, exists := next.Devices[device]; exists && pub != g.DevicePublicKey {
		return errGrantConflict
	}
	if len(next.Grants) >= s.maxGrants {
		return errStoreUnavailable
	}
	next.Devices[device] = g.DevicePublicKey
	next.Grants[hash] = record
	if err := s.persist(next); err != nil {
		return err
	}
	s.disk = next
	return nil
}

// Consume verifies proof and binding before atomically persisting consumption.
// A successful return is the only authorization to reveal content private keys.
func (s *GrantStore) Consume(p DeviceProof, keyID string) error {
	if s == nil {
		return errStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unavailable || s.lock == nil {
		return errStoreUnavailable
	}
	if p.Version != 1 || !canonicalUUID(p.UserID) || !canonicalUUID(p.DeviceID) || !canonicalHex(p.GrantID, 64) {
		return errInvalidGrant
	}
	hash := grantHash(p.GrantID)
	record, exists := s.disk.Grants[hash]
	if !exists || record.UserID != p.UserID || record.DeviceID != p.DeviceID || record.KeyID != keyID || record.ExpiresAt <= s.now().Unix() {
		return errInvalidGrant
	}
	pub, err := signingPublicKey(record.PublicKey)
	if err != nil {
		return errStoreUnavailable
	}
	signature, err := decodeStandardBase64(p.Signature)
	if err != nil {
		return errInvalidGrant
	}
	message := "familychat-device-grant-v1\n" + keyID + "\n" + p.UserID + "\n" + p.DeviceID + "\n" + p.GrantID
	digest := sha256.Sum256([]byte(message))
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return errInvalidGrant
	}
	if record.Consumed {
		return errGrantConsumed
	}
	next := s.clone()
	record.Consumed = true
	next.Grants[hash] = record
	if err := s.persist(next); err != nil {
		return err
	}
	s.disk = next
	return nil
}
