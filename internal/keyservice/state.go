// Package keyservice stores one family's existing fc1 key and distributes it
// directly to clients authorized by short-lived main-server tickets.
package keyservice

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const Scheme = "fc1"
const KeyPath = "/api/v1/keys/current"

type State struct {
	Version      int    `json:"version"`
	Scheme       string `json:"scheme"`
	KeyID        string `json:"key_id"`
	PublicKey    []byte `json:"public_key"`
	PrivateKey   []byte `json:"private_key"`
	TicketIssuer string `json:"ticket_issuer"`
	TicketSecret []byte `json:"ticket_secret"`
}

// Integration contains an authentication secret, but no content private key.
type Integration struct {
	Scheme       string `json:"scheme"`
	KeyID        string `json:"key_id"`
	PublicKey    []byte `json:"public_key"`
	KeyServerURL string `json:"key_server_url"`
	TicketIssuer string `json:"ticket_issuer"`
	TicketSecret []byte `json:"ticket_secret"`
}

type Import struct {
	JSONFile    string
	PublicFile  string
	PrivateFile string
}

func (i Import) present() bool { return i.JSONFile != "" || i.PublicFile != "" || i.PrivateFile != "" }

func keyFromPrivate(raw []byte) (*State, error) {
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, errors.New("content private key must be 32-byte X25519")
	}
	public := private.PublicKey().Bytes()
	id := sha256.Sum256(public)
	return &State{Version: 1, Scheme: Scheme, KeyID: hex.EncodeToString(id[:]), PublicKey: public, PrivateKey: private.Bytes()}, nil
}

func (s *State) validate() error {
	key, err := keyFromPrivate(s.PrivateKey)
	if err != nil || s.Version != 1 || s.Scheme != Scheme || s.KeyID != key.KeyID || !bytes.Equal(s.PublicKey, key.PublicKey) {
		return errors.New("invalid or inconsistent key-server state; restore its original backup")
	}
	if len(s.TicketSecret) != 32 || len(s.TicketIssuer) < 16 || len(s.TicketIssuer) > 128 {
		return errors.New("invalid ticket credentials; restore key-server state")
	}
	return nil
}

func restrictedRead(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, fmt.Errorf("%s must be a restricted regular file (0400 or 0600)", filepath.Base(path))
	}
	return os.ReadFile(path)
}

func checkDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be a real directory with permissions 0700")
	}
	return nil
}

func Load(dir string) (*State, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	raw, err := restrictedRead(filepath.Join(dir, "state.json"), 16384)
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, errors.New("invalid state JSON")
	}
	if err := state.validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func readImport(imp Import) (*State, error) {
	if imp.JSONFile != "" {
		if imp.PublicFile != "" || imp.PrivateFile != "" {
			return nil, errors.New("choose JSON import or the public/private secret pair")
		}
		raw, err := restrictedRead(imp.JSONFile, 16384)
		if err != nil {
			return nil, err
		}
		var old struct {
			Scheme  string `json:"scheme"`
			ID      string `json:"key_id"`
			Public  []byte `json:"public_key"`
			Private []byte `json:"private_key"`
		}
		if err := json.Unmarshal(raw, &old); err != nil {
			return nil, errors.New("invalid imported key JSON")
		}
		state, err := keyFromPrivate(old.Private)
		if err != nil {
			return nil, err
		}
		if (old.Scheme != "" && old.Scheme != Scheme) || old.ID != state.KeyID || !bytes.Equal(old.Public, state.PublicKey) {
			return nil, errors.New("imported JSON contains inconsistent key material")
		}
		return state, nil
	}
	if imp.PublicFile == "" || imp.PrivateFile == "" {
		return nil, errors.New("both --import-public and --import-private are required")
	}
	read := func(path string) ([]byte, error) {
		raw, err := restrictedRead(path, 128)
		if err != nil {
			return nil, err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) != 32 {
			return nil, errors.New("imported secret must contain a base64 32-byte key")
		}
		return decoded, nil
	}
	private, err := read(imp.PrivateFile)
	if err != nil {
		return nil, err
	}
	public, err := read(imp.PublicFile)
	if err != nil {
		return nil, err
	}
	state, err := keyFromPrivate(private)
	if err != nil || !bytes.Equal(public, state.PublicKey) {
		return nil, errors.New("imported public/private secrets do not match")
	}
	return state, nil
}

// Initialize is idempotent and never rotates an established key. Imported keys
// preserve the historical fingerprint already recorded in the main database.
func Initialize(dir string, imp Import) (*State, error) {
	var imported *State
	var err error
	if imp.present() {
		imported, err = readImport(imp)
		if err != nil {
			return nil, err
		}
	}
	if existing, err := Load(dir); err == nil {
		if imported != nil && existing.KeyID != imported.KeyID {
			return nil, errors.New("import conflicts with established key; existing state was not changed")
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		return nil, errors.New("state.json is missing from a nonempty state directory; restore the backup instead of generating a replacement")
	}
	state := imported
	if state == nil {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		state, err = keyFromPrivate(private.Bytes())
		if err != nil {
			return nil, err
		}
	}
	state.TicketSecret = make([]byte, 32)
	if _, err := rand.Read(state.TicketSecret); err != nil {
		return nil, err
	}
	issuer := make([]byte, 16)
	if _, err := rand.Read(issuer); err != nil {
		return nil, err
	}
	state.TicketIssuer = "familychat-" + hex.EncodeToString(issuer)
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, "state.json"), append(raw, '\n'), false); err != nil {
		return nil, err
	}
	return Load(dir)
}

func (s *State) Integration(endpoint string) (*Integration, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != KeyPath {
		return nil, errors.New("key-server URL must be https://hostname:8443/api/v1/keys/current without credentials, query or fragment")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1024 || port > 65535 || port == 8080 {
		return nil, errors.New("use a dedicated explicit HTTPS port between 1024 and 65535, except 8080 (default 8443)")
	}
	return &Integration{Scheme: s.Scheme, KeyID: s.KeyID, PublicKey: s.PublicKey, KeyServerURL: endpoint, TicketIssuer: s.TicketIssuer, TicketSecret: s.TicketSecret}, nil
}

func Export(s *State, endpoint, path string) error {
	config, err := s.Integration(endpoint)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'), true)
}

func writeAtomic(path string, raw []byte, replace bool) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to overwrite a nonregular file")
		}
		if !replace {
			return errors.New("state already exists; refusing to overwrite it")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".keyserver-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if replace {
		err = os.Rename(temp.Name(), path)
	} else {
		err = os.Link(temp.Name(), path)
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
