package keyservice

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializePreservesKeyAndTicketAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first, err := Initialize(dir, Import{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := Initialize(dir, Import{})
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID != again.KeyID || !bytes.Equal(first.PrivateKey, again.PrivateKey) ||
		!bytes.Equal(first.TicketSecret, again.TicketSecret) || first.TicketIssuer != again.TicketIssuer {
		t.Fatal("init replaced an established key or ticket credentials")
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{dir, 0700}, {filepath.Join(dir, "state.json"), 0600},
	} {
		info, err := os.Stat(entry.path)
		if err != nil || info.Mode().Perm() != entry.mode {
			t.Fatalf("unsafe permissions: %v %v", info, err)
		}
	}
	public, err := ecdh.X25519().NewPrivateKey(first.PrivateKey)
	if err != nil || !bytes.Equal(public.PublicKey().Bytes(), first.PublicKey) {
		t.Fatal("invalid keypair")
	}
}

func TestImportOldSecretPairAndExportNeverIncludesContentPrivateKey(t *testing.T) {
	root := t.TempDir()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath, privatePath := filepath.Join(root, "public.txt"), filepath.Join(root, "private.txt")
	for path, raw := range map[string][]byte{publicPath: key.PublicKey().Bytes(), privatePath: key.Bytes()} {
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	state, err := Initialize(filepath.Join(root, "state"), Import{PublicFile: publicPath, PrivateFile: privatePath})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(state.PrivateKey, key.Bytes()) {
		t.Fatal("import lost history key")
	}
	config, err := state.Integration("https://keys.example.com:8443/api/v1/keys/current")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(config)
	if bytes.Contains(raw, []byte("private_key")) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(key.Bytes()))) {
		t.Fatal("integration configuration leaked the content private key")
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != 6 || fields["scheme"] != "fc1" || fields["key_server_url"] != "https://keys.example.com:8443/api/v1/keys/current" {
		t.Fatalf("wrong integration contract: %s", raw)
	}
}

func TestImportJSONRejectsConflictingKeyWithoutChangingState(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	first, err := Initialize(dir, Import{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Initialize(filepath.Join(root, "other"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	old := map[string]any{"key_id": other.KeyID, "public_key": other.PublicKey, "private_key": other.PrivateKey}
	raw, _ := json.Marshal(old)
	file := filepath.Join(root, "old.json")
	_ = os.WriteFile(file, raw, 0600)
	if _, err = Initialize(dir, Import{JSONFile: file}); err == nil {
		t.Fatal("conflicting import accepted")
	}
	after, err := Load(dir)
	if err != nil || after.KeyID != first.KeyID {
		t.Fatal("conflict modified existing state")
	}
	imported, err := Initialize(filepath.Join(root, "imported"), Import{JSONFile: file})
	if err != nil || imported.KeyID != other.KeyID {
		t.Fatal("legacy JSON import failed:", err)
	}
}

func TestMissingStateInNonemptyDirectoryDoesNotGenerateReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "backup.marker"), []byte("existing installation"), 0600)
	if _, err := Initialize(dir, Import{}); err == nil {
		t.Fatal("silently regenerated a potentially lost key")
	}
}

func TestImportRejectsMismatchedAndUnsafeSecrets(t *testing.T) {
	root := t.TempDir()
	first, _ := ecdh.X25519().GenerateKey(rand.Reader)
	second, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub, priv := filepath.Join(root, "pub"), filepath.Join(root, "priv")
	_ = os.WriteFile(pub, []byte(base64.StdEncoding.EncodeToString(first.PublicKey().Bytes())), 0600)
	_ = os.WriteFile(priv, []byte(base64.StdEncoding.EncodeToString(second.Bytes())), 0600)
	if _, err := Initialize(filepath.Join(root, "mismatch"), Import{PublicFile: pub, PrivateFile: priv}); err == nil {
		t.Fatal("mismatched pair accepted")
	}
	_ = os.WriteFile(priv, []byte(base64.StdEncoding.EncodeToString(first.Bytes())), 0600)
	_ = os.Chmod(priv, 0644)
	if _, err := Initialize(filepath.Join(root, "unsafe"), Import{PublicFile: pub, PrivateFile: priv}); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}

func TestIntegrationRequiresHTTPSAndDedicatedPort(t *testing.T) {
	state, err := Initialize(filepath.Join(t.TempDir(), "state"), Import{})
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"http://keys.example:8443/api/v1/keys/current", "https://keys.example/api/v1/keys/current", "https://keys.example:443/api/v1/keys/current", "https://keys.example:8080/api/v1/keys/current", "https://user:pass@keys.example:8443/api/v1/keys/current", "https://keys.example:8443/other"} {
		if _, err := state.Integration(url); err == nil {
			t.Errorf("unsafe endpoint accepted: %s", url)
		}
	}
}
