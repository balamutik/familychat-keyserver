package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"familychat/keyserver/internal/keyservice"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitAndExportCLIKeepPrivateKeyOutOfMainConfiguration(t *testing.T) {
	root := t.TempDir()
	state, out := filepath.Join(root, "state"), filepath.Join(root, "integration.json")
	var output bytes.Buffer
	args := []string{"init", "--state-dir", state, "--url", "https://keys.example:8443/api/v1/keys/current", "--export", out}
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("ticket_secret")) || bytes.Contains(first, []byte("private_key")) {
		t.Fatal("secret leaked")
	}
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(out)
	if !bytes.Equal(first, again) {
		t.Fatal("init changed existing integration")
	}
	if err := run([]string{"export", "--state-dir", state, "--url", "https://new.example:9443/api/v1/keys/current", "--out", out}, &output); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	raw, _ := os.ReadFile(out)
	_ = json.Unmarshal(raw, &fields)
	if fields["key_server_url"] != "https://new.example:9443/api/v1/keys/current" {
		t.Fatal("export did not update endpoint")
	}
}

func TestServeRejectsMainApplicationPortsBeforeListening(t *testing.T) {
	for _, port := range []string{":443", ":8080", ":80", ":0"} {
		if err := run([]string{"serve", "--listen", port}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %s", port)
		}
	}
}

func TestServeRequiresPersistentGrantStoreAndReleasesLockOnListenFailure(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := keyservice.Initialize(stateDir, keyservice.Import{}); err != nil {
		t.Fatal(err)
	}
	cert, key := writeTLSFixture(t, root)
	grantDir := filepath.Join(root, "grants")
	store, err := keyservice.OpenGrantStore(grantDir)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"serve", "--state-dir", stateDir, "--grants-dir", grantDir, "--listen", "127.0.0.1:18443", "--tls-cert", cert, "--tls-key", key}
	if err := run(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "persistent grants") {
		t.Fatalf("missing store lock check: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	args[6] = listener.Addr().String()
	if err := run(args, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted already occupied listener")
	}
	reopened, err := keyservice.OpenGrantStore(grantDir)
	if err != nil {
		t.Fatalf("serve retained grant lock after failed listen: %v", err)
	}
	defer reopened.Close()
}

func writeTLSFixture(t *testing.T, dir string) (string, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keys.example"}, DNSNames: []string{"keys.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}
