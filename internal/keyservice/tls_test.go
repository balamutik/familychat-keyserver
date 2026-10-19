package keyservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateReloadUsesNewCertificateAndKeepsLastGoodDuringReplacement(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair := func(serial int64) {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "keys.example"}, DNSNames: []string{"keys.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
		_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600)
	}
	writePair(1)
	config, err := TLSConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("initial certificate not loaded")
	}
	writePair(2)
	next, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || next.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("renewed certificate not loaded", err)
	}
	_ = os.WriteFile(key, []byte("replacement in progress"), 0600)
	last, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || last.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("partial renewal broke existing TLS", err)
	}
}
