package keyservice

import (
	"crypto/tls"
	"sync"
)

// TLSConfig reloads renewed certificates for new handshakes. A temporarily
// incomplete replacement keeps the last valid certificate until both files
// become readable and match; it never falls back to plaintext HTTP.
func TLSConfig(certPath, keyPath string) (*tls.Config, error) {
	initial, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	current := &initial
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if refreshed, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			current = &refreshed
		}
		return current, nil
	}}, nil
}
