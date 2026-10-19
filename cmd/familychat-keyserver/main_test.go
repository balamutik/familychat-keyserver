package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
