package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"familychat/keyserver/internal/keyservice"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: familychat-keyserver init|export|serve|health [options]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(out)
	switch args[0] {
	case "init", "export":
		dir := flags.String("state-dir", "/var/lib/familychat-keyserver", "restricted state directory")
		endpoint := flags.String("url", "", "public HTTPS endpoint including dedicated port and /api/v1/keys/current")
		var path *string
		imp := keyservice.Import{}
		if args[0] == "init" {
			path = flags.String("export", "", "write main-server integration JSON here (no content private key)")
			flags.StringVar(&imp.JSONFile, "import-json", "", "import original fc1 JSON key")
			flags.StringVar(&imp.PublicFile, "import-public", "", "import base64 public secret file")
			flags.StringVar(&imp.PrivateFile, "import-private", "", "import base64 private secret file")
		} else {
			path = flags.String("out", "", "write main-server integration JSON here")
		}
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *endpoint == "" || *path == "" || flags.NArg() != 0 {
			return errors.New("--url and --export/--out are required")
		}
		var state *keyservice.State
		var err error
		if args[0] == "init" {
			state, err = keyservice.Initialize(*dir, imp)
		} else {
			state, err = keyservice.Load(*dir)
		}
		if err != nil {
			return err
		}
		if err := keyservice.Export(state, *endpoint, *path); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Key server configured; restricted integration JSON written. Keep a separate backup of the state directory.")
		return err
	case "serve":
		grantsDir := flags.String("grants-dir", "/grants", "restricted writable persistent grants directory")
		dir := flags.String("state-dir", "/var/lib/familychat-keyserver", "restricted state directory")
		listen := flags.String("listen", ":8443", "dedicated HTTPS listen address")
		cert := flags.String("tls-cert", "", "TLS full-chain PEM file")
		private := flags.String("tls-key", "", "TLS private PEM file")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		_, portRaw, err := net.SplitHostPort(*listen)
		port, portErr := strconv.Atoi(portRaw)
		if err != nil || portErr != nil || port < 1024 || port > 65535 || port == 8080 {
			return errors.New("--listen requires a dedicated port between 1024 and 65535 except 8080 (default :8443)")
		}
		if *cert == "" || *private == "" || flags.NArg() != 0 {
			return errors.New("--tls-cert and --tls-key are required; plaintext HTTP is not supported")
		}
		state, err := keyservice.Load(*dir)
		if err != nil {
			return err
		}
		tlsConfig, err := keyservice.TLSConfig(*cert, *private)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		grants, err := keyservice.OpenGrantStore(*grantsDir)
		if err != nil {
			return fmt.Errorf("open persistent grants: %w", err)
		}
		defer grants.Close()
		server := &http.Server{Addr: *listen, Handler: keyservice.NewHandler(state, grants), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		done := make(chan struct{})
		shutdownDone := make(chan struct{})
		go func() {
			defer close(shutdownDone)
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdown)
			case <-done:
			}
		}()
		_, _ = fmt.Fprintln(out, "FamilyChat key server listening over HTTPS on "+*listen)
		err = server.ListenAndServeTLS("", "")
		close(done)
		<-shutdownDone
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case "health":
		endpoint := flags.String("url", "", "public HTTPS readiness URL")
		connect := flags.String("connect", "", "optional local host:port to connect without public DNS")
		ca := flags.String("ca", "", "optional trusted PEM certificate bundle")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		u, err := url.Parse(*endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return errors.New("--url must be an HTTPS readiness endpoint")
		}
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if *ca != "" {
			pem, err := os.ReadFile(*ca)
			if err != nil {
				return err
			}
			config.RootCAs = x509.NewCertPool()
			if !config.RootCAs.AppendCertsFromPEM(pem) {
				return errors.New("invalid CA PEM file")
			}
		}
		transport := &http.Transport{TLSClientConfig: config}
		defer transport.CloseIdleConnections()
		if *connect != "" {
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, *connect)
			}
		}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Get(*endpoint)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("readiness returned status %d", res.StatusCode)
		}
		return nil
	default:
		return errors.New("unknown command; use init, export, serve or health")
	}
}
