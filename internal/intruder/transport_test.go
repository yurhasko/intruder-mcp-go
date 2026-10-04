package intruder

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These need a real TLS stack and connection pool, which handlerTransport
// skips. net/http runs on both ends of an in-memory pipe, so nothing binds.

type pipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func (p *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-p.connections:
		return conn, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeListener) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (*pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "memory", Net: "pipe"} }

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"intruder.test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func pipeClient(t *testing.T, handler http.HandlerFunc, timeout time.Duration, maxTLS uint16) (*Client, *atomic.Int32) {
	t.Helper()

	listener := &pipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	certificate, roots := selfSignedCert(t)

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxTLS,
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(tlsListener) }()

	var dials atomic.Int32
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			client, server := net.Pipe()
			select {
			case listener.connections <- server:
				return client, nil
			case <-ctx.Done():
				_ = client.Close()
				_ = server.Close()
				return nil, ctx.Err()
			case <-listener.closed:
				_ = client.Close()
				_ = server.Close()
				return nil, net.ErrClosed
			}
		},
	}

	client, err := New("fixture-key", Options{
		BaseURL:        "https://intruder.test/v1",
		HTTPClient:     &http.Client{Transport: transport},
		RequestTimeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		client.Close()
		_ = server.Close()
		if err := <-stopped; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("HTTP server stopped: %v", err)
		}
	})
	return client, &dials
}

func TestHTTPConnectionReuse(t *testing.T) {
	client, dials := pipeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-key" || r.URL.Path != "/v1/health/" {
			t.Errorf("request = %s %s", r.Method, r.URL)
		}
		fmt.Fprint(w, `{"status":"ok","authenticated_as":"user"}`)
	}, time.Second, tls.VersionTLS13)

	for range 2 {
		if _, err := client.Health(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	if dials.Load() != 1 {
		t.Fatalf("connections = %d, want one reused connection", dials.Load())
	}
}

func TestHTTPBodyReadTimeout(t *testing.T) {
	client, _ := pipeClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":`) // Never finishes.
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}, 50*time.Millisecond, tls.VersionTLS13)

	_, err := client.Health(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body read error = %v", err)
	}
}

func TestTLSHostnameVerification(t *testing.T) {
	client, _ := pipeClient(t, func(http.ResponseWriter, *http.Request) {
		t.Error("request reached server with an invalid hostname")
	}, time.Second, tls.VersionTLS12)

	client.base.Host = "wrong.test"

	_, err := client.Health(context.Background())
	var hostnameError x509.HostnameError
	if !errors.As(err, &hostnameError) {
		t.Fatalf("TLS error = %v", err)
	}
}
