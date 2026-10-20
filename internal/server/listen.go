package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

// dotConfig is the TLS configuration for DNS over TLS: TLS 1.3 only.
func dotConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}

// selfSignedCert creates an in-memory ECDSA certificate for localhost, for testing DoT.
func selfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "dnsr"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fmt.Sprintf("%X", sum), nil
}

type Config struct {
	Addr       string
	DoTAddr    string
	CertFile   string
	KeyFile    string
	SelfSigned bool
}

// ListenAndServe listens on UDP and TCP at cfg.Addr and, if cfg.DoTAddr is set, on DNS over TLS.
func (s *Server) ListenAndServe(cfg Config) error {
	pc, err := net.ListenPacket("udp", cfg.Addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	log.Printf("dnsr listening on udp+tcp://%s — try: dig @%s -p %s example.com", pc.LocalAddr(), host, port)
	allowed := s.Allow
	if len(allowed) == 0 {
		allowed = loopbackOnly
	}
	log.Printf("accepting clients from %v (change with -allow)", allowed)
	errs := make(chan error, 3)
	go func() { errs <- s.ServeUDP(pc) }()
	go func() { errs <- s.ServeStream(ln) }()

	if cfg.DoTAddr != "" {
		var cert tls.Certificate
		switch {
		case cfg.CertFile != "":
			if cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
				return err
			}
		case cfg.SelfSigned:
			var fp string
			if cert, fp, err = selfSignedCert(); err != nil {
				return err
			}
			log.Printf("self-signed certificate, SHA-256 fingerprint %s", fp)
		default:
			return fmt.Errorf("DoT needs -cert and -key, or -selfsigned")
		}
		tl, err := tls.Listen("tcp", cfg.DoTAddr, dotConfig(cert))
		if err != nil {
			return err
		}
		log.Printf("dnsr listening on DNS over TLS %s", tl.Addr())
		go func() { errs <- s.ServeStream(tl) }()
	}
	return <-errs
}
