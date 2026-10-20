package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/swayam5342/dnsr/internal/dnstest"
	"github.com/swayam5342/dnsr/internal/resolver"
	"github.com/swayam5342/dnsr/internal/wire"
)

func testResolver(t *testing.T) *resolver.Resolver {
	n := dnstest.Start(t)
	r := resolver.New()
	r.Port = n.Port
	r.Timeout = 500 * time.Millisecond
	r.Roots = []resolver.Nameserver{{Name: "fake-root.", IP: dnstest.RootIP}}
	r.Anchors = []wire.DS{n.Root.Anchor()}
	return r
}

func plainQuery(id uint16, name string, qtype wire.RRType) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b, _ = wire.EncodeName(b, name)
	b = binary.BigEndian.AppendUint16(b, uint16(qtype))
	return binary.BigEndian.AppendUint16(b, 1)
}

func startTestServer(t *testing.T, s *Server) net.Addr {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	go s.ServeUDP(pc)
	return pc.LocalAddr()
}

func udpAsk(t *testing.T, addr net.Addr, q []byte) *wire.Message {
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(q)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wire.ParseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestServerSetsADForSecureAnswers(t *testing.T) {
	r := testResolver(t)
	r.DNSSEC = true
	addr := startTestServer(t, New(r))
	m := udpAsk(t, addr, plainQuery(7, "www.example.com.", wire.TypeA))
	if !m.Header.AD || len(m.Answers) != 1 || m.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("AD=%v answers=%v", m.Header.AD, m.Answers)
	}
	m = udpAsk(t, addr, plainQuery(8, "tampered.example.com.", wire.TypeA))
	if m.Header.Rcode != wire.RcodeServFail {
		t.Fatalf("bogus answer should be SERVFAIL, got %s", wire.RcodeString(m.Header.Rcode))
	}
}

func TestServerTruncatesLargeUDPResponses(t *testing.T) {
	addr := startTestServer(t, New(testResolver(t)))
	m := udpAsk(t, addr, plainQuery(9, "many.example.com.", wire.TypeA))
	if !m.Header.TC || len(m.Answers) != 0 {
		t.Fatalf("expected TC=1 with no answers for a >512-byte response, got TC=%v and %d answers", m.Header.TC, len(m.Answers))
	}
}

func TestServerRateLimit(t *testing.T) {
	s := New(resolver.New())
	s.init()
	s.Rate, s.Burst = 1, 5
	allowed := 0
	for range 20 {
		if s.allow("192.0.2.1") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed %d of 20 back-to-back queries, want burst of 5", allowed)
	}
	if !s.allow("192.0.2.2") {
		t.Fatal("another client should not be limited")
	}
}

func TestDNSOverTLS(t *testing.T) {
	r := testResolver(t)
	cert, _, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", dotConfig(cert))
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	go New(r).ServeStream(ln)

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	q, _ := wire.BuildQuery(42, "www.example.com.", wire.TypeA, false)
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	io.ReadFull(c, buf)
	m, err := wire.ParseMessage(buf)
	if err != nil || m.Header.ID != 42 || len(m.Answers) != 1 || m.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestServerStripsDNSSECRecordsForPlainClients(t *testing.T) {
	addr := startTestServer(t, New(testResolver(t)))
	m := udpAsk(t, addr, plainQuery(10, "nope.example.com.", wire.TypeA))
	if m.Header.Rcode != wire.RcodeNXDomain || m.Header.TC {
		t.Fatalf("rcode %s TC=%v", wire.RcodeString(m.Header.Rcode), m.Header.TC)
	}
	for _, rr := range m.Authority {
		if rr.Type == wire.TypeRRSIG {
			t.Fatalf("plain client received %s", rr.Type)
		}
	}
	q, _ := wire.BuildQuery(11, "nope.example.com.", wire.TypeA, true)
	m = udpAsk(t, addr, q)
	sigs := 0
	for _, rr := range m.Authority {
		if rr.Type == wire.TypeRRSIG {
			sigs++
		}
	}
	if sigs == 0 {
		t.Fatal("client with DO=1 should receive the RRSIG")
	}
}

func TestDNSOverTLSRequiresTLS13(t *testing.T) {
	cert, _, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", dotConfig(cert))
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	if c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}); err == nil {
		c.Close()
		t.Fatal("a TLS 1.2 client was accepted")
	}
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v := c.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version %x, want 1.3", v)
	}
}

func TestServerAccessList(t *testing.T) {
	r := testResolver(t)
	s := New(r)
	acl, err := ParseAllow("10.0.0.0/8, 192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	s.Allow = acl
	addr := startTestServer(t, s)
	m := udpAsk(t, addr, plainQuery(12, "www.example.com.", wire.TypeA))
	if m.Header.Rcode != wire.RcodeRefused || len(m.Answers) != 0 {
		t.Fatalf("client outside the list got %s with %d answers", wire.RcodeString(m.Header.Rcode), len(m.Answers))
	}
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.168.1.5": true, "192.168.1.6": false,
		"127.0.0.1": false, "::ffff:10.0.0.1": true, "garbage": false} {
		if got := s.permitted(ip); got != want {
			t.Errorf("custom list: permitted(%s) = %v, want %v", ip, got, want)
		}
	}
	def := New(r)
	for ip, want := range map[string]bool{"127.0.0.1": true, "127.5.5.5": true, "::1": true, "192.168.1.1": false} {
		if got := def.permitted(ip); got != want {
			t.Errorf("default list: permitted(%s) = %v, want %v", ip, got, want)
		}
	}
	for _, bad := range []string{"10.0.0.0/33", "not-an-ip"} {
		if _, err := ParseAllow(bad); err == nil {
			t.Errorf("ParseAllow(%q) should fail", bad)
		}
	}
}
