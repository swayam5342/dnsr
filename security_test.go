package main

// security_test.go — tests for the hardening features, QNAME minimisation,
// DNSSEC validation and the server, all against the fake hierarchy.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTTLIsCapped(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("huge.example.com", TypeA)
	if err != nil || len(res.Answers) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Answers[0].TTL > defaultMaxTTL {
		t.Fatalf("TTL %d not capped at %d", res.Answers[0].TTL, defaultMaxTTL)
	}
	r.mu.Lock()
	e := r.cache["huge.example.com.|A"]
	r.mu.Unlock()
	if time.Until(e.expires) > defaultMaxTTL*time.Second {
		t.Fatalf("cache entry expires in %v", time.Until(e.expires))
	}
}

func TestCachesAreBounded(t *testing.T) {
	r := NewResolver()
	r.MaxCacheEntries = 5
	for i := range 50 {
		name := "n" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example."
		r.cachePut(name, TypeA, []RR{a(name, "10.0.0.1")}, nil)
		r.putZone(name, []nameserver{{"ns.", "10.0.0.1"}}, 300)
	}
	if len(r.cache) > 5 || len(r.zoneNS) > 5 {
		t.Fatalf("cache %d entries, zoneNS %d entries; limit 5", len(r.cache), len(r.zoneNS))
	}
}

func TestExpiredDelegationIsIgnored(t *testing.T) {
	r := NewResolver()
	r.zoneNS["example.com."] = zoneEntry{[]nameserver{{"ns1.example.com.", "10.0.0.1"}}, time.Now().Add(-time.Second)}
	if zone, _ := r.closestKnownZone("www.example.com."); zone != "." {
		t.Fatalf("used expired delegation %s", zone)
	}
}

func TestGluelessLookupsAreLimited(t *testing.T) {
	n := newTestNet(t)
	_, err := n.r.Resolve("www.fanout.com", TypeA)
	if err == nil || !strings.Contains(err.Error(), "could not find an address") {
		t.Fatalf("expected failure, got %v", err)
	}
	asked := map[string]bool{}
	for _, q := range n.zones["org."].questions() {
		if strings.HasSuffix(q.Name, ".nowhere.org.") && strings.HasPrefix(q.Name, "ns") {
			asked[q.Name] = true
		}
	}
	if len(asked) == 0 || len(asked) > maxGluelessLookups {
		t.Fatalf("looked up %d of 8 nameservers, want 1..%d: %v", len(asked), maxGluelessLookups, asked)
	}
}

func TestForgedReplyIsIgnored(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("forged.example.com", TypeA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10.1.1.1" {
		t.Fatalf("accepted a forged reply: %+v %v\n%s", res, err, trace)
	}
}

func TestTCPReplyMustMatchQuestion(t *testing.T) {
	r, trace := newTestResolver(t)
	_, err := r.Resolve("badtcp.example.com", TypeA)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected TCP mismatch error, got %v\n%s", err, trace)
	}
}

func TestQNAMEMinimisation(t *testing.T) {
	n := newTestNet(t)
	if _, err := n.r.Resolve("www.example.com", TypeA); err != nil {
		t.Fatal(err)
	}
	for zone, want := range map[string]string{".": "com.", "com.": "example.com."} {
		for _, q := range n.zones[zone].questions() {
			if q.Name != want || q.Type != TypeNS {
				t.Errorf("%s server saw %s %s, want only %s NS", zone, q.Name, q.Type, want)
			}
		}
	}
}

func TestQNAMEMinimisationCanBeDisabled(t *testing.T) {
	n := newTestNet(t)
	n.r.Minimise = false
	n.r.Resolve("www.example.com", TypeA)
	if qs := n.zones["."].questions(); len(qs) == 0 || qs[0].Name != "www.example.com." {
		t.Errorf("with minimisation off the root should see the full name, saw %v", qs)
	}
}

func TestDNSSECSecure(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	for _, name := range []string{"www.example.com", "alias.example.com"} {
		res, err := n.r.Resolve(name, TypeA)
		if err != nil || res.Security != SecSecure {
			t.Fatalf("%s: security %v (%s) err %v\n%s", name, res.Security, res.SecurityNote, err, n.trace)
		}
	}
	res, _ := n.r.Resolve("example.com", TypeMX)
	if res.Security != SecSecure {
		t.Fatalf("MX: %v %s", res.Security, res.SecurityNote)
	}
}

func TestDNSSECBogusWhenRecordIsTampered(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	res, err := n.r.Resolve("tampered.example.com", TypeA)
	if err != nil || res.Security != SecBogus {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func TestDNSSECBogusWithWrongTrustAnchor(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	n.r.Anchors = []DSRecord{newSigner(".").anchor()}
	res, err := n.r.Resolve("www.example.com", TypeA)
	if err != nil || res.Security != SecBogus {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func TestDNSSECInsecureDelegation(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	res, err := n.r.Resolve("glueless.com", TypeA)
	if err != nil || res.Security != SecInsecure {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func TestRRSIGParsesAndPrints(t *testing.T) {
	s := newSigner("example.com.")
	sig := s.sign([]RR{a("www.example.com.", "10.0.0.1")})
	p, err := parseRRSIG(sig.Raw)
	if err != nil || p.Signer != "example.com." || p.TypeCovered != TypeA || p.KeyTag != s.tag {
		t.Fatalf("%+v %v", p, err)
	}
}

func plainQuery(id uint16, name string, qtype RRType) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b, _ = encodeName(b, name)
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

func udpAsk(t *testing.T, addr net.Addr, q []byte) *Message {
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
	m, err := ParseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestServerSetsADForSecureAnswers(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	addr := startTestServer(t, NewServer(n.r))
	m := udpAsk(t, addr, plainQuery(7, "www.example.com.", TypeA))
	if !m.Header.AD || len(m.Answers) != 1 || m.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("AD=%v answers=%v", m.Header.AD, m.Answers)
	}
	m = udpAsk(t, addr, plainQuery(8, "tampered.example.com.", TypeA))
	if m.Header.Rcode != RcodeServFail {
		t.Fatalf("bogus answer should be SERVFAIL, got %s", rcodeString(m.Header.Rcode))
	}
}

func TestServerTruncatesLargeUDPResponses(t *testing.T) {
	n := newTestNet(t)
	addr := startTestServer(t, NewServer(n.r))
	m := udpAsk(t, addr, plainQuery(9, "many.example.com.", TypeA))
	if !m.Header.TC || len(m.Answers) != 0 {
		t.Fatalf("expected TC=1 with no answers for a >512-byte response, got TC=%v and %d answers", m.Header.TC, len(m.Answers))
	}
}

func TestServerRateLimit(t *testing.T) {
	s := NewServer(NewResolver())
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
	n := newTestNet(t)
	cert, _, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	go NewServer(n.r).ServeStream(ln)

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	q, _ := BuildQuery(42, "www.example.com.", TypeA, false)
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	io.ReadFull(c, buf)
	m, err := ParseMessage(buf)
	if err != nil || m.Header.ID != 42 || len(m.Answers) != 1 || m.Answers[0].Data != "93.184.216.34" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestServerStripsDNSSECRecordsForPlainClients(t *testing.T) {
	n := newTestNet(t)
	addr := startTestServer(t, NewServer(n.r))
	m := udpAsk(t, addr, plainQuery(10, "nope.example.com.", TypeA))
	if m.Header.Rcode != RcodeNXDomain || m.Header.TC {
		t.Fatalf("rcode %s TC=%v", rcodeString(m.Header.Rcode), m.Header.TC)
	}
	for _, rr := range m.Authority {
		if rr.Type == TypeRRSIG {
			t.Fatalf("plain client received %s", rr.Type)
		}
	}
	q, _ := BuildQuery(11, "nope.example.com.", TypeA, true)
	m = udpAsk(t, addr, q)
	sigs := 0
	for _, rr := range m.Authority {
		if rr.Type == TypeRRSIG {
			sigs++
		}
	}
	if sigs == 0 {
		t.Fatal("client with DO=1 should receive the RRSIG")
	}
}
