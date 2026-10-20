package main

// resolver_test.go — a fake DNS hierarchy on loopback (127.0.0.10–15) so the
// full iterative walk can be tested offline and deterministically:
//
//   .            127.0.0.10  → delegates com., org.
//   com.         127.0.0.11  → delegates example.com. (with glue), glueless.com. (no glue)
//   example.com. 127.0.0.12  → authoritative: www, alias (CNAME), mail (MX), big (TC→TCP)
//   org.         127.0.0.13  → delegates dnshost.org.
//   dnshost.org. 127.0.0.14  → ns.dnshost.org A 127.0.0.15
//   glueless.com 127.0.0.15  → authoritative, its NS lives under .org

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPort = "15353"

type fakeZone struct {
	origin  string
	records []RR
	deleg   map[string][]RR
	glue    []RR
	tcOnUDP map[string]bool
	signer  *testSigner
	tamper  map[string]string
	forge   map[string]bool
	badTCP  map[string]bool
	mu      sync.Mutex
	seen    []Question
}

func a(name, ip string) RR {
	return RR{Name: name, Type: TypeA, Class: 1, TTL: 300, Data: ip, Raw: net.ParseIP(ip).To4()}
}
func ns(zone, host string) RR { return RR{Name: zone, Type: TypeNS, Class: 1, TTL: 3600, Data: host} }

type testSigner struct {
	zone string
	key  *ecdsa.PrivateKey
	rr   RR
	tag  uint16
}

func newSigner(zone string) *testSigner {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := k.PublicKey.Bytes()
	rd := append([]byte{0x01, 0x01, 3, 13}, pub[1:]...)
	return &testSigner{zone, k, RR{Name: zone, Type: TypeDNSKEY, Class: 1, TTL: 3600, Raw: rd}, keyTag(rd)}
}

func (s *testSigner) ds() RR {
	owner, _ := encodeName(nil, s.zone)
	sum := sha256.Sum256(append(owner, s.rr.Raw...))
	rd := append(binary.BigEndian.AppendUint16(nil, s.tag), 13, 2)
	return RR{Name: s.zone, Type: TypeDS, Class: 1, TTL: 3600, Raw: append(rd, sum[:]...)}
}

func (s *testSigner) anchor() DSRecord {
	d, _ := parseDS(s.ds())
	return d
}

func (s *testSigner) sign(set []RR) RR {
	now := uint32(time.Now().Unix())
	sig := &rrsig{TypeCovered: set[0].Type, Algorithm: 13, Labels: uint8(labelCount(set[0].Name)), OrigTTL: set[0].TTL,
		Expiration: now + 3600, Inception: now - 3600, KeyTag: s.tag, Signer: s.zone}
	data, _ := signedData(sig, set)
	h := sha256.Sum256(data)
	der, _ := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	sb := rawECDSASignature(der, 32)
	return RR{Name: set[0].Name, Type: TypeRRSIG, Class: 1, TTL: set[0].TTL, Raw: append(sig.prefix(), sb...)}
}

// rawECDSASignature converts an ASN.1 ECDSA signature to the fixed-size r||s form DNSSEC uses.
func rawECDSASignature(der []byte, size int) []byte {
	var sig struct{ R, S *big.Int }
	asn1.Unmarshal(der, &sig)
	return append(sig.R.FillBytes(make([]byte, size)), sig.S.FillBytes(make([]byte, size))...)
}

// withSigs signs each RRset of an answer, then applies any tampering, so a
// tampered record carries a signature over the original data.
func (z *fakeZone) withSigs(an []RR) []RR {
	if z.signer != nil && len(an) > 0 {
		var order []RRType
		sets := map[RRType][]RR{}
		for _, rr := range an {
			if _, ok := sets[rr.Type]; !ok {
				order = append(order, rr.Type)
			}
			sets[rr.Type] = append(sets[rr.Type], rr)
		}
		for _, t := range order {
			an = append(an, z.signer.sign(sets[t]))
		}
	}
	for i := range an {
		if v, ok := z.tamper[an[i].Name]; ok && an[i].Type == TypeA {
			an[i].Data, an[i].Raw = v, net.ParseIP(v).To4()
		}
	}
	return an
}

func (z *fakeZone) questions() []Question {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]Question(nil), z.seen...)
}

func (z *fakeZone) answer(q Question, udp bool) []byte {
	z.mu.Lock()
	z.seen = append(z.seen, q)
	z.mu.Unlock()
	resp := func(rcode int, aa, tc bool, an, au, ad []RR) []byte {
		b := buildResponse(0, q, false, rcode, an, au, ad)
		if aa {
			b[2] |= 0x04
		}
		if tc {
			b[2] |= 0x02
		}
		return b
	}
	soa := RR{Name: z.origin, Type: TypeSOA, Class: 1, TTL: 60,
		Data: "ns." + z.origin + " admin." + z.origin + " 1 7200 900 1209600 60"}

	if _, cut := z.deleg[q.Name]; cut && q.Type == TypeDS {
		var ds []RR
		for _, rr := range z.records {
			if rr.Name == q.Name && rr.Type == TypeDS {
				ds = append(ds, rr)
			}
		}
		if len(ds) == 0 {
			return resp(0, true, false, nil, []RR{soa}, nil)
		}
		return resp(0, true, false, z.withSigs(ds), nil, nil)
	}
	for child, nsrrs := range z.deleg {
		if isSubdomain(q.Name, child) {
			return resp(0, false, false, nil, nsrrs, z.glue)
		}
	}
	var exists bool
	var an []RR
	for _, rr := range z.records {
		if rr.Name != q.Name {
			continue
		}
		exists = true
		if rr.Type == q.Type || rr.Type == TypeCNAME {
			an = append(an, rr)
		}
	}
	if !exists {
		return resp(RcodeNXDomain, true, false, nil, z.withSigs([]RR{soa}), nil)
	}
	if udp && z.tcOnUDP[q.Name] {
		return resp(0, true, true, nil, nil, nil)
	}
	if len(an) == 0 {
		return resp(0, true, false, nil, []RR{soa}, nil)
	}
	return resp(0, true, false, z.withSigs(an), nil, nil)
}

func startFake(t *testing.T, ip string, z *fakeZone) {
	t.Helper()
	addr := net.JoinHostPort(ip, testPort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind tcp %s: %v", addr, err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })

	reply := func(pkt []byte, udp bool) []byte {
		m, err := ParseMessage(pkt)
		if err != nil || len(m.Questions) != 1 {
			return nil
		}
		q := m.Questions[0]
		if !udp && z.badTCP[q.Name] {
			q.Name = "evil." + q.Name
		}
		out := z.answer(q, udp)
		binary.BigEndian.PutUint16(out, m.Header.ID)
		return out
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if m, err := ParseMessage(buf[:n]); err == nil && len(m.Questions) == 1 && z.forge[m.Questions[0].Name] {
				q := m.Questions[0]
				forged := buildResponse(m.Header.ID^0xFFFF, q, false, 0, []RR{a(q.Name, "6.6.6.6")}, nil, nil)
				pc.WriteTo(forged, from)
			}
			if out := reply(buf[:n], true); out != nil {
				pc.WriteTo(out, from)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				pkt := make([]byte, binary.BigEndian.Uint16(lb[:]))
				io.ReadFull(c, pkt)
				out := reply(pkt, false)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
			}(c)
		}
	}()
}

type testNet struct {
	r     *Resolver
	trace *bytes.Buffer
	zones map[string]*fakeZone
	root  *testSigner
}

func newTestNet(t *testing.T) *testNet {
	rootKey, comKey, exKey := newSigner("."), newSigner("com."), newSigner("example.com.")
	many := []RR{}
	for i := range 40 {
		i++
		many = append(many, a("many.example.com.", "10.1.2."+strconv.Itoa(i)))
	}
	var fanout []RR
	for i := range 8 {
		i++
		fanout = append(fanout, ns("fanout.com.", "ns"+strconv.Itoa(i)+".nowhere.org."))
	}
	huge := a("huge.example.com.", "10.7.7.7")
	huge.TTL = 4000000000

	zones := map[string]*fakeZone{
		".": {origin: ".",
			records: []RR{rootKey.rr, comKey.ds()},
			deleg: map[string][]RR{
				"com.": {ns("com.", "ns.gtld.com.")},
				"org.": {ns("org.", "ns.org.")},
			},
			glue:   []RR{a("ns.gtld.com.", "127.0.0.11"), a("ns.org.", "127.0.0.13")},
			signer: rootKey,
		},
		"com.": {origin: "com.",
			records: []RR{comKey.rr, exKey.ds()},
			deleg: map[string][]RR{
				"example.com.":  {ns("example.com.", "ns1.example.com.")},
				"glueless.com.": {ns("glueless.com.", "ns.dnshost.org.")},
				"trap.com.":     {ns("net.", "ns.evil.net.")},
				"fanout.com.":   fanout,
			},
			glue: []RR{
				a("ns1.example.com.", "127.0.0.12"),
				a("ns.dnshost.org.", "6.6.6.6"),
			},
			signer: comKey,
		},
		"example.com.": {origin: "example.com.",
			records: append([]RR{
				exKey.rr,
				a("www.example.com.", "93.184.216.34"),
				{Name: "alias.example.com.", Type: TypeCNAME, Class: 1, TTL: 300, Data: "www.example.com."},
				{Name: "example.com.", Type: TypeMX, Class: 1, TTL: 300, Data: "10 mail.example.com."},
				a("mail.example.com.", "93.184.216.35"),
				a("big.example.com.", "10.9.9.9"),
				a("badtcp.example.com.", "10.9.9.8"),
				a("forged.example.com.", "10.1.1.1"),
				a("tampered.example.com.", "10.2.2.2"),
				huge,
			}, many...),
			tcOnUDP: map[string]bool{"big.example.com.": true, "badtcp.example.com.": true},
			badTCP:  map[string]bool{"badtcp.example.com.": true},
			forge:   map[string]bool{"forged.example.com.": true},
			tamper:  map[string]string{"tampered.example.com.": "6.6.6.6"},
			signer:  exKey,
		},
		"org.": {origin: "org.",
			deleg: map[string][]RR{"dnshost.org.": {ns("dnshost.org.", "ns.dnshost.org.")}},
			glue:  []RR{a("ns.dnshost.org.", "127.0.0.14")},
		},
		"dnshost.org.": {origin: "dnshost.org.",
			records: []RR{a("ns.dnshost.org.", "127.0.0.15")},
		},
		"glueless.com.": {origin: "glueless.com.",
			records: []RR{a("glueless.com.", "10.0.0.1")},
		},
	}
	for ip, z := range map[string]string{"127.0.0.10": ".", "127.0.0.11": "com.", "127.0.0.12": "example.com.",
		"127.0.0.13": "org.", "127.0.0.14": "dnshost.org.", "127.0.0.15": "glueless.com."} {
		startFake(t, ip, zones[z])
	}

	r := NewResolver()
	r.Port = testPort
	r.Timeout = 500 * time.Millisecond
	r.Roots = []nameserver{{"fake-root.", "127.0.0.10"}}
	r.Anchors = []DSRecord{rootKey.anchor()}
	var trace bytes.Buffer
	r.Trace = &trace
	return &testNet{r, &trace, zones, rootKey}
}

func newTestResolver(t *testing.T) (*Resolver, *bytes.Buffer) {
	n := newTestNet(t)
	return n.r, n.trace
}

func TestReferralChain(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("www.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Answers) != 1 || res.Answers[0].Data != "93.184.216.34" || res.Hops != 3 {
		t.Fatalf("got %+v\n%s", res, trace)
	}
	for _, want := range []string{"referral to com.", "referral to example.com.", "answered 1 A"} {
		if !strings.Contains(trace.String(), want) {
			t.Errorf("trace missing %q:\n%s", want, trace)
		}
	}
}

func TestDelegationCache(t *testing.T) {
	r, trace := newTestResolver(t)
	r.Resolve("www.example.com", TypeA)
	trace.Reset()
	res, err := r.Resolve("mail.example.com", TypeA)
	if err != nil || res.Hops != 1 {
		t.Fatalf("expected 1 hop via cached example.com. delegation, got %+v err=%v\n%s", res, err, trace)
	}
	if strings.Contains(trace.String(), "fake-root") {
		t.Errorf("should not have touched the root:\n%s", trace)
	}
}

func TestCNAME(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("alias.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Answers) != 2 || res.Answers[0].Type != TypeCNAME || res.Answers[1].Data != "93.184.216.34" {
		t.Fatalf("got %+v\n%s", res.Answers, trace)
	}
}

func TestNXDomainAndNoData(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("nope.example.com", TypeA)
	if err != nil || res.Rcode != RcodeNXDomain || len(res.Authority) == 0 || res.Authority[0].Type != TypeSOA {
		t.Fatalf("NXDOMAIN: %+v %v", res, err)
	}
	res, err = r.Resolve("www.example.com", TypeAAAA)
	if err != nil || res.Rcode != RcodeNoError || len(res.Answers) != 0 {
		t.Fatalf("NODATA: %+v %v", res, err)
	}
}

func TestMX(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("example.com", TypeMX)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10 mail.example.com." {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGluelessDelegationIgnoresPoisonedGlue(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("glueless.com", TypeA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10.0.0.1" {
		t.Fatalf("%+v %v\n%s", res, err, trace)
	}
	if strings.Contains(trace.String(), "6.6.6.6") {
		t.Errorf("used out-of-bailiwick glue:\n%s", trace)
	}
	if !strings.Contains(trace.String(), "no glue") {
		t.Errorf("expected glueless path:\n%s", trace)
	}
}

func TestOutOfBailiwickReferralRejected(t *testing.T) {
	r, _ := newTestResolver(t)
	_, err := r.Resolve("www.trap.com", TypeA)
	if err == nil || !strings.Contains(err.Error(), "bailiwick") {
		t.Fatalf("expected bailiwick error, got %v", err)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("big.example.com", TypeA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10.9.9.9" {
		t.Fatalf("%+v %v\n%s", res, err, trace)
	}
	if !strings.Contains(trace.String(), "TCP") {
		t.Errorf("expected TCP retry in trace:\n%s", trace)
	}
}

func TestNameCompression(t *testing.T) {
	pkt := []byte{
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
		0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 1, 2, 3, 4,
	}
	m, err := ParseMessage(pkt)
	if err != nil || m.Answers[0].Name != "www.example.com." || m.Answers[0].Data != "1.2.3.4" {
		t.Fatalf("%+v %v", m, err)
	}
	loop := append(append([]byte{}, pkt[:12]...), 0xC0, 0x0C)
	if _, err := ParseMessage(loop); err == nil {
		t.Fatal("expected loop error")
	}
}
