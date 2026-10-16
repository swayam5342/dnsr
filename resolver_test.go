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
	"encoding/binary"
	"io"
	"net"
	"strings"
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
}

func a(name, ip string) RR {
	return RR{Name: name, Type: TypeA, Class: 1, TTL: 300, Data: ip, Raw: net.ParseIP(ip).To4()}
}
func ns(zone, host string) RR { return RR{Name: zone, Type: TypeNS, Class: 1, TTL: 3600, Data: host} }

func (z *fakeZone) answer(q Question, udp bool) []byte {
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
		return resp(RcodeNXDomain, true, false, nil, []RR{soa}, nil)
	}
	if udp && z.tcOnUDP[q.Name] {
		return resp(0, true, true, nil, nil, nil)
	}
	if len(an) == 0 {
		return resp(0, true, false, nil, []RR{soa}, nil)
	}
	return resp(0, true, false, an, nil, nil)
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
		out := z.answer(m.Questions[0], udp)
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

func newTestResolver(t *testing.T) (*Resolver, *bytes.Buffer) {
	startFake(t, "127.0.0.10", &fakeZone{origin: ".",
		deleg: map[string][]RR{
			"com.": {ns("com.", "ns.gtld.com.")},
			"org.": {ns("org.", "ns.org.")},
		},
		glue: []RR{a("ns.gtld.com.", "127.0.0.11"), a("ns.org.", "127.0.0.13")},
	})
	startFake(t, "127.0.0.11", &fakeZone{origin: "com.",
		deleg: map[string][]RR{
			"example.com.":  {ns("example.com.", "ns1.example.com.")},
			"glueless.com.": {ns("glueless.com.", "ns.dnshost.org.")},
			"trap.com.":     {ns("net.", "ns.evil.net.")},
		},
		glue: []RR{
			a("ns1.example.com.", "127.0.0.12"),
			a("ns.dnshost.org.", "6.6.6.6"),
		},
	})
	startFake(t, "127.0.0.12", &fakeZone{origin: "example.com.",
		records: []RR{
			a("www.example.com.", "93.184.216.34"),
			{Name: "alias.example.com.", Type: TypeCNAME, Class: 1, TTL: 300, Data: "www.example.com."},
			{Name: "example.com.", Type: TypeMX, Class: 1, TTL: 300, Data: "10 mail.example.com."},
			a("mail.example.com.", "93.184.216.35"),
			a("big.example.com.", "10.9.9.9"),
		},
		tcOnUDP: map[string]bool{"big.example.com.": true},
	})
	startFake(t, "127.0.0.13", &fakeZone{origin: "org.",
		deleg: map[string][]RR{"dnshost.org.": {ns("dnshost.org.", "ns.dnshost.org.")}},
		glue:  []RR{a("ns.dnshost.org.", "127.0.0.14")},
	})
	startFake(t, "127.0.0.14", &fakeZone{origin: "dnshost.org.",
		records: []RR{a("ns.dnshost.org.", "127.0.0.15")},
	})
	startFake(t, "127.0.0.15", &fakeZone{origin: "glueless.com.",
		records: []RR{a("glueless.com.", "10.0.0.1")},
	})

	r := NewResolver()
	r.Port = testPort
	r.Timeout = 500 * time.Millisecond
	r.Roots = []nameserver{{"fake-root.", "127.0.0.10"}}
	var trace bytes.Buffer
	r.Trace = &trace
	return r, &trace
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
