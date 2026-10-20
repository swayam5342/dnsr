package resolver

import (
	"testing"

	"github.com/swayam5342/dnsr/internal/dnstest"
	"github.com/swayam5342/dnsr/internal/wire"
)

func TestDNSSECSecure(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	for _, name := range []string{"www.example.com", "alias.example.com"} {
		res, err := n.r.Resolve(name, wire.TypeA)
		if err != nil || res.Security != SecSecure {
			t.Fatalf("%s: security %v (%s) err %v\n%s", name, res.Security, res.SecurityNote, err, n.trace)
		}
	}
	res, _ := n.r.Resolve("example.com", wire.TypeMX)
	if res.Security != SecSecure {
		t.Fatalf("MX: %v %s", res.Security, res.SecurityNote)
	}
}

func TestDNSSECBogusWhenRecordIsTampered(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	res, err := n.r.Resolve("tampered.example.com", wire.TypeA)
	if err != nil || res.Security != SecBogus {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func TestDNSSECBogusWithWrongTrustAnchor(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	n.r.Anchors = []wire.DS{dnstest.NewSigner(".").Anchor()}
	res, err := n.r.Resolve("www.example.com", wire.TypeA)
	if err != nil || res.Security != SecBogus {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func TestDNSSECInsecureDelegation(t *testing.T) {
	n := newTestNet(t)
	n.r.DNSSEC = true
	res, err := n.r.Resolve("glueless.com", wire.TypeA)
	if err != nil || res.Security != SecInsecure {
		t.Fatalf("security %v (%s) err %v", res.Security, res.SecurityNote, err)
	}
}

func BenchmarkVerifyECDSAP256(b *testing.B) {
	s := dnstest.NewSigner("example.com.")
	k, _ := wire.ParseDNSKEY(s.RR)
	set := []wire.RR{dnstest.A("www.example.com.", "1.2.3.4")}
	sig := s.Sign(set)
	for b.Loop() {
		if err := verifyRRset(set, []wire.RR{sig}, []*wire.DNSKEY{k}, "example.com."); err != nil {
			b.Fatal(err)
		}
	}
}
