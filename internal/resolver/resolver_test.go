package resolver

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/swayam5342/dnsr/internal/dnstest"
	"github.com/swayam5342/dnsr/internal/wire"
)

type testNet struct {
	r     *Resolver
	trace *bytes.Buffer
	zones map[string]*dnstest.Zone
	root  *dnstest.Signer
}

func newTestNet(t *testing.T) *testNet {
	n := dnstest.Start(t)
	r := New()
	r.Port = n.Port
	r.Timeout = 500 * time.Millisecond
	r.Roots = []Nameserver{{"fake-root.", dnstest.RootIP}}
	r.Anchors = []wire.DS{n.Root.Anchor()}
	var trace bytes.Buffer
	r.Trace = &trace
	return &testNet{r, &trace, n.Zones, n.Root}
}

func newTestResolver(t *testing.T) (*Resolver, *bytes.Buffer) {
	n := newTestNet(t)
	return n.r, n.trace
}

func TestReferralChain(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("www.example.com", wire.TypeA)
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
	r.Resolve("www.example.com", wire.TypeA)
	trace.Reset()
	res, err := r.Resolve("mail.example.com", wire.TypeA)
	if err != nil || res.Hops != 1 {
		t.Fatalf("expected 1 hop via cached example.com. delegation, got %+v err=%v\n%s", res, err, trace)
	}
	if strings.Contains(trace.String(), "fake-root") {
		t.Errorf("should not have touched the root:\n%s", trace)
	}
}

func TestCNAME(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("alias.example.com", wire.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Answers) != 2 || res.Answers[0].Type != wire.TypeCNAME || res.Answers[1].Data != "93.184.216.34" {
		t.Fatalf("got %+v\n%s", res.Answers, trace)
	}
}

func TestNXDomainAndNoData(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("nope.example.com", wire.TypeA)
	if err != nil || res.Rcode != wire.RcodeNXDomain || len(res.Authority) == 0 || res.Authority[0].Type != wire.TypeSOA {
		t.Fatalf("NXDOMAIN: %+v %v", res, err)
	}
	res, err = r.Resolve("www.example.com", wire.TypeAAAA)
	if err != nil || res.Rcode != wire.RcodeNoError || len(res.Answers) != 0 {
		t.Fatalf("NODATA: %+v %v", res, err)
	}
}

func TestMX(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("example.com", wire.TypeMX)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10 mail.example.com." {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestGluelessDelegationIgnoresPoisonedGlue(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("glueless.com", wire.TypeA)
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
	_, err := r.Resolve("www.trap.com", wire.TypeA)
	if err == nil || !strings.Contains(err.Error(), "bailiwick") {
		t.Fatalf("expected bailiwick error, got %v", err)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	r, trace := newTestResolver(t)
	res, err := r.Resolve("big.example.com", wire.TypeA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10.9.9.9" {
		t.Fatalf("%+v %v\n%s", res, err, trace)
	}
	if !strings.Contains(trace.String(), "TCP") {
		t.Errorf("expected TCP retry in trace:\n%s", trace)
	}
}

func TestQNAMEMinimisation(t *testing.T) {
	n := newTestNet(t)
	if _, err := n.r.Resolve("www.example.com", wire.TypeA); err != nil {
		t.Fatal(err)
	}
	for zone, want := range map[string]string{".": "com.", "com.": "example.com."} {
		for _, q := range n.zones[zone].Questions() {
			if q.Name != want || q.Type != wire.TypeNS {
				t.Errorf("%s server saw %s %s, want only %s NS", zone, q.Name, q.Type, want)
			}
		}
	}
}

func TestQNAMEMinimisationCanBeDisabled(t *testing.T) {
	n := newTestNet(t)
	n.r.Minimise = false
	n.r.Resolve("www.example.com", wire.TypeA)
	if qs := n.zones["."].Questions(); len(qs) == 0 || qs[0].Name != "www.example.com." {
		t.Errorf("with minimisation off the root should see the full name, saw %v", qs)
	}
}
