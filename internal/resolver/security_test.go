package resolver

import (
	"strings"
	"testing"
	"time"

	"github.com/swayam5342/dnsr/internal/dnstest"
	"github.com/swayam5342/dnsr/internal/wire"
)

func TestTTLIsCapped(t *testing.T) {
	r, _ := newTestResolver(t)
	res, err := r.Resolve("huge.example.com", wire.TypeA)
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
	r := New()
	r.MaxCacheEntries = 5
	for i := range 50 {
		name := "n" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example."
		r.cachePut(name, wire.TypeA, []wire.RR{dnstest.A(name, "10.0.0.1")}, nil)
		r.putZone(name, []Nameserver{{"ns.", "10.0.0.1"}}, 300)
	}
	if len(r.cache) > 5 || len(r.zoneNS) > 5 {
		t.Fatalf("cache %d entries, zoneNS %d entries; limit 5", len(r.cache), len(r.zoneNS))
	}
}

func TestExpiredDelegationIsIgnored(t *testing.T) {
	r := New()
	r.zoneNS["example.com."] = zoneEntry{[]Nameserver{{"ns1.example.com.", "10.0.0.1"}}, time.Now().Add(-time.Second)}
	if zone, _ := r.closestKnownZone("www.example.com."); zone != "." {
		t.Fatalf("used expired delegation %s", zone)
	}
}

func TestGluelessLookupsAreLimited(t *testing.T) {
	n := newTestNet(t)
	_, err := n.r.Resolve("www.fanout.com", wire.TypeA)
	if err == nil || !strings.Contains(err.Error(), "could not find an address") {
		t.Fatalf("expected failure, got %v", err)
	}
	asked := map[string]bool{}
	for _, q := range n.zones["org."].Questions() {
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
	res, err := r.Resolve("forged.example.com", wire.TypeA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Data != "10.1.1.1" {
		t.Fatalf("accepted a forged reply: %+v %v\n%s", res, err, trace)
	}
}

func TestTCPReplyMustMatchQuestion(t *testing.T) {
	r, trace := newTestResolver(t)
	_, err := r.Resolve("badtcp.example.com", wire.TypeA)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected TCP mismatch error, got %v\n%s", err, trace)
	}
}

func TestQueryIDsAndCaseAreRandom(t *testing.T) {
	ids := map[uint16]bool{}
	for range 2000 {
		ids[randomID()] = true
	}
	if len(ids) < 1900 {
		t.Fatalf("only %d distinct IDs in 2000 draws", len(ids))
	}
	name := "www.example-domain-with-many-letters.com."
	variants := map[string]bool{}
	for range 20 {
		m := randomCase(name)
		if !strings.EqualFold(m, name) || len(m) != len(name) {
			t.Fatalf("randomCase changed the name: %s", m)
		}
		variants[m] = true
	}
	if len(variants) < 19 {
		t.Fatalf("only %d distinct case patterns in 20 draws", len(variants))
	}
}

func TestQueriesUseRandomCaseAndAnswersAreLowercase(t *testing.T) {
	n := newTestNet(t)
	for _, name := range []string{"www.example.com", "mail.example.com", "alias.example.com"} {
		res, err := n.r.Resolve(name, wire.TypeA)
		if err != nil || len(res.Answers) == 0 {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		for _, rr := range res.Answers {
			if rr.Name != strings.ToLower(rr.Name) {
				t.Fatalf("answer name not normalised: %s", rr.Name)
			}
		}
	}
	mixed := 0
	for _, q := range n.zones["example.com."].RawNames() {
		if q != strings.ToLower(q) {
			mixed++
		}
	}
	if mixed == 0 {
		t.Fatalf("no query used mixed case: %v", n.zones["example.com."].RawNames())
	}
}

func TestCaseRandomisationFallsBackForServersThatDoNotPreserveCase(t *testing.T) {
	n := newTestNet(t)
	n.zones["example.com."].NoCase = true
	for _, name := range []string{"www.example.com", "mail.example.com", "alias.example.com", "big.example.com", "forged.example.com"} {
		res, err := n.r.Resolve(name, wire.TypeA)
		if err != nil || len(res.Answers) == 0 {
			t.Fatalf("%s failed against a case-insensitive server: %+v %v\n%s", name, res, err, n.trace)
		}
		if n.r.caseUnsafe("127.0.0.12") {
			break
		}
	}
	if !n.r.caseUnsafe("127.0.0.12") || !strings.Contains(n.trace.String(), "does not preserve letter case") {
		t.Fatalf("fallback not recorded:\n%s", n.trace)
	}
}
