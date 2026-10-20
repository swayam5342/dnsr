// Package resolver does iterative resolution, the way a real recursor does it:
//
//	root (.)  ──referral──▶  TLD (com.)  ──referral──▶  example.com. NS  ──▶ answer
//
// We start from hard-coded root hints, send non-recursive queries, and follow
// referrals (NS in Authority + glue in Additional) until someone answers
// authoritatively. CNAMEs are chased, glueless delegations are resolved
// with a nested lookup, and truncated UDP responses fall back to TCP.
// Queries are QNAME-minimised (RFC 9156): each server only sees one label
// more than the zone it serves, until the final server gets the full name.
package resolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/swayam5342/dnsr/internal/term"
	"github.com/swayam5342/dnsr/internal/wire"
)

var rootHints = []Nameserver{
	{"a.root-servers.net.", "198.41.0.4"},
	{"b.root-servers.net.", "170.247.170.2"},
	{"c.root-servers.net.", "192.33.4.12"},
	{"d.root-servers.net.", "199.7.91.13"},
	{"e.root-servers.net.", "192.203.230.10"},
	{"f.root-servers.net.", "192.5.5.241"},
	{"g.root-servers.net.", "192.112.36.4"},
	{"h.root-servers.net.", "198.97.190.53"},
	{"i.root-servers.net.", "192.36.148.17"},
	{"j.root-servers.net.", "192.58.128.30"},
	{"k.root-servers.net.", "193.0.14.129"},
	{"l.root-servers.net.", "199.7.83.42"},
	{"m.root-servers.net.", "202.12.27.33"},
}

const (
	defaultMaxTTL      = 86400
	defaultCacheSize   = 10000
	maxGluelessLookups = 3
	maxMinimiseLabels  = 10
)

type Nameserver struct {
	Name string
	IP   string
}

type Result struct {
	Rcode        int
	Answers      []wire.RR
	Authority    []wire.RR
	Sigs         []wire.RR
	Hops         int
	Elapsed      time.Duration
	Security     Security
	SecurityNote string
}

type Resolver struct {
	Timeout           time.Duration
	MaxHops           int
	Trace             io.Writer
	Port              string
	Roots             []Nameserver
	Minimise          bool
	DNSSEC            bool
	Anchors           []wire.DS
	MaxTTL            uint32
	MaxCacheEntries   int
	CaseRandomisation bool
	Color             bool
	mu                sync.Mutex
	cache             map[string]cacheEntry
	zoneNS            map[string]zoneEntry
	keys              map[string]keyEntry
	no0x20            map[string]time.Time
}

func New() *Resolver {
	return &Resolver{
		Timeout:           2 * time.Second,
		MaxHops:           40,
		Port:              "53",
		Roots:             rootHints,
		Minimise:          true,
		Anchors:           rootAnchors,
		MaxTTL:            defaultMaxTTL,
		MaxCacheEntries:   defaultCacheSize,
		CaseRandomisation: true,
		cache:             map[string]cacheEntry{},
		zoneNS:            map[string]zoneEntry{},
		keys:              map[string]keyEntry{},
		no0x20:            map[string]time.Time{},
	}
}

var (
	ErrLoop     = errors.New("resolution loop / too deep")
	ErrNoServer = errors.New("all nameservers failed")
)

// childToward returns the name one label below zone on the way to name
// ("www.example.com." from "com." → "example.com.").
func childToward(name, zone string) string {
	if name == zone || !wire.IsSubdomain(name, zone) {
		return name
	}
	nl, zl := wire.SplitLabels(name), len(wire.SplitLabels(zone))
	return strings.Join(nl[len(nl)-zl-1:], ".") + "."
}

// Resolve resolves name/qtype from the root and, when DNSSEC is enabled,
// validates the answer against the root trust anchor.
func (r *Resolver) Resolve(name string, qtype wire.RRType) (*Result, error) {
	start := time.Now()
	res, err := r.resolve(wire.Fqdn(name), qtype, 0, 0)
	if err == nil && r.DNSSEC {
		res.Security, res.SecurityNote = r.validateResult(res)
		r.traceSecurity(res)
	}
	if res != nil {
		res.Elapsed = time.Since(start)
	}
	return res, err
}

// coveredSigs returns the RRSIGs that cover records of type t.
func coveredSigs(sigs []wire.RR, t wire.RRType) []wire.RR {
	var out []wire.RR
	for _, s := range sigs {
		if len(s.Raw) >= 2 && wire.RRType(binary.BigEndian.Uint16(s.Raw)) == t {
			out = append(out, s)
		}
	}
	return out
}

// referralNS extracts the delegation from a reply: NS records in the authority
// section, or, for a minimised NS query, NS records for qname in the answer.
func referralNS(msg *wire.Message, qname string, probing bool) ([]wire.RR, string) {
	var out []wire.RR
	var child string
	if probing {
		for _, rr := range msg.Answers {
			if rr.Type == wire.TypeNS && strings.EqualFold(rr.Name, qname) {
				out, child = append(out, rr), strings.ToLower(rr.Name)
			}
		}
		if len(out) > 0 {
			return out, child
		}
	}
	for _, rr := range msg.Authority {
		if rr.Type == wire.TypeNS {
			out, child = append(out, rr), strings.ToLower(rr.Name)
		}
	}
	return out, child
}

// unexpectedAnswer reports whether a reply to a minimised NS query contains
// anything other than NS records for the probed name (a CNAME, for example).
func unexpectedAnswer(msg *wire.Message, qname string) bool {
	for _, rr := range msg.Answers {
		if rr.Type == wire.TypeRRSIG {
			continue
		}
		if rr.Type != wire.TypeNS || !strings.EqualFold(rr.Name, qname) {
			return true
		}
	}
	return false
}

func (r *Resolver) resolve(name string, qtype wire.RRType, depth, hops int) (*Result, error) {
	if depth > 8 {
		return nil, ErrLoop
	}
	if rrs, sigs, ok := r.cacheGet(name, qtype); ok {
		r.tracef(depth, "%s %s %s", r.c(term.Green, "✓ cache hit"), name, qtype)
		return &Result{Rcode: wire.RcodeNoError, Answers: rrs, Sigs: sigs, Hops: hops}, nil
	}

	start := name
	if qtype == wire.TypeDS && name != "." {
		start = wire.ParentName(name)
	}
	zone, servers := r.closestKnownZone(start)
	if zone != "." {
		r.tracef(depth, "%s starting at cached zone %s", r.c(term.Dim, "↷"), r.c(term.Bold, zone))
	}
	minimise := r.Minimise && len(wire.SplitLabels(name)) <= maxMinimiseLabels
	probe := childToward(name, zone)

	for ; hops < r.MaxHops; hops++ {
		qname, qt := name, qtype
		if minimise && probe != name {
			qname, qt = probe, wire.TypeNS
		}
		probing := qname != name
		msg, ns, rtt, err := r.queryAny(servers, qname, qt, depth)
		if err != nil {
			return nil, fmt.Errorf("querying %s servers for %s: %w", zone, qname, err)
		}

		if probing && (msg.Header.Rcode != wire.RcodeNoError || unexpectedAnswer(msg, qname)) {
			r.tracef(depth, "%s %s gave %s to the minimised query, asking for the full name", r.c(term.Yellow, "↺"), ns.Name, wire.RcodeString(msg.Header.Rcode))
			minimise = false
			continue
		}

		if !probing {
			if msg.Header.Rcode == wire.RcodeNXDomain {
				r.tracef(depth, "%s %s says %s (%s)", r.c(term.Red, "✗"), ns.Name, r.c(term.Red, "NXDOMAIN"), rtt)
				return &Result{Rcode: wire.RcodeNXDomain, Authority: r.clampTTLs(msg.Authority), Hops: hops + 1}, nil
			}
			if msg.Header.Rcode != wire.RcodeNoError {
				r.tracef(depth, "%s %s returned %s, trying next server", r.c(term.Yellow, "!"), ns.Name, wire.RcodeString(msg.Header.Rcode))
				servers = without(servers, ns)
				if len(servers) == 0 {
					return &Result{Rcode: msg.Header.Rcode, Hops: hops + 1}, nil
				}
				continue
			}

			var direct, cnames, sigs []wire.RR
			for _, rr := range msg.Answers {
				if !strings.EqualFold(rr.Name, name) {
					continue
				}
				rr.Zone = zone
				switch {
				case rr.Type == qtype:
					direct = append(direct, rr)
				case rr.Type == wire.TypeCNAME:
					cnames = append(cnames, rr)
				case rr.Type == wire.TypeRRSIG:
					sigs = append(sigs, rr)
				}
			}
			if len(direct) > 0 {
				r.tracef(depth, "%s %s answered %s (%s)", r.c(term.Green, "✓"), ns.Name,
					r.c(term.Green, fmt.Sprintf("%d %s record(s)", len(direct), qtype)), rtt)
				direct, sigs = r.clampTTLs(direct), coveredSigs(sigs, qtype)
				r.cachePut(name, qtype, direct, sigs)
				return &Result{Rcode: wire.RcodeNoError, Answers: direct, Sigs: sigs, Hops: hops + 1}, nil
			}
			if len(cnames) > 0 {
				target := wire.Fqdn(cnames[0].Data)
				r.tracef(depth, "%s %s is an alias → %s, restarting from the top", r.c(term.Cyan, "↪ CNAME"), name, r.c(term.Bold, target))
				sub, err := r.resolve(target, qtype, depth+1, hops+1)
				if err != nil {
					return nil, err
				}
				sub.Answers = append(r.clampTTLs(cnames[:1]), sub.Answers...)
				sub.Sigs = append(coveredSigs(sigs, wire.TypeCNAME), sub.Sigs...)
				return sub, nil
			}
			if msg.Header.AA {
				r.tracef(depth, "%s %s: name exists but has no %s records (NODATA)", r.c(term.Yellow, "∅"), ns.Name, qtype)
				return &Result{Rcode: wire.RcodeNoError, Authority: r.clampTTLs(msg.Authority), Hops: hops + 1}, nil
			}
		}

		nsRRs, child := referralNS(msg, qname, probing)
		if len(nsRRs) == 0 {
			if probing && msg.Header.AA {
				r.tracef(depth, "%s %s: no zone cut at %s (%s)", r.c(term.Dim, "·"), ns.Name, qname, rtt)
				probe = childToward(name, probe)
				continue
			}
			return nil, fmt.Errorf("lame response from %s: no answer, no referral", ns.Name)
		}

		if !wire.IsSubdomain(name, child) || !wire.IsSubdomain(child, zone) || child == zone {
			return nil, fmt.Errorf("out-of-bailiwick referral from %s: %s is not under %s", ns.Name, child, zone)
		}

		next := r.glueFor(nsRRs, msg.Additional, zone)
		names := make([]string, 0, len(nsRRs))
		for _, rr := range nsRRs {
			names = append(names, strings.TrimSuffix(rr.Data, "."))
		}
		r.tracef(depth, "%s %s → referral to %s %s (%s)", r.c(term.Cyan, "↓"), ns.Name, r.c(term.Bold, child),
			r.c(term.Dim, fmt.Sprintf("[%s]", summarize(names, 3))), rtt)

		if len(next) == 0 {
			r.tracef(depth, "%s no glue for %s — resolving a nameserver's address first", r.c(term.Yellow, "⋯"), child)
			for i, nsrr := range shuffled(nsRRs) {
				if i >= maxGluelessLookups {
					r.tracef(depth, "%s giving up after %d nameserver lookups for %s", r.c(term.Yellow, "!"), maxGluelessLookups, child)
					break
				}
				sub, err := r.resolve(wire.Fqdn(nsrr.Data), wire.TypeA, depth+1, 0)
				if err != nil || sub.Rcode != wire.RcodeNoError {
					continue
				}
				for _, a := range sub.Answers {
					if a.Type == wire.TypeA {
						next = append(next, Nameserver{wire.Fqdn(nsrr.Data), a.Data})
					}
				}
				if len(next) > 0 {
					break
				}
			}
			if len(next) == 0 {
				return nil, fmt.Errorf("could not find an address for any %s nameserver", child)
			}
		}

		r.putZone(child, next, minTTL(nsRRs))
		zone, servers = child, next
		probe = childToward(name, zone)
	}
	return nil, ErrLoop
}

// glueFor pairs NS names with A records from the Additional section.
// Glue is only trusted if it lies inside the zone of the server that sent it
// (askedZone) — a .com server may vouch for ns1.example.com, not for ns.evil.org.
func (r *Resolver) glueFor(nsRRs, additional []wire.RR, askedZone string) []Nameserver {
	want := map[string]bool{}
	for _, rr := range nsRRs {
		want[wire.Fqdn(rr.Data)] = true
	}
	var out []Nameserver
	for _, rr := range additional {
		n := wire.Fqdn(rr.Name)
		if rr.Type == wire.TypeA && want[n] && wire.IsSubdomain(n, askedZone) {
			out = append(out, Nameserver{n, rr.Data})
		}
	}
	return out
}

func shuffled[T any](in []T) []T {
	out := append([]T(nil), in...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func without(in []Nameserver, x Nameserver) []Nameserver {
	var out []Nameserver
	for _, s := range in {
		if s != x {
			out = append(out, s)
		}
	}
	return out
}
