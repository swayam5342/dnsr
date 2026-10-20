package main

// resolver.go — iterative resolution, the way a real recursor does it:
//
//   root (.)  ──referral──▶  TLD (com.)  ──referral──▶  example.com. NS  ──▶ answer
//
// We start from hard-coded root hints, send non-recursive queries, and follow
// referrals (NS in Authority + glue in Additional) until someone answers
// authoritatively. CNAMEs are chased, glueless delegations are resolved
// with a nested lookup, and truncated UDP responses fall back to TCP.
// Queries are QNAME-minimised (RFC 9156): each server only sees one label
// more than the zone it serves, until the final server gets the full name.

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"time"
)

var rootHints = []nameserver{
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

type nameserver struct {
	Name string
	IP   string
}

type Result struct {
	Rcode        int
	Answers      []RR
	Authority    []RR
	Sigs         []RR
	Hops         int
	Elapsed      time.Duration
	Security     Security
	SecurityNote string
}

type cacheEntry struct {
	rrs     []RR
	sigs    []RR
	expires time.Time
}

type zoneEntry struct {
	ns      []nameserver
	expires time.Time
}

type Resolver struct {
	Timeout           time.Duration
	MaxHops           int
	Trace             io.Writer
	Port              string
	Roots             []nameserver
	Minimise          bool
	DNSSEC            bool
	Anchors           []DSRecord
	MaxTTL            uint32
	MaxCacheEntries   int
	CaseRandomisation bool
	color             bool
	mu                sync.Mutex
	cache             map[string]cacheEntry
	zoneNS            map[string]zoneEntry
	keys              map[string]keyEntry
	no0x20            map[string]time.Time
}

func NewResolver() *Resolver {
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

func fqdn(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// isSubdomain reports whether child is at or below parent ("a.b.c." under "b.c.").
func isSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	return child == parent || strings.HasSuffix(child, "."+parent)
}

// splitLabels returns the labels of a name, without the root ("www.example.com." → www, example, com).
func splitLabels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// parentName drops the leftmost label ("www.example.com." → "example.com.").
func parentName(name string) string {
	ls := splitLabels(name)
	if len(ls) <= 1 {
		return "."
	}
	return strings.Join(ls[1:], ".") + "."
}

// childToward returns the name one label below zone on the way to name
// ("www.example.com." from "com." → "example.com.").
func childToward(name, zone string) string {
	if name == zone || !isSubdomain(name, zone) {
		return name
	}
	nl, zl := splitLabels(name), len(splitLabels(zone))
	return strings.Join(nl[len(nl)-zl-1:], ".") + "."
}

// Resolve resolves name/qtype from the root and, when DNSSEC is enabled,
// validates the answer against the root trust anchor.
func (r *Resolver) Resolve(name string, qtype RRType) (*Result, error) {
	start := time.Now()
	res, err := r.resolve(fqdn(name), qtype, 0, 0)
	if err == nil && r.DNSSEC {
		res.Security, res.SecurityNote = r.validateResult(res)
		r.traceSecurity(res)
	}
	if res != nil {
		res.Elapsed = time.Since(start)
	}
	return res, err
}

const (
	cDim, cCyan, cGreen, cYellow, cRed, cBold, cReset = "\033[2m", "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"
)

func (r *Resolver) c(code, s string) string {
	if !r.color {
		return s
	}
	return code + printable(s) + cReset
}

// tracef prints one trace line; control characters from untrusted names are escaped.
func (r *Resolver) tracef(depth int, format string, a ...any) {
	if r.Trace == nil {
		return
	}
	for i, v := range a {
		if s, ok := v.(string); ok && !strings.HasPrefix(s, "\033") {
			a[i] = printable(s)
		}
	}
	fmt.Fprintf(r.Trace, "%s%s\n", strings.Repeat("  │ ", depth), fmt.Sprintf(format, a...))
}

// printable escapes bytes that could act as terminal control sequences.
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			var b strings.Builder
			for j := 0; j < len(s); j++ {
				if c := s[j]; c < 0x20 || c == 0x7f {
					fmt.Fprintf(&b, "\\%03d", c)
				} else {
					b.WriteByte(c)
				}
			}
			return b.String()
		}
	}
	return s
}

// clampTTLs caps every TTL at MaxTTL so no record can stay cached for longer.
func (r *Resolver) clampTTLs(rrs []RR) []RR {
	out := make([]RR, len(rrs))
	for i, rr := range rrs {
		if rr.TTL > r.MaxTTL {
			rr.TTL = r.MaxTTL
		}
		out[i] = rr
	}
	return out
}

func minTTL(rrs []RR) uint32 {
	m := rrs[0].TTL
	for _, rr := range rrs {
		if rr.TTL < m {
			m = rr.TTL
		}
	}
	return m
}

// evict makes room in a bounded cache: expired entries go first, then arbitrary ones.
func evict[V any](m map[string]V, max int, expired func(V) bool) {
	if len(m) < max {
		return
	}
	for k, v := range m {
		if expired(v) {
			delete(m, k)
		}
	}
	for k := range m {
		if len(m) < max {
			break
		}
		delete(m, k)
	}
}

func (r *Resolver) cacheGet(name string, t RRType) ([]RR, []RR, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name+"|"+t.String()]
	if !ok || time.Now().After(e.expires) {
		return nil, nil, false
	}
	left := uint32(time.Until(e.expires).Seconds())
	out := make([]RR, len(e.rrs))
	for i, rr := range e.rrs {
		rr.TTL = left
		out[i] = rr
	}
	return out, e.sigs, true
}

func (r *Resolver) cachePut(name string, t RRType, rrs, sigs []RR) {
	if len(rrs) == 0 {
		return
	}
	ttl := min(minTTL(rrs), r.MaxTTL)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	evict(r.cache, r.MaxCacheEntries, func(e cacheEntry) bool { return now.After(e.expires) })
	r.cache[name+"|"+t.String()] = cacheEntry{rrs, sigs, now.Add(time.Duration(ttl) * time.Second)}
}

func (r *Resolver) putZone(zone string, ns []nameserver, ttl uint32) {
	ttl = min(ttl, r.MaxTTL)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	evict(r.zoneNS, r.MaxCacheEntries, func(e zoneEntry) bool { return now.After(e.expires) })
	r.zoneNS[zone] = zoneEntry{ns, now.Add(time.Duration(ttl) * time.Second)}
}

func (r *Resolver) closestKnownZone(name string) (string, []nameserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for z := name; ; {
		if e, ok := r.zoneNS[z]; ok && len(e.ns) > 0 && now.Before(e.expires) {
			return z, e.ns
		}
		if z == "." {
			return ".", r.Roots
		}
		z = parentName(z)
	}
}

// coveredSigs returns the RRSIGs that cover records of type t.
func coveredSigs(sigs []RR, t RRType) []RR {
	var out []RR
	for _, s := range sigs {
		if len(s.Raw) >= 2 && RRType(binary.BigEndian.Uint16(s.Raw)) == t {
			out = append(out, s)
		}
	}
	return out
}

// referralNS extracts the delegation from a reply: NS records in the authority
// section, or, for a minimised NS query, NS records for qname in the answer.
func referralNS(msg *Message, qname string, probing bool) ([]RR, string) {
	var out []RR
	var child string
	if probing {
		for _, rr := range msg.Answers {
			if rr.Type == TypeNS && strings.EqualFold(rr.Name, qname) {
				out, child = append(out, rr), strings.ToLower(rr.Name)
			}
		}
		if len(out) > 0 {
			return out, child
		}
	}
	for _, rr := range msg.Authority {
		if rr.Type == TypeNS {
			out, child = append(out, rr), strings.ToLower(rr.Name)
		}
	}
	return out, child
}

// unexpectedAnswer reports whether a reply to a minimised NS query contains
// anything other than NS records for the probed name (a CNAME, for example).
func unexpectedAnswer(msg *Message, qname string) bool {
	for _, rr := range msg.Answers {
		if rr.Type == TypeRRSIG {
			continue
		}
		if rr.Type != TypeNS || !strings.EqualFold(rr.Name, qname) {
			return true
		}
	}
	return false
}

func (r *Resolver) resolve(name string, qtype RRType, depth, hops int) (*Result, error) {
	if depth > 8 {
		return nil, ErrLoop
	}
	if rrs, sigs, ok := r.cacheGet(name, qtype); ok {
		r.tracef(depth, "%s %s %s", r.c(cGreen, "✓ cache hit"), name, qtype)
		return &Result{Rcode: RcodeNoError, Answers: rrs, Sigs: sigs, Hops: hops}, nil
	}

	start := name
	if qtype == TypeDS && name != "." {
		start = parentName(name)
	}
	zone, servers := r.closestKnownZone(start)
	if zone != "." {
		r.tracef(depth, "%s starting at cached zone %s", r.c(cDim, "↷"), r.c(cBold, zone))
	}
	minimise := r.Minimise && len(splitLabels(name)) <= maxMinimiseLabels
	probe := childToward(name, zone)

	for ; hops < r.MaxHops; hops++ {
		qname, qt := name, qtype
		if minimise && probe != name {
			qname, qt = probe, TypeNS
		}
		probing := qname != name
		msg, ns, rtt, err := r.queryAny(servers, qname, qt, depth)
		if err != nil {
			return nil, fmt.Errorf("querying %s servers for %s: %w", zone, qname, err)
		}

		if probing && (msg.Header.Rcode != RcodeNoError || unexpectedAnswer(msg, qname)) {
			r.tracef(depth, "%s %s gave %s to the minimised query, asking for the full name", r.c(cYellow, "↺"), ns.Name, rcodeString(msg.Header.Rcode))
			minimise = false
			continue
		}

		if !probing {
			if msg.Header.Rcode == RcodeNXDomain {
				r.tracef(depth, "%s %s says %s (%s)", r.c(cRed, "✗"), ns.Name, r.c(cRed, "NXDOMAIN"), rtt)
				return &Result{Rcode: RcodeNXDomain, Authority: r.clampTTLs(msg.Authority), Hops: hops + 1}, nil
			}
			if msg.Header.Rcode != RcodeNoError {
				r.tracef(depth, "%s %s returned %s, trying next server", r.c(cYellow, "!"), ns.Name, rcodeString(msg.Header.Rcode))
				servers = without(servers, ns)
				if len(servers) == 0 {
					return &Result{Rcode: msg.Header.Rcode, Hops: hops + 1}, nil
				}
				continue
			}

			var direct, cnames, sigs []RR
			for _, rr := range msg.Answers {
				if !strings.EqualFold(rr.Name, name) {
					continue
				}
				rr.Zone = zone
				switch {
				case rr.Type == qtype:
					direct = append(direct, rr)
				case rr.Type == TypeCNAME:
					cnames = append(cnames, rr)
				case rr.Type == TypeRRSIG:
					sigs = append(sigs, rr)
				}
			}
			if len(direct) > 0 {
				r.tracef(depth, "%s %s answered %s (%s)", r.c(cGreen, "✓"), ns.Name,
					r.c(cGreen, fmt.Sprintf("%d %s record(s)", len(direct), qtype)), rtt)
				direct, sigs = r.clampTTLs(direct), coveredSigs(sigs, qtype)
				r.cachePut(name, qtype, direct, sigs)
				return &Result{Rcode: RcodeNoError, Answers: direct, Sigs: sigs, Hops: hops + 1}, nil
			}
			if len(cnames) > 0 {
				target := fqdn(cnames[0].Data)
				r.tracef(depth, "%s %s is an alias → %s, restarting from the top", r.c(cCyan, "↪ CNAME"), name, r.c(cBold, target))
				sub, err := r.resolve(target, qtype, depth+1, hops+1)
				if err != nil {
					return nil, err
				}
				sub.Answers = append(r.clampTTLs(cnames[:1]), sub.Answers...)
				sub.Sigs = append(coveredSigs(sigs, TypeCNAME), sub.Sigs...)
				return sub, nil
			}
			if msg.Header.AA {
				r.tracef(depth, "%s %s: name exists but has no %s records (NODATA)", r.c(cYellow, "∅"), ns.Name, qtype)
				return &Result{Rcode: RcodeNoError, Authority: r.clampTTLs(msg.Authority), Hops: hops + 1}, nil
			}
		}

		nsRRs, child := referralNS(msg, qname, probing)
		if len(nsRRs) == 0 {
			if probing && msg.Header.AA {
				r.tracef(depth, "%s %s: no zone cut at %s (%s)", r.c(cDim, "·"), ns.Name, qname, rtt)
				probe = childToward(name, probe)
				continue
			}
			return nil, fmt.Errorf("lame response from %s: no answer, no referral", ns.Name)
		}

		if !isSubdomain(name, child) || !isSubdomain(child, zone) || child == zone {
			return nil, fmt.Errorf("out-of-bailiwick referral from %s: %s is not under %s", ns.Name, child, zone)
		}

		next := r.glueFor(nsRRs, msg.Additional, zone)
		names := make([]string, 0, len(nsRRs))
		for _, rr := range nsRRs {
			names = append(names, strings.TrimSuffix(rr.Data, "."))
		}
		r.tracef(depth, "%s %s → referral to %s %s (%s)", r.c(cCyan, "↓"), ns.Name, r.c(cBold, child),
			r.c(cDim, fmt.Sprintf("[%s]", summarize(names, 3))), rtt)

		if len(next) == 0 {
			r.tracef(depth, "%s no glue for %s — resolving a nameserver's address first", r.c(cYellow, "⋯"), child)
			for i, nsrr := range shuffled(nsRRs) {
				if i >= maxGluelessLookups {
					r.tracef(depth, "%s giving up after %d nameserver lookups for %s", r.c(cYellow, "!"), maxGluelessLookups, child)
					break
				}
				sub, err := r.resolve(fqdn(nsrr.Data), TypeA, depth+1, 0)
				if err != nil || sub.Rcode != RcodeNoError {
					continue
				}
				for _, a := range sub.Answers {
					if a.Type == TypeA {
						next = append(next, nameserver{fqdn(nsrr.Data), a.Data})
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
func (r *Resolver) glueFor(nsRRs, additional []RR, askedZone string) []nameserver {
	want := map[string]bool{}
	for _, rr := range nsRRs {
		want[fqdn(rr.Data)] = true
	}
	var out []nameserver
	for _, rr := range additional {
		n := fqdn(rr.Name)
		if rr.Type == TypeA && want[n] && isSubdomain(n, askedZone) {
			out = append(out, nameserver{n, rr.Data})
		}
	}
	return out
}

// queryAny tries servers in random order until one gives a usable reply.
func (r *Resolver) queryAny(servers []nameserver, name string, qtype RRType, depth int) (*Message, nameserver, time.Duration, error) {
	var lastErr error = ErrNoServer
	for i, ns := range shuffled(servers) {
		if i >= 4 {
			break
		}
		r.tracef(depth, "%s asking %s %s for %s %s", r.c(cDim, "→"), ns.Name, r.c(cDim, "("+ns.IP+")"), name, qtype)
		t0 := time.Now()
		msg, err := r.exchange(ns.IP, name, qtype)
		rtt := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			r.tracef(depth, "%s %s: %v", r.c(cYellow, "!"), ns.Name, err)
			lastErr = err
			continue
		}
		return msg, ns, rtt, nil
	}
	return nil, nameserver{}, 0, lastErr
}

// matchesQuery is the anti-spoofing check: a reply is only accepted if it
// carries our ID and repeats exactly the question we asked.
func matchesQuery(m *Message, id uint16, name string, qtype RRType) bool {
	return m.Header.ID == id && m.Header.QR && len(m.Questions) == 1 &&
		strings.EqualFold(m.Questions[0].Name, name) && m.Questions[0].Type == qtype
}

var errCaseMismatch = errors.New("reply does not repeat the 0x20 letter case of the query")

// randomID draws a query ID from the operating system's cryptographic random source.
func randomID() uint16 {
	var b [2]byte
	crand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// randomCase flips each letter of name to upper or lower case at random
// (the 0x20 technique), adding one bit of entropy per letter to the query.
func randomCase(name string) string {
	bits := make([]byte, len(name))
	crand.Read(bits)
	b := []byte(name)
	for i, c := range b {
		if 'a' <= c|0x20 && c|0x20 <= 'z' {
			b[i] = c&^0x20 | (bits[i]&1)<<5
		}
	}
	return string(b)
}

// lowerNames normalises the names in an accepted reply, so that the random
// letter case of the query never reaches the caches or the output.
func lowerNames(m *Message) {
	for i := range m.Questions {
		m.Questions[i].Name = strings.ToLower(m.Questions[i].Name)
	}
	for _, sec := range [][]RR{m.Answers, m.Authority, m.Additional} {
		for i := range sec {
			sec[i].Name = strings.ToLower(sec[i].Name)
			switch sec[i].Type {
			case TypeNS, TypeCNAME, TypePTR, TypeMX, TypeSOA:
				sec[i].Data = strings.ToLower(sec[i].Data)
			}
		}
	}
}

func (r *Resolver) caseUnsafe(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.no0x20[ip]
	return ok && time.Now().Before(t)
}

func (r *Resolver) markCaseUnsafe(ip string) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	evict(r.no0x20, r.MaxCacheEntries, func(t time.Time) bool { return now.After(t) })
	r.no0x20[ip] = now.Add(time.Hour)
}

// exchange sends one query, with 0x20 case randomisation unless the server is
// known not to preserve case. A server that answers with different case is
// remembered for an hour and asked again without 0x20.
func (r *Resolver) exchange(ip, name string, qtype RRType) (*Message, error) {
	mixed := r.CaseRandomisation && !r.caseUnsafe(ip)
	m, err := r.exchangeOnce(ip, name, qtype, mixed)
	if errors.Is(err, errCaseMismatch) {
		r.tracef(0, "%s %s does not preserve letter case, retrying without 0x20", r.c(cYellow, "!"), ip)
		r.markCaseUnsafe(ip)
		m, err = r.exchangeOnce(ip, name, qtype, false)
	}
	return m, err
}

// exchangeOnce sends one query over UDP, retrying over TCP if the answer is truncated.
func (r *Resolver) exchangeOnce(ip, name string, qtype RRType, mixed bool) (*Message, error) {
	sent := name
	if mixed {
		sent = randomCase(name)
	}
	id := randomID()
	q, err := BuildQuery(id, sent, qtype, r.DNSSEC)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip, r.Port)

	conn, err := net.DialTimeout("udp", addr, r.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(r.Timeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		m, err := ParseMessage(buf[:n])
		if err != nil || !matchesQuery(m, id, sent, qtype) {
			continue
		}
		if mixed && m.Questions[0].Name != sent {
			return nil, errCaseMismatch
		}
		if m.Header.TC {
			r.tracef(0, "%s response truncated, retrying over TCP", r.c(cYellow, "⇄"))
			return exchangeTCP(addr, q, id, sent, qtype, r.Timeout, mixed)
		}
		lowerNames(m)
		return m, nil
	}
}

// DNS over TCP: same message, prefixed with a 2-byte length (RFC 1035 §4.2.2).
func exchangeTCP(addr string, q []byte, id uint16, name string, qtype RRType, timeout time.Duration, mixed bool) (*Message, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := conn.Write(append(frame, q...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	m, err := ParseMessage(buf)
	if err != nil {
		return nil, err
	}
	if !matchesQuery(m, id, name, qtype) {
		return nil, errors.New("TCP reply does not match the query (ID or question)")
	}
	if mixed && m.Questions[0].Name != name {
		return nil, errCaseMismatch
	}
	lowerNames(m)
	return m, nil
}

func shuffled[T any](in []T) []T {
	out := append([]T(nil), in...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func without(in []nameserver, x nameserver) []nameserver {
	var out []nameserver
	for _, s := range in {
		if s != x {
			out = append(out, s)
		}
	}
	return out
}

func summarize(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(s[:n], ", "), len(s)-n)
}
