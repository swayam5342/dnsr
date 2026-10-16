package main

// resolver.go — iterative resolution, the way a real recursor does it:
//
//   root (.)  ──referral──▶  TLD (com.)  ──referral──▶  example.com. NS  ──▶ answer
//
// We start from hard-coded root hints, send non-recursive queries, and follow
// referrals (NS in Authority + glue in Additional) until someone answers
// authoritatively. CNAMEs are chased, glueless delegations are resolved
// with a nested lookup, and truncated UDP responses fall back to TCP.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
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

type nameserver struct {
	Name string
	IP   string
}

type Result struct {
	Rcode     int
	Answers   []RR
	Authority []RR
	Hops      int
	Elapsed   time.Duration
}

type cacheEntry struct {
	rrs     []RR
	expires time.Time
}

type Resolver struct {
	Timeout time.Duration
	MaxHops int
	Trace   io.Writer
	Port    string
	Roots   []nameserver
	color   bool
	mu      sync.Mutex
	cache   map[string]cacheEntry
	zoneNS  map[string][]nameserver
}

func NewResolver() *Resolver {
	return &Resolver{
		Timeout: 2 * time.Second,
		MaxHops: 40,
		Port:    "53",
		Roots:   rootHints,
		cache:   map[string]cacheEntry{},
		zoneNS:  map[string][]nameserver{},
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

func (r *Resolver) Resolve(name string, qtype RRType) (*Result, error) {
	start := time.Now()
	res, err := r.resolve(fqdn(name), qtype, 0, 0)
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
	return code + s + cReset
}

func (r *Resolver) tracef(depth int, format string, a ...any) {
	if r.Trace == nil {
		return
	}
	fmt.Fprintf(r.Trace, "%s%s\n", strings.Repeat("  │ ", depth), fmt.Sprintf(format, a...))
}

func (r *Resolver) cacheGet(name string, t RRType) ([]RR, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name+"|"+t.String()]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	left := uint32(time.Until(e.expires).Seconds())
	out := make([]RR, len(e.rrs))
	for i, rr := range e.rrs {
		rr.TTL = left
		out[i] = rr
	}
	return out, true
}

func (r *Resolver) cachePut(name string, t RRType, rrs []RR) {
	if len(rrs) == 0 {
		return
	}
	min := rrs[0].TTL
	for _, rr := range rrs {
		if rr.TTL < min {
			min = rr.TTL
		}
	}
	r.mu.Lock()
	r.cache[name+"|"+t.String()] = cacheEntry{rrs, time.Now().Add(time.Duration(min) * time.Second)}
	r.mu.Unlock()
}

func (r *Resolver) closestKnownZone(name string) (string, []nameserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for z := name; ; {
		if ns, ok := r.zoneNS[z]; ok && len(ns) > 0 {
			return z, ns
		}
		if z == "." {
			return ".", r.Roots
		}
		if i := strings.IndexByte(z, '.'); i >= 0 && i+1 < len(z) {
			z = z[i+1:]
		} else {
			z = "."
		}
	}
}

func (r *Resolver) resolve(name string, qtype RRType, depth, hops int) (*Result, error) {
	if depth > 8 {
		return nil, ErrLoop
	}
	if rrs, ok := r.cacheGet(name, qtype); ok {
		r.tracef(depth, "%s %s %s", r.c(cGreen, "✓ cache hit"), name, qtype)
		return &Result{Rcode: RcodeNoError, Answers: rrs, Hops: hops}, nil
	}

	zone, servers := r.closestKnownZone(name)
	if zone != "." {
		r.tracef(depth, "%s starting at cached zone %s", r.c(cDim, "↷"), r.c(cBold, zone))
	}

	for ; hops < r.MaxHops; hops++ {
		msg, ns, rtt, err := r.queryAny(servers, name, qtype, depth)
		if err != nil {
			return nil, fmt.Errorf("querying %s servers for %s: %w", zone, name, err)
		}
		if msg.Header.Rcode == RcodeNXDomain {
			r.tracef(depth, "%s %s says %s (%s)", r.c(cRed, "✗"), ns.Name, r.c(cRed, "NXDOMAIN"), rtt)
			return &Result{Rcode: RcodeNXDomain, Authority: msg.Authority, Hops: hops + 1}, nil
		}
		if msg.Header.Rcode != RcodeNoError {
			r.tracef(depth, "%s %s returned %s, trying next server", r.c(cYellow, "!"), ns.Name, rcodeString(msg.Header.Rcode))
			servers = without(servers, ns)
			if len(servers) == 0 {
				return &Result{Rcode: msg.Header.Rcode, Hops: hops + 1}, nil
			}
			continue
		}

		if len(msg.Answers) > 0 {
			var direct, cnames []RR
			for _, rr := range msg.Answers {
				if !strings.EqualFold(rr.Name, name) {
					continue
				}
				if rr.Type == qtype {
					direct = append(direct, rr)
				} else if rr.Type == TypeCNAME {
					cnames = append(cnames, rr)
				}
			}
			if len(direct) > 0 {
				r.tracef(depth, "%s %s answered %s (%s)", r.c(cGreen, "✓"), ns.Name,
					r.c(cGreen, fmt.Sprintf("%d %s record(s)", len(direct), qtype)), rtt)
				r.cachePut(name, qtype, direct)
				return &Result{Rcode: RcodeNoError, Answers: direct, Hops: hops + 1}, nil
			}
			if len(cnames) > 0 {
				target := fqdn(cnames[0].Data)
				r.tracef(depth, "%s %s is an alias → %s, restarting from the top", r.c(cCyan, "↪ CNAME"), name, r.c(cBold, target))
				sub, err := r.resolve(target, qtype, depth+1, hops+1)
				if err != nil {
					return nil, err
				}
				sub.Answers = append([]RR{cnames[0]}, sub.Answers...)
				return sub, nil
			}
		}
		if msg.Header.AA {
			r.tracef(depth, "%s %s: name exists but has no %s records (NODATA)", r.c(cYellow, "∅"), ns.Name, qtype)
			return &Result{Rcode: RcodeNoError, Authority: msg.Authority, Hops: hops + 1}, nil
		}

		var nsRRs []RR
		var child string
		for _, rr := range msg.Authority {
			if rr.Type == TypeNS {
				nsRRs = append(nsRRs, rr)
				child = strings.ToLower(rr.Name)
			}
		}
		if len(nsRRs) == 0 {
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
			for _, nsrr := range shuffled(nsRRs) {
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

		r.mu.Lock()
		r.zoneNS[child] = next
		r.mu.Unlock()
		zone, servers = child, next
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

// exchange sends one query over UDP, retrying over TCP if the answer is truncated.
func (r *Resolver) exchange(ip, name string, qtype RRType) (*Message, error) {
	id := uint16(rand.Uint32())
	q, err := BuildQuery(id, name, qtype)
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
		if err != nil {
			return nil, err
		}
		if m.Header.ID != id || !m.Header.QR || len(m.Questions) != 1 ||
			!strings.EqualFold(m.Questions[0].Name, name) || m.Questions[0].Type != qtype {
			continue
		}
		if m.Header.TC {
			r.tracef(0, "%s response truncated, retrying over TCP", r.c(cYellow, "⇄"))
			return exchangeTCP(addr, q, id, r.Timeout)
		}
		return m, nil
	}
}

// DNS over TCP: same message, prefixed with a 2-byte length (RFC 1035 §4.2.2).
func exchangeTCP(addr string, q []byte, id uint16, timeout time.Duration) (*Message, error) {
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
	if m.Header.ID != id {
		return nil, errors.New("TCP response ID mismatch")
	}
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
