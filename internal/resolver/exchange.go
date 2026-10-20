package resolver

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/swayam5342/dnsr/internal/term"
	"github.com/swayam5342/dnsr/internal/wire"
)

// queryAny tries servers in random order until one gives a usable reply.
func (r *Resolver) queryAny(servers []Nameserver, name string, qtype wire.RRType, depth int) (*wire.Message, Nameserver, time.Duration, error) {
	var lastErr error = ErrNoServer
	for i, ns := range shuffled(servers) {
		if i >= 4 {
			break
		}
		r.tracef(depth, "%s asking %s %s for %s %s", r.c(term.Dim, "→"), ns.Name, r.c(term.Dim, "("+ns.IP+")"), name, qtype)
		t0 := time.Now()
		msg, err := r.exchange(ns.IP, name, qtype)
		rtt := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			r.tracef(depth, "%s %s: %v", r.c(term.Yellow, "!"), ns.Name, err)
			lastErr = err
			continue
		}
		return msg, ns, rtt, nil
	}
	return nil, Nameserver{}, 0, lastErr
}

// matchesQuery is the anti-spoofing check: a reply is only accepted if it
// carries our ID and repeats exactly the question we asked.
func matchesQuery(m *wire.Message, id uint16, name string, qtype wire.RRType) bool {
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
func lowerNames(m *wire.Message) {
	for i := range m.Questions {
		m.Questions[i].Name = strings.ToLower(m.Questions[i].Name)
	}
	for _, sec := range [][]wire.RR{m.Answers, m.Authority, m.Additional} {
		for i := range sec {
			sec[i].Name = strings.ToLower(sec[i].Name)
			switch sec[i].Type {
			case wire.TypeNS, wire.TypeCNAME, wire.TypePTR, wire.TypeMX, wire.TypeSOA:
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
func (r *Resolver) exchange(ip, name string, qtype wire.RRType) (*wire.Message, error) {
	mixed := r.CaseRandomisation && !r.caseUnsafe(ip)
	m, err := r.exchangeOnce(ip, name, qtype, mixed)
	if errors.Is(err, errCaseMismatch) {
		r.tracef(0, "%s %s does not preserve letter case, retrying without 0x20", r.c(term.Yellow, "!"), ip)
		r.markCaseUnsafe(ip)
		m, err = r.exchangeOnce(ip, name, qtype, false)
	}
	return m, err
}

// exchangeOnce sends one query over UDP, retrying over TCP if the answer is truncated.
func (r *Resolver) exchangeOnce(ip, name string, qtype wire.RRType, mixed bool) (*wire.Message, error) {
	sent := name
	if mixed {
		sent = randomCase(name)
	}
	id := randomID()
	q, err := wire.BuildQuery(id, sent, qtype, r.DNSSEC)
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
		m, err := wire.ParseMessage(buf[:n])
		if err != nil || !matchesQuery(m, id, sent, qtype) {
			continue
		}
		if mixed && m.Questions[0].Name != sent {
			return nil, errCaseMismatch
		}
		if m.Header.TC {
			r.tracef(0, "%s response truncated, retrying over TCP", r.c(term.Yellow, "⇄"))
			return exchangeTCP(addr, q, id, sent, qtype, r.Timeout, mixed)
		}
		lowerNames(m)
		return m, nil
	}
}

// DNS over TCP: same message, prefixed with a 2-byte length (RFC 1035 §4.2.2).
func exchangeTCP(addr string, q []byte, id uint16, name string, qtype wire.RRType, timeout time.Duration, mixed bool) (*wire.Message, error) {
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
	m, err := wire.ParseMessage(buf)
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
