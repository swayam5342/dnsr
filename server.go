package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

func encodeRData(rr RR) ([]byte, error) {
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR:
		return encodeName(nil, rr.Data)
	case TypeMX:
		var pref uint16
		var host string
		if _, err := fmt.Sscanf(rr.Data, "%d %s", &pref, &host); err != nil {
			return nil, err
		}
		return encodeName(binary.BigEndian.AppendUint16(nil, pref), host)
	case TypeSOA:
		f := strings.Fields(rr.Data)
		if len(f) != 7 {
			return nil, fmt.Errorf("bad SOA %q", rr.Data)
		}
		b, err := encodeName(nil, f[0])
		if err != nil {
			return nil, err
		}
		if b, err = encodeName(b, f[1]); err != nil {
			return nil, err
		}
		for _, s := range f[2:] {
			var v uint32
			fmt.Sscan(s, &v)
			b = binary.BigEndian.AppendUint32(b, v)
		}
		return b, nil
	default:
		return rr.Raw, nil
	}
}

func appendRR(b []byte, rr RR) ([]byte, error) {
	b, err := encodeName(b, rr.Name)
	if err != nil {
		return nil, err
	}
	rd, err := encodeRData(rr)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Type))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...), nil
}

func buildResponse(id uint16, q Question, rd bool, rcode int, ans, auth, add []RR) []byte {
	flags := uint16(0x8000 | 0x0080)
	if rd {
		flags |= 0x0100
	}
	flags |= uint16(rcode & 0xF)

	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	b, _ = encodeName(b, q.Name)
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, q.Class)

	var na, nn uint16
	for _, rr := range ans {
		if nb, err := appendRR(b, rr); err == nil {
			b, na = nb, na+1
		}
	}
	for _, rr := range auth {
		if nb, err := appendRR(b, rr); err == nil {
			b, nn = nb, nn+1
		}
	}
	var nr uint16
	for _, rr := range add {
		if nb, err := appendRR(b, rr); err == nil {
			b, nr = nb, nr+1
		}
	}
	binary.BigEndian.PutUint16(b[6:], na)
	binary.BigEndian.PutUint16(b[8:], nn)
	binary.BigEndian.PutUint16(b[10:], nr)
	return b
}

// Server answers DNS queries from clients using a shared Resolver. It limits
// the number of queries in flight and the query rate of each client address,
// and only serves clients whose address is in Allow (loopback when empty).
type Server struct {
	R           *Resolver
	MaxInflight int
	Rate        float64
	Burst       float64
	Allow       []netip.Prefix
	sem         chan struct{}
	mu          sync.Mutex
	buckets     map[string]*bucket
	refused     map[string]time.Time
}

var loopbackOnly = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// ParseAllow reads a comma-separated list of CIDR ranges or single addresses.
func ParseAllow(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// permitted reports whether a client address falls inside the access list.
func (s *Server) permitted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	allow := s.Allow
	if len(allow) == 0 {
		allow = loopbackOnly
	}
	for _, p := range allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// noteRefused logs a refused client at most once per minute.
func (s *Server) noteRefused(ip string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.refused[ip]) < time.Minute {
		return
	}
	if len(s.refused) > 10000 {
		clear(s.refused)
	}
	s.refused[ip] = now
	log.Printf("access list: refusing queries from %s", ip)
}

type bucket struct {
	tokens  float64
	last    time.Time
	logged  time.Time
	dropped int
}

func NewServer(r *Resolver) *Server {
	return &Server{R: r, MaxInflight: 256, Rate: 20, Burst: 40}
}

func (s *Server) init() {
	if s.sem == nil {
		s.sem = make(chan struct{}, s.MaxInflight)
		s.buckets = map[string]*bucket{}
		s.refused = map[string]time.Time{}
	}
}

// allow is a per-client token bucket: Rate queries per second, bursts up to Burst.
func (s *Server) allow(ip string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buckets) > 10000 {
		for k, b := range s.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(s.buckets, k)
			}
		}
	}
	b, ok := s.buckets[ip]
	if !ok {
		b = &bucket{tokens: s.Burst, last: now}
		s.buckets[ip] = b
	}
	b.tokens = min(s.Burst, b.tokens+now.Sub(b.last).Seconds()*s.Rate)
	b.last = now
	if b.tokens < 1 {
		if b.dropped++; now.Sub(b.logged) > time.Minute {
			log.Printf("rate limit: dropping queries from %s (%d dropped)", ip, b.dropped)
			b.logged = now
		}
		return false
	}
	b.tokens--
	return true
}

// handle turns one query into one response; nil means drop the packet.
// For UDP, a response larger than the client's buffer is truncated (TC=1).
func (s *Server) handle(pkt []byte, client string, udp bool) []byte {
	m, err := ParseMessage(pkt)
	if err != nil || len(m.Questions) != 1 || m.Header.QR {
		return nil
	}
	q := m.Questions[0]
	if !s.permitted(client) {
		s.noteRefused(client)
		return buildResponse(m.Header.ID, q, m.Header.RD, RcodeRefused, nil, nil, nil)
	}
	if !s.allow(client) {
		return nil
	}
	res, err := s.R.Resolve(q.Name, q.Type)
	var out []byte
	switch {
	case err != nil:
		log.Printf("%-30s %-5s SERVFAIL (%v)", q.Name, q.Type, err)
		out = buildResponse(m.Header.ID, q, m.Header.RD, RcodeServFail, nil, nil, nil)
	case res.Security == SecBogus:
		log.Printf("%-30s %-5s SERVFAIL (DNSSEC bogus: %s)", q.Name, q.Type, res.SecurityNote)
		out = buildResponse(m.Header.ID, q, m.Header.RD, RcodeServFail, nil, nil, nil)
	default:
		log.Printf("%-30s %-5s %-8s %d answer(s), %d hops, %s%s", q.Name, q.Type, rcodeString(res.Rcode),
			len(res.Answers), res.Hops, res.Elapsed.Round(1e6), securityTag(res))
		ans, auth := res.Answers, res.Authority
		if m.EDNS != nil && m.EDNS.DO {
			ans = append(append([]RR(nil), ans...), res.Sigs...)
		} else {
			auth = withoutDNSSEC(auth)
		}
		out = buildResponse(m.Header.ID, q, m.Header.RD, res.Rcode, ans, auth, nil)
		if res.Security == SecSecure {
			out[3] |= 0x20
		}
	}
	if limit := udpLimit(m); udp && len(out) > limit {
		out = buildResponse(m.Header.ID, q, m.Header.RD, int(out[3]&0xF), nil, nil, nil)
		out[2] |= 0x02
	}
	return out
}

// withoutDNSSEC drops RRSIG, NSEC and NSEC3 records, which only clients that set DO asked for.
func withoutDNSSEC(rrs []RR) []RR {
	var out []RR
	for _, rr := range rrs {
		if rr.Type != TypeRRSIG && rr.Type != TypeNSEC && rr.Type != TypeNSEC3 {
			out = append(out, rr)
		}
	}
	return out
}

func securityTag(res *Result) string {
	if res.Security == SecUnchecked {
		return ""
	}
	return ", dnssec " + res.Security.String()
}

// udpLimit is the largest UDP response the client accepts: 512 bytes, or its EDNS size up to 1232.
func udpLimit(m *Message) int {
	if m.EDNS == nil || m.EDNS.UDPSize < 512 {
		return 512
	}
	return min(int(m.EDNS.UDPSize), 1232)
}

func hostOf(addr net.Addr) string {
	h, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return h
}

// ServeUDP answers queries on a UDP socket; when MaxInflight queries are
// already being resolved, new packets are dropped instead of queued.
func (s *Server) ServeUDP(pc net.PacketConn) error {
	s.init()
	buf := make([]byte, 1500)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
		default:
			continue
		}
		go func() {
			defer func() { <-s.sem }()
			if out := s.handle(pkt, hostOf(client), true); out != nil {
				pc.WriteTo(out, client)
			}
		}()
	}
}

// ServeStream answers length-prefixed queries on TCP or TLS connections (RFC 7766, RFC 7858).
func (s *Server) ServeStream(ln net.Listener) error {
	s.init()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-s.sem }()
			defer c.Close()
			client := hostOf(c.RemoteAddr())
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				pkt := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, pkt); err != nil {
					return
				}
				out := s.handle(pkt, client, false)
				if out == nil {
					return
				}
				if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil {
					return
				}
			}
		}()
	}
}

// dotConfig is the TLS configuration for DNS over TLS: TLS 1.3 only.
func dotConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}

// selfSignedCert creates an in-memory ECDSA certificate for localhost, for testing DoT.
func selfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "dnsr"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fmt.Sprintf("%X", sum), nil
}

type ServeConfig struct {
	Addr       string
	DoTAddr    string
	CertFile   string
	KeyFile    string
	SelfSigned bool
}

// serve listens on UDP and TCP at cfg.Addr and, if cfg.DoTAddr is set, on DNS over TLS.
func serve(cfg ServeConfig, s *Server) error {
	pc, err := net.ListenPacket("udp", cfg.Addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	log.Printf("dnsr listening on udp+tcp://%s — try: dig @%s -p %s example.com", pc.LocalAddr(), host, port)
	allowed := s.Allow
	if len(allowed) == 0 {
		allowed = loopbackOnly
	}
	log.Printf("accepting clients from %v (change with -allow)", allowed)
	errs := make(chan error, 3)
	go func() { errs <- s.ServeUDP(pc) }()
	go func() { errs <- s.ServeStream(ln) }()

	if cfg.DoTAddr != "" {
		var cert tls.Certificate
		switch {
		case cfg.CertFile != "":
			if cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
				return err
			}
		case cfg.SelfSigned:
			var fp string
			if cert, fp, err = selfSignedCert(); err != nil {
				return err
			}
			log.Printf("self-signed certificate, SHA-256 fingerprint %s", fp)
		default:
			return fmt.Errorf("DoT needs -cert and -key, or -selfsigned")
		}
		tl, err := tls.Listen("tcp", cfg.DoTAddr, dotConfig(cert))
		if err != nil {
			return err
		}
		log.Printf("dnsr listening on DNS over TLS %s", tl.Addr())
		go func() { errs <- s.ServeStream(tl) }()
	}
	return <-errs
}
