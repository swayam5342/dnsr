package server

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/swayam5342/dnsr/internal/resolver"
	"github.com/swayam5342/dnsr/internal/wire"
)

// Server answers DNS queries from clients using a shared Resolver. It limits
// the number of queries in flight and the query rate of each client address,
// and only serves clients whose address is in Allow (loopback when empty).
type Server struct {
	R           *resolver.Resolver
	MaxInflight int
	Rate        float64
	Burst       float64
	Allow       []netip.Prefix
	sem         chan struct{}
	mu          sync.Mutex
	buckets     map[string]*bucket
	refused     map[string]time.Time
}

func New(r *resolver.Resolver) *Server {
	return &Server{R: r, MaxInflight: 256, Rate: 20, Burst: 40}
}

func (s *Server) init() {
	if s.sem == nil {
		s.sem = make(chan struct{}, s.MaxInflight)
		s.buckets = map[string]*bucket{}
		s.refused = map[string]time.Time{}
	}
}

// handle turns one query into one response; nil means drop the packet.
// For UDP, a response larger than the client's buffer is truncated (TC=1).
func (s *Server) handle(pkt []byte, client string, udp bool) []byte {
	m, err := wire.ParseMessage(pkt)
	if err != nil || len(m.Questions) != 1 || m.Header.QR {
		return nil
	}
	q := m.Questions[0]
	if !s.permitted(client) {
		s.noteRefused(client)
		return wire.BuildResponse(m.Header.ID, q, m.Header.RD, wire.RcodeRefused, nil, nil, nil)
	}
	if !s.allow(client) {
		return nil
	}
	res, err := s.R.Resolve(q.Name, q.Type)
	var out []byte
	switch {
	case err != nil:
		log.Printf("%-30s %-5s SERVFAIL (%v)", q.Name, q.Type, err)
		out = wire.BuildResponse(m.Header.ID, q, m.Header.RD, wire.RcodeServFail, nil, nil, nil)
	case res.Security == resolver.SecBogus:
		log.Printf("%-30s %-5s SERVFAIL (DNSSEC bogus: %s)", q.Name, q.Type, res.SecurityNote)
		out = wire.BuildResponse(m.Header.ID, q, m.Header.RD, wire.RcodeServFail, nil, nil, nil)
	default:
		log.Printf("%-30s %-5s %-8s %d answer(s), %d hops, %s%s", q.Name, q.Type, wire.RcodeString(res.Rcode),
			len(res.Answers), res.Hops, res.Elapsed.Round(1e6), securityTag(res))
		ans, auth := res.Answers, res.Authority
		if m.EDNS != nil && m.EDNS.DO {
			ans = append(append([]wire.RR(nil), ans...), res.Sigs...)
		} else {
			auth = withoutDNSSEC(auth)
		}
		out = wire.BuildResponse(m.Header.ID, q, m.Header.RD, res.Rcode, ans, auth, nil)
		if res.Security == resolver.SecSecure {
			out[3] |= 0x20
		}
	}
	if limit := udpLimit(m); udp && len(out) > limit {
		out = wire.BuildResponse(m.Header.ID, q, m.Header.RD, int(out[3]&0xF), nil, nil, nil)
		out[2] |= 0x02
	}
	return out
}

// withoutDNSSEC drops RRSIG, NSEC and NSEC3 records, which only clients that set DO asked for.
func withoutDNSSEC(rrs []wire.RR) []wire.RR {
	var out []wire.RR
	for _, rr := range rrs {
		if rr.Type != wire.TypeRRSIG && rr.Type != wire.TypeNSEC && rr.Type != wire.TypeNSEC3 {
			out = append(out, rr)
		}
	}
	return out
}

func securityTag(res *resolver.Result) string {
	if res.Security == resolver.SecUnchecked {
		return ""
	}
	return ", dnssec " + res.Security.String()
}

// udpLimit is the largest UDP response the client accepts: 512 bytes, or its EDNS size up to 1232.
func udpLimit(m *wire.Message) int {
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
