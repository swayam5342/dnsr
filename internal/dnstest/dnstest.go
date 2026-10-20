// Package dnstest is a fake DNS hierarchy on loopback (127.0.0.10–15) so the
// full iterative walk can be tested offline and deterministically:
//
//	.            127.0.0.10  → delegates com., org.
//	com.         127.0.0.11  → delegates example.com. (with glue), glueless.com. (no glue)
//	example.com. 127.0.0.12  → authoritative: www, alias (CNAME), mail (MX), big (TC→TCP)
//	org.         127.0.0.13  → delegates dnshost.org.
//	dnshost.org. 127.0.0.14  → ns.dnshost.org A 127.0.0.15
//	glueless.com 127.0.0.15  → authoritative, its NS lives under .org
package dnstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swayam5342/dnsr/internal/wire"
)

const RootIP = "127.0.0.10"

type Zone struct {
	origin  string
	records []wire.RR
	deleg   map[string][]wire.RR
	glue    []wire.RR
	tcOnUDP map[string]bool
	signer  *Signer
	tamper  map[string]string
	forge   map[string]bool
	badTCP  map[string]bool
	NoCase  bool
	mu      sync.Mutex
	seen    []wire.Question
	raw     []string
}

func A(name, ip string) wire.RR {
	return wire.RR{Name: name, Type: wire.TypeA, Class: 1, TTL: 300, Data: ip, Raw: net.ParseIP(ip).To4()}
}

func NS(zone, host string) wire.RR {
	return wire.RR{Name: zone, Type: wire.TypeNS, Class: 1, TTL: 3600, Data: host}
}

type Signer struct {
	zone string
	key  *ecdsa.PrivateKey
	RR   wire.RR
	Tag  uint16
}

func NewSigner(zone string) *Signer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := k.PublicKey.Bytes()
	rd := append([]byte{0x01, 0x01, 3, 13}, pub[1:]...)
	return &Signer{zone, k, wire.RR{Name: zone, Type: wire.TypeDNSKEY, Class: 1, TTL: 3600, Raw: rd}, wire.KeyTag(rd)}
}

func (s *Signer) DS() wire.RR {
	owner, _ := wire.EncodeName(nil, s.zone)
	sum := sha256.Sum256(append(owner, s.RR.Raw...))
	rd := append(binary.BigEndian.AppendUint16(nil, s.Tag), 13, 2)
	return wire.RR{Name: s.zone, Type: wire.TypeDS, Class: 1, TTL: 3600, Raw: append(rd, sum[:]...)}
}

func (s *Signer) Anchor() wire.DS {
	d, _ := wire.ParseDS(s.DS())
	return d
}

func (s *Signer) Sign(set []wire.RR) wire.RR {
	now := uint32(time.Now().Unix())
	sig := &wire.RRSIG{TypeCovered: set[0].Type, Algorithm: 13, Labels: uint8(wire.LabelCount(set[0].Name)), OrigTTL: set[0].TTL,
		Expiration: now + 3600, Inception: now - 3600, KeyTag: s.Tag, Signer: s.zone}
	data, _ := wire.SignedData(sig, set)
	h := sha256.Sum256(data)
	der, _ := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	sb := rawECDSASignature(der, 32)
	return wire.RR{Name: set[0].Name, Type: wire.TypeRRSIG, Class: 1, TTL: set[0].TTL, Raw: append(sig.Prefix(), sb...)}
}

// rawECDSASignature converts an ASN.1 ECDSA signature to the fixed-size r||s form DNSSEC uses.
func rawECDSASignature(der []byte, size int) []byte {
	var sig struct{ R, S *big.Int }
	asn1.Unmarshal(der, &sig)
	return append(sig.R.FillBytes(make([]byte, size)), sig.S.FillBytes(make([]byte, size))...)
}

// withSigs signs each RRset of an answer, then applies any tampering, so a
// tampered record carries a signature over the original data.
func (z *Zone) withSigs(an []wire.RR) []wire.RR {
	if z.signer != nil && len(an) > 0 {
		var order []wire.RRType
		sets := map[wire.RRType][]wire.RR{}
		for _, rr := range an {
			if _, ok := sets[rr.Type]; !ok {
				order = append(order, rr.Type)
			}
			sets[rr.Type] = append(sets[rr.Type], rr)
		}
		for _, t := range order {
			an = append(an, z.signer.Sign(sets[t]))
		}
	}
	for i := range an {
		if v, ok := z.tamper[an[i].Name]; ok && an[i].Type == wire.TypeA {
			an[i].Data, an[i].Raw = v, net.ParseIP(v).To4()
		}
	}
	return an
}

func (z *Zone) RawNames() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.raw...)
}

func (z *Zone) Questions() []wire.Question {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]wire.Question(nil), z.seen...)
}

func (z *Zone) answer(q wire.Question, udp bool) []byte {
	z.mu.Lock()
	z.seen = append(z.seen, q)
	z.mu.Unlock()
	resp := func(rcode int, aa, tc bool, an, au, ad []wire.RR) []byte {
		b := wire.BuildResponse(0, q, false, rcode, an, au, ad)
		if aa {
			b[2] |= 0x04
		}
		if tc {
			b[2] |= 0x02
		}
		return b
	}
	soa := wire.RR{Name: z.origin, Type: wire.TypeSOA, Class: 1, TTL: 60,
		Data: "ns." + z.origin + " admin." + z.origin + " 1 7200 900 1209600 60"}

	if _, cut := z.deleg[q.Name]; cut && q.Type == wire.TypeDS {
		var ds []wire.RR
		for _, rr := range z.records {
			if rr.Name == q.Name && rr.Type == wire.TypeDS {
				ds = append(ds, rr)
			}
		}
		if len(ds) == 0 {
			return resp(0, true, false, nil, []wire.RR{soa}, nil)
		}
		return resp(0, true, false, z.withSigs(ds), nil, nil)
	}
	for child, nsrrs := range z.deleg {
		if wire.IsSubdomain(q.Name, child) {
			return resp(0, false, false, nil, nsrrs, z.glue)
		}
	}
	var exists bool
	var an []wire.RR
	for _, rr := range z.records {
		if rr.Name != q.Name {
			continue
		}
		exists = true
		if rr.Type == q.Type || rr.Type == wire.TypeCNAME {
			an = append(an, rr)
		}
	}
	if !exists {
		return resp(wire.RcodeNXDomain, true, false, nil, z.withSigs([]wire.RR{soa}), nil)
	}
	if udp && z.tcOnUDP[q.Name] {
		return resp(0, true, true, nil, nil, nil)
	}
	if len(an) == 0 {
		return resp(0, true, false, nil, []wire.RR{soa}, nil)
	}
	return resp(0, true, false, z.withSigs(an), nil, nil)
}

func (z *Zone) serve(pc net.PacketConn, ln net.Listener) {
	reply := func(pkt []byte, udp bool) []byte {
		m, err := wire.ParseMessage(pkt)
		if err != nil || len(m.Questions) != 1 {
			return nil
		}
		q := m.Questions[0]
		asked := q.Name
		q.Name = strings.ToLower(asked)
		z.mu.Lock()
		z.raw = append(z.raw, asked)
		z.mu.Unlock()
		if !udp && z.badTCP[q.Name] {
			q.Name = "evil." + q.Name
		}
		out := z.answer(q, udp)
		if !z.NoCase && q.Name == strings.ToLower(asked) {
			enc, _ := wire.EncodeName(nil, asked)
			copy(out[12:], enc)
		}
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
			if m, err := wire.ParseMessage(buf[:n]); err == nil && len(m.Questions) == 1 && z.forge[strings.ToLower(m.Questions[0].Name)] {
				q := m.Questions[0]
				forged := wire.BuildResponse(m.Header.ID^0xFFFF, q, false, 0, []wire.RR{A(q.Name, "6.6.6.6")}, nil, nil)
				pc.WriteTo(forged, from)
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

type Net struct {
	Port  string
	Zones map[string]*Zone
	Root  *Signer
}

var zoneIPs = map[string]string{"127.0.0.10": ".", "127.0.0.11": "com.", "127.0.0.12": "example.com.",
	"127.0.0.13": "org.", "127.0.0.14": "dnshost.org.", "127.0.0.15": "glueless.com."}

// listenAll binds UDP and TCP on every zone address at one port, picking a
// random free port so test binaries of different packages can run in parallel.
func listenAll(t *testing.T) (string, map[string]net.PacketConn, map[string]net.Listener) {
	t.Helper()
	for range 50 {
		port := strconv.Itoa(20000 + mrand.IntN(40000))
		pcs, lns := map[string]net.PacketConn{}, map[string]net.Listener{}
		var err error
		for ip := range zoneIPs {
			addr := net.JoinHostPort(ip, port)
			if pcs[ip], err = net.ListenPacket("udp", addr); err != nil {
				break
			}
			if lns[ip], err = net.Listen("tcp", addr); err != nil {
				break
			}
		}
		if err == nil {
			return port, pcs, lns
		}
		for _, c := range pcs {
			if c != nil {
				c.Close()
			}
		}
		for _, l := range lns {
			if l != nil {
				l.Close()
			}
		}
	}
	t.Skip("cannot bind the fake hierarchy on 127.0.0.10-15")
	return "", nil, nil
}

func Start(t *testing.T) *Net {
	rootKey, comKey, exKey := NewSigner("."), NewSigner("com."), NewSigner("example.com.")
	many := []wire.RR{}
	for i := range 40 {
		many = append(many, A("many.example.com.", fmt.Sprintf("10.1.2.%d", i+1)))
	}
	var fanout []wire.RR
	for i := range 8 {
		fanout = append(fanout, NS("fanout.com.", fmt.Sprintf("ns%d.nowhere.org.", i+1)))
	}
	huge := A("huge.example.com.", "10.7.7.7")
	huge.TTL = 4000000000

	zones := map[string]*Zone{
		".": {origin: ".",
			records: []wire.RR{rootKey.RR, comKey.DS()},
			deleg: map[string][]wire.RR{
				"com.": {NS("com.", "ns.gtld.com.")},
				"org.": {NS("org.", "ns.org.")},
			},
			glue:   []wire.RR{A("ns.gtld.com.", "127.0.0.11"), A("ns.org.", "127.0.0.13")},
			signer: rootKey,
		},
		"com.": {origin: "com.",
			records: []wire.RR{comKey.RR, exKey.DS()},
			deleg: map[string][]wire.RR{
				"example.com.":  {NS("example.com.", "ns1.example.com.")},
				"glueless.com.": {NS("glueless.com.", "ns.dnshost.org.")},
				"trap.com.":     {NS("net.", "ns.evil.net.")},
				"fanout.com.":   fanout,
			},
			glue: []wire.RR{
				A("ns1.example.com.", "127.0.0.12"),
				A("ns.dnshost.org.", "6.6.6.6"),
			},
			signer: comKey,
		},
		"example.com.": {origin: "example.com.",
			records: append([]wire.RR{
				exKey.RR,
				A("www.example.com.", "93.184.216.34"),
				{Name: "alias.example.com.", Type: wire.TypeCNAME, Class: 1, TTL: 300, Data: "www.example.com."},
				{Name: "example.com.", Type: wire.TypeMX, Class: 1, TTL: 300, Data: "10 mail.example.com."},
				A("mail.example.com.", "93.184.216.35"),
				A("big.example.com.", "10.9.9.9"),
				A("badtcp.example.com.", "10.9.9.8"),
				A("forged.example.com.", "10.1.1.1"),
				A("tampered.example.com.", "10.2.2.2"),
				huge,
			}, many...),
			tcOnUDP: map[string]bool{"big.example.com.": true, "badtcp.example.com.": true},
			badTCP:  map[string]bool{"badtcp.example.com.": true},
			forge:   map[string]bool{"forged.example.com.": true},
			tamper:  map[string]string{"tampered.example.com.": "6.6.6.6"},
			signer:  exKey,
		},
		"org.": {origin: "org.",
			deleg: map[string][]wire.RR{"dnshost.org.": {NS("dnshost.org.", "ns.dnshost.org.")}},
			glue:  []wire.RR{A("ns.dnshost.org.", "127.0.0.14")},
		},
		"dnshost.org.": {origin: "dnshost.org.",
			records: []wire.RR{A("ns.dnshost.org.", "127.0.0.15")},
		},
		"glueless.com.": {origin: "glueless.com.",
			records: []wire.RR{A("glueless.com.", "10.0.0.1")},
		},
	}
	port, pcs, lns := listenAll(t)
	for ip, z := range zoneIPs {
		pc, ln := pcs[ip], lns[ip]
		t.Cleanup(func() { pc.Close(); ln.Close() })
		zones[z].serve(pc, ln)
	}
	return &Net{Port: port, Zones: zones, Root: rootKey}
}
