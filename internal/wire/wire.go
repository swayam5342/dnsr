// Package wire is the RFC 1035 message format, hand-rolled. No net/dns helpers.
//
//	+---------------------+
//	|        Header       |  12 bytes: ID, flags, 4 counts
//	+---------------------+
//	|       Question      |  QNAME QTYPE QCLASS
//	+---------------------+
//	|        Answer       |  RRs
//	+---------------------+
//	|      Authority      |  RRs (NS records on a referral)
//	+---------------------+
//	|      Additional     |  RRs (glue A/AAAA for those NS)
//	+---------------------+
package wire

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type RRType uint16

const (
	TypeA      RRType = 1
	TypeNS     RRType = 2
	TypeCNAME  RRType = 5
	TypeSOA    RRType = 6
	TypePTR    RRType = 12
	TypeMX     RRType = 15
	TypeTXT    RRType = 16
	TypeAAAA   RRType = 28
	TypeOPT    RRType = 41
	TypeDS     RRType = 43
	TypeRRSIG  RRType = 46
	TypeNSEC   RRType = 47
	TypeDNSKEY RRType = 48
	TypeNSEC3  RRType = 50
)

var typeNames = map[RRType]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT",
	TypeDS: "DS", TypeRRSIG: "RRSIG", TypeNSEC: "NSEC", TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3",
}

func (t RRType) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", uint16(t))
}

func ParseType(s string) (RRType, error) {
	s = strings.ToUpper(s)
	for t, n := range typeNames {
		if n == s {
			return t, nil
		}
	}
	return 0, fmt.Errorf("unknown record type %q", s)
}

const (
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func RcodeString(r int) string {
	if r < len(rcodeNames) {
		return rcodeNames[r]
	}
	return fmt.Sprintf("RCODE%d", r)
}

type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	AD      bool
	CD      bool
	Rcode   int
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  RRType
	Class uint16
}

type RR struct {
	Name  string
	Type  RRType
	Class uint16
	TTL   uint32
	Data  string
	Raw   []byte
	Zone  string
}

func (r RR) String() string {
	return fmt.Sprintf("%-28s %6d IN %-5s %s", r.Name, r.TTL, r.Type, r.Data)
}

type EDNS struct {
	UDPSize uint16
	DO      bool
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
	EDNS       *EDNS
}

var errShort = errors.New("message truncated")

// ReadName decodes a possibly-compressed name starting at off.
// Returns the name and the offset just past it in the *original* stream.
func ReadName(msg []byte, off int) (string, int, error) {
	var labels []string
	end, total := -1, 1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, errShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, ".") + ".", end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errShort
			}
			if end < 0 {
				end = off + 2
			}
			jumps++
			if jumps > 64 {
				return "", 0, errors.New("compression pointer loop")
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, fmt.Errorf("unsupported label type 0x%x", l)
		default:
			off++
			if off+l > len(msg) {
				return "", 0, errShort
			}
			if total += l + 1; total > 255 {
				return "", 0, errors.New("name longer than 255 bytes")
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		}
	}
}

func readRR(msg []byte, off int) (RR, int, error) {
	var rr RR
	var err error
	if rr.Name, off, err = ReadName(msg, off); err != nil {
		return rr, 0, err
	}
	if off+10 > len(msg) {
		return rr, 0, errShort
	}
	rr.Type = RRType(binary.BigEndian.Uint16(msg[off:]))
	rr.Class = binary.BigEndian.Uint16(msg[off+2:])
	rr.TTL = binary.BigEndian.Uint32(msg[off+4:])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if off+rdlen > len(msg) {
		return rr, 0, errShort
	}
	rd := msg[off : off+rdlen]
	rr.Raw = rd

	switch rr.Type {
	case TypeA:
		if rdlen == 4 {
			rr.Data = net.IP(rd).String()
		}
	case TypeAAAA:
		if rdlen == 16 {
			rr.Data = net.IP(rd).String()
		}
	case TypeNS, TypeCNAME, TypePTR:
		rr.Data, _, err = ReadName(msg, off)
	case TypeMX:
		if rdlen >= 3 {
			var host string
			host, _, err = ReadName(msg, off+2)
			rr.Data = fmt.Sprintf("%d %s", binary.BigEndian.Uint16(rd), host)
		}
	case TypeSOA:
		var mname, rname string
		var p int
		if mname, p, err = ReadName(msg, off); err == nil {
			if rname, p, err = ReadName(msg, p); err == nil && p+20 <= off+rdlen {
				rr.Data = fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname,
					binary.BigEndian.Uint32(msg[p:]), binary.BigEndian.Uint32(msg[p+4:]),
					binary.BigEndian.Uint32(msg[p+8:]), binary.BigEndian.Uint32(msg[p+12:]),
					binary.BigEndian.Uint32(msg[p+16:]))
			}
		}
	case TypeTXT:
		var parts []string
		for i := 0; i < len(rd); {
			n := int(rd[i])
			i++
			if i+n > len(rd) {
				break
			}
			parts = append(parts, fmt.Sprintf("%q", rd[i:i+n]))
			i += n
		}
		rr.Data = strings.Join(parts, " ")
	case TypeDS:
		if rdlen > 4 {
			rr.Data = fmt.Sprintf("%d %d %d %X", binary.BigEndian.Uint16(rd), rd[2], rd[3], rd[4:])
		}
	case TypeDNSKEY:
		if rdlen > 4 {
			rr.Data = fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rd), rd[2], rd[3], base64.StdEncoding.EncodeToString(rd[4:]))
		}
	case TypeRRSIG:
		if s, perr := ParseRRSIG(rd); perr == nil {
			ts := func(v uint32) string { return time.Unix(int64(v), 0).UTC().Format("20060102150405") }
			rr.Data = fmt.Sprintf("%s %d %d %d %s %s %d %s %s", s.TypeCovered, s.Algorithm, s.Labels, s.OrigTTL,
				ts(s.Expiration), ts(s.Inception), s.KeyTag, s.Signer, base64.StdEncoding.EncodeToString(s.Signature))
		}
	default:
		rr.Data = fmt.Sprintf("\\# %d %x", rdlen, rd)
	}
	if err != nil {
		return rr, 0, err
	}
	return rr, off + rdlen, nil
}

func ParseMessage(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, errShort
	}
	m := &Message{}
	f := binary.BigEndian.Uint16(msg[2:])
	m.Header = Header{
		ID:      binary.BigEndian.Uint16(msg[0:]),
		QR:      f&0x8000 != 0,
		Opcode:  uint8(f>>11) & 0xF,
		AA:      f&0x0400 != 0,
		TC:      f&0x0200 != 0,
		RD:      f&0x0100 != 0,
		RA:      f&0x0080 != 0,
		AD:      f&0x0020 != 0,
		CD:      f&0x0010 != 0,
		Rcode:   int(f & 0xF),
		QDCount: binary.BigEndian.Uint16(msg[4:]),
		ANCount: binary.BigEndian.Uint16(msg[6:]),
		NSCount: binary.BigEndian.Uint16(msg[8:]),
		ARCount: binary.BigEndian.Uint16(msg[10:]),
	}
	off := 12
	for i := 0; i < int(m.Header.QDCount); i++ {
		name, p, err := ReadName(msg, off)
		if err != nil {
			return nil, err
		}
		if p+4 > len(msg) {
			return nil, errShort
		}
		m.Questions = append(m.Questions, Question{name,
			RRType(binary.BigEndian.Uint16(msg[p:])), binary.BigEndian.Uint16(msg[p+2:])})
		off = p + 4
	}
	sections := []struct {
		n   uint16
		dst *[]RR
	}{{m.Header.ANCount, &m.Answers}, {m.Header.NSCount, &m.Authority}, {m.Header.ARCount, &m.Additional}}
	for _, s := range sections {
		for i := 0; i < int(s.n); i++ {
			rr, p, err := readRR(msg, off)
			if err != nil {
				return nil, err
			}
			if rr.Type == TypeOPT {
				m.EDNS = &EDNS{UDPSize: rr.Class, DO: rr.TTL&0x8000 != 0}
			} else {
				*s.dst = append(*s.dst, rr)
			}
			off = p
		}
	}
	return m, nil
}
