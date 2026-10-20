package wire

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func EncodeName(buf []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for label := range strings.SplitSeq(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("bad label %q in %q", label, name)
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	return append(buf, 0), nil
}

// BuildQuery makes a non-recursive query (RD=0) with an EDNS0 OPT record
// advertising a 1232-byte UDP buffer (the DNS Flag Day 2020 value).
// With dnssec set, the DO bit asks servers to include RRSIG records.
func BuildQuery(id uint16, name string, qtype RRType, dnssec bool) ([]byte, error) {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[10:], 1)

	var err error
	if b, err = EncodeName(b, name); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(qtype))
	b = binary.BigEndian.AppendUint16(b, 1)

	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(TypeOPT))
	b = binary.BigEndian.AppendUint16(b, 1232)
	var ext uint32
	if dnssec {
		ext = 0x8000
	}
	b = binary.BigEndian.AppendUint32(b, ext)
	b = binary.BigEndian.AppendUint16(b, 0)
	return b, nil
}

func EncodeRData(rr RR) ([]byte, error) {
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR:
		return EncodeName(nil, rr.Data)
	case TypeMX:
		var pref uint16
		var host string
		if _, err := fmt.Sscanf(rr.Data, "%d %s", &pref, &host); err != nil {
			return nil, err
		}
		return EncodeName(binary.BigEndian.AppendUint16(nil, pref), host)
	case TypeSOA:
		f := strings.Fields(rr.Data)
		if len(f) != 7 {
			return nil, fmt.Errorf("bad SOA %q", rr.Data)
		}
		b, err := EncodeName(nil, f[0])
		if err != nil {
			return nil, err
		}
		if b, err = EncodeName(b, f[1]); err != nil {
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

func AppendRR(b []byte, rr RR) ([]byte, error) {
	b, err := EncodeName(b, rr.Name)
	if err != nil {
		return nil, err
	}
	rd, err := EncodeRData(rr)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(rr.Type))
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...), nil
}

func BuildResponse(id uint16, q Question, rd bool, rcode int, ans, auth, add []RR) []byte {
	flags := uint16(0x8000 | 0x0080)
	if rd {
		flags |= 0x0100
	}
	flags |= uint16(rcode & 0xF)

	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	b, _ = EncodeName(b, q.Name)
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, q.Class)

	var na, nn uint16
	for _, rr := range ans {
		if nb, err := AppendRR(b, rr); err == nil {
			b, na = nb, na+1
		}
	}
	for _, rr := range auth {
		if nb, err := AppendRR(b, rr); err == nil {
			b, nn = nb, nn+1
		}
	}
	var nr uint16
	for _, rr := range add {
		if nb, err := AppendRR(b, rr); err == nil {
			b, nr = nb, nr+1
		}
	}
	binary.BigEndian.PutUint16(b[6:], na)
	binary.BigEndian.PutUint16(b[8:], nn)
	binary.BigEndian.PutUint16(b[10:], nr)
	return b
}
