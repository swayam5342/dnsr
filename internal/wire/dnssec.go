package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

type DS struct {
	Owner      string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

func ParseDS(rr RR) (DS, error) {
	if len(rr.Raw) < 5 {
		return DS{}, errors.New("malformed DS")
	}
	return DS{strings.ToLower(rr.Name), binary.BigEndian.Uint16(rr.Raw), rr.Raw[2], rr.Raw[3], rr.Raw[4:]}, nil
}

type RRSIG struct {
	TypeCovered RRType
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	Signer      string
	Signature   []byte
}

// ParseRRSIG decodes RRSIG RDATA; the signer name is never compressed (RFC 4034 §3.1.7).
func ParseRRSIG(rd []byte) (*RRSIG, error) {
	if len(rd) < 19 {
		return nil, errShort
	}
	be16, be32 := binary.BigEndian.Uint16, binary.BigEndian.Uint32
	s := &RRSIG{TypeCovered: RRType(be16(rd)), Algorithm: rd[2], Labels: rd[3], OrigTTL: be32(rd[4:]),
		Expiration: be32(rd[8:]), Inception: be32(rd[12:]), KeyTag: be16(rd[16:])}
	name, end, err := ReadName(rd, 18)
	if err != nil {
		return nil, err
	}
	s.Signer, s.Signature = strings.ToLower(name), rd[end:]
	return s, nil
}

// Prefix is the RRSIG RDATA without the signature, the first part of the signed data.
func (s *RRSIG) Prefix() []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(s.TypeCovered))
	b = append(b, s.Algorithm, s.Labels)
	b = binary.BigEndian.AppendUint32(b, s.OrigTTL)
	b = binary.BigEndian.AppendUint32(b, s.Expiration)
	b = binary.BigEndian.AppendUint32(b, s.Inception)
	b = binary.BigEndian.AppendUint16(b, s.KeyTag)
	b, _ = EncodeName(b, strings.ToLower(s.Signer))
	return b
}

type DNSKEY struct {
	Owner     string
	Flags     uint16
	Algorithm uint8
	Key       []byte
	Raw       []byte
	Tag       uint16
}

func ParseDNSKEY(rr RR) (*DNSKEY, error) {
	if len(rr.Raw) < 5 || rr.Raw[2] != 3 {
		return nil, errors.New("malformed DNSKEY")
	}
	return &DNSKEY{Owner: strings.ToLower(rr.Name), Flags: binary.BigEndian.Uint16(rr.Raw), Algorithm: rr.Raw[3],
		Key: rr.Raw[4:], Raw: rr.Raw, Tag: KeyTag(rr.Raw)}, nil
}

// KeyTag is the 16-bit checksum of DNSKEY RDATA (RFC 4034 Appendix B).
func KeyTag(rd []byte) uint16 {
	var ac uint32
	for i, b := range rd {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac)
}

// CanonicalRData is the RDATA in canonical form: names uncompressed and lower-case (RFC 4034 §6.2).
func CanonicalRData(rr RR) ([]byte, error) {
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR, TypeMX, TypeSOA:
		rr.Data = strings.ToLower(rr.Data)
		return EncodeRData(rr)
	}
	return rr.Raw, nil
}

// LabelCount counts labels for the RRSIG Labels field, ignoring a leading "*".
func LabelCount(name string) int {
	ls := SplitLabels(name)
	if len(ls) > 0 && ls[0] == "*" {
		return len(ls) - 1
	}
	return len(ls)
}

// SignedData builds the bytes an RRSIG signs: its own fields followed by the
// RRset in canonical form and order (RFC 4034 §3.1.8.1, §6.3).
func SignedData(s *RRSIG, set []RR) ([]byte, error) {
	owner := strings.ToLower(set[0].Name)
	if n := LabelCount(owner); int(s.Labels) < n {
		ls := SplitLabels(owner)
		owner = "*." + strings.Join(ls[len(ls)-int(s.Labels):], ".") + "."
		if s.Labels == 0 {
			owner = "*."
		}
	}
	ow, err := EncodeName(nil, owner)
	if err != nil {
		return nil, err
	}
	var rds [][]byte
	for _, rr := range set {
		rd, err := CanonicalRData(rr)
		if err != nil {
			return nil, err
		}
		rds = append(rds, rd)
	}
	sort.Slice(rds, func(i, j int) bool { return bytes.Compare(rds[i], rds[j]) < 0 })
	out := s.Prefix()
	for i, rd := range rds {
		if i > 0 && bytes.Equal(rd, rds[i-1]) {
			continue
		}
		out = append(out, ow...)
		out = binary.BigEndian.AppendUint16(out, uint16(set[0].Type))
		out = binary.BigEndian.AppendUint16(out, set[0].Class)
		out = binary.BigEndian.AppendUint32(out, s.OrigTTL)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
		out = append(out, rd...)
	}
	return out, nil
}
