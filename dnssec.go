package main

// dnssec.go — DNSSEC validation of positive answers (RFC 4033–4035):
//
//   root anchor ─▶ . DNSKEY ─▶ com. DS ─▶ com. DNSKEY ─▶ example.com. DS ─▶ example.com. DNSKEY ─▶ RRSIG on the answer
//
// Every answer RRset must carry an RRSIG made by a key of the zone that signed
// it. Those keys are trusted only if one of them matches the DS record that the
// parent zone publishes (and signs), and so on up to the root, whose key must
// match a built-in trust anchor. Proofs of non-existence (NSEC/NSEC3) are not
// validated, so a missing DS is reported as insecure without a proof.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sort"
	"strings"
	"time"
)

type Security int

const (
	SecUnchecked Security = iota
	SecInsecure
	SecSecure
	SecBogus
)

func (s Security) String() string {
	return [...]string{"unchecked", "insecure", "secure", "bogus"}[s]
}

type DSRecord struct {
	Owner      string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// IANA root trust anchors (root-anchors.xml): KSK-2017 and KSK-2024.
var rootAnchors = []DSRecord{
	{".", 20326, 8, 2, mustHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")},
	{".", 38696, 8, 2, mustHex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")},
}

type rrsig struct {
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

// parseRRSIG decodes RRSIG RDATA; the signer name is never compressed (RFC 4034 §3.1.7).
func parseRRSIG(rd []byte) (*rrsig, error) {
	if len(rd) < 19 {
		return nil, errShort
	}
	be16, be32 := binary.BigEndian.Uint16, binary.BigEndian.Uint32
	s := &rrsig{TypeCovered: RRType(be16(rd)), Algorithm: rd[2], Labels: rd[3], OrigTTL: be32(rd[4:]),
		Expiration: be32(rd[8:]), Inception: be32(rd[12:]), KeyTag: be16(rd[16:])}
	name, end, err := readName(rd, 18)
	if err != nil {
		return nil, err
	}
	s.Signer, s.Signature = strings.ToLower(name), rd[end:]
	return s, nil
}

// prefix is the RRSIG RDATA without the signature, the first part of the signed data.
func (s *rrsig) prefix() []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(s.TypeCovered))
	b = append(b, s.Algorithm, s.Labels)
	b = binary.BigEndian.AppendUint32(b, s.OrigTTL)
	b = binary.BigEndian.AppendUint32(b, s.Expiration)
	b = binary.BigEndian.AppendUint32(b, s.Inception)
	b = binary.BigEndian.AppendUint16(b, s.KeyTag)
	b, _ = encodeName(b, strings.ToLower(s.Signer))
	return b
}

type dnskey struct {
	Owner     string
	Flags     uint16
	Algorithm uint8
	Key       []byte
	Raw       []byte
	Tag       uint16
}

func parseDNSKEY(rr RR) (*dnskey, error) {
	if len(rr.Raw) < 5 || rr.Raw[2] != 3 {
		return nil, errors.New("malformed DNSKEY")
	}
	return &dnskey{Owner: strings.ToLower(rr.Name), Flags: binary.BigEndian.Uint16(rr.Raw), Algorithm: rr.Raw[3],
		Key: rr.Raw[4:], Raw: rr.Raw, Tag: keyTag(rr.Raw)}, nil
}

func parseDS(rr RR) (DSRecord, error) {
	if len(rr.Raw) < 5 {
		return DSRecord{}, errors.New("malformed DS")
	}
	return DSRecord{strings.ToLower(rr.Name), binary.BigEndian.Uint16(rr.Raw), rr.Raw[2], rr.Raw[3], rr.Raw[4:]}, nil
}

// keyTag is the 16-bit checksum of DNSKEY RDATA (RFC 4034 Appendix B).
func keyTag(rd []byte) uint16 {
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

func supportedAlgorithm(a uint8) bool { return a == 8 || a == 10 || a == 13 || a == 14 || a == 15 }

func digester(t uint8) hash.Hash {
	switch t {
	case 1:
		return sha1.New()
	case 2:
		return sha256.New()
	case 4:
		return sha512.New384()
	}
	return nil
}

// dsMatches checks that a DS record is the digest of this DNSKEY (RFC 4034 §5.1.4).
func dsMatches(ds DSRecord, k *dnskey) bool {
	if ds.KeyTag != k.Tag || ds.Algorithm != k.Algorithm || !strings.EqualFold(ds.Owner, k.Owner) {
		return false
	}
	h := digester(ds.DigestType)
	if h == nil {
		return false
	}
	owner, _ := encodeName(nil, k.Owner)
	h.Write(owner)
	h.Write(k.Raw)
	return bytes.Equal(h.Sum(nil), ds.Digest)
}

// canonicalRData is the RDATA in canonical form: names uncompressed and lower-case (RFC 4034 §6.2).
func canonicalRData(rr RR) ([]byte, error) {
	switch rr.Type {
	case TypeNS, TypeCNAME, TypePTR, TypeMX, TypeSOA:
		rr.Data = strings.ToLower(rr.Data)
		return encodeRData(rr)
	}
	return rr.Raw, nil
}

// labelCount counts labels for the RRSIG Labels field, ignoring a leading "*".
func labelCount(name string) int {
	ls := splitLabels(name)
	if len(ls) > 0 && ls[0] == "*" {
		return len(ls) - 1
	}
	return len(ls)
}

// signedData builds the bytes an RRSIG signs: its own fields followed by the
// RRset in canonical form and order (RFC 4034 §3.1.8.1, §6.3).
func signedData(s *rrsig, set []RR) ([]byte, error) {
	owner := strings.ToLower(set[0].Name)
	if n := labelCount(owner); int(s.Labels) < n {
		ls := splitLabels(owner)
		owner = "*." + strings.Join(ls[len(ls)-int(s.Labels):], ".") + "."
		if s.Labels == 0 {
			owner = "*."
		}
	}
	ow, err := encodeName(nil, owner)
	if err != nil {
		return nil, err
	}
	var rds [][]byte
	for _, rr := range set {
		rd, err := canonicalRData(rr)
		if err != nil {
			return nil, err
		}
		rds = append(rds, rd)
	}
	sort.Slice(rds, func(i, j int) bool { return bytes.Compare(rds[i], rds[j]) < 0 })
	out := s.prefix()
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

// rsaPublicKey decodes the RFC 3110 key format: exponent length, exponent, modulus.
func rsaPublicKey(k []byte) (*rsa.PublicKey, error) {
	if len(k) < 3 {
		return nil, errors.New("short RSA key")
	}
	elen, off := int(k[0]), 1
	if elen == 0 {
		elen, off = int(binary.BigEndian.Uint16(k[1:])), 3
	}
	if off+elen >= len(k) || elen > 4 {
		return nil, errors.New("bad RSA key")
	}
	e := new(big.Int).SetBytes(k[off : off+elen])
	return &rsa.PublicKey{N: new(big.Int).SetBytes(k[off+elen:]), E: int(e.Int64())}, nil
}

var errBadSignature = errors.New("signature does not verify")

// verifySignature checks one RRSIG against one DNSKEY for the supported algorithms.
func verifySignature(s *rrsig, k *dnskey, data []byte) error {
	switch k.Algorithm {
	case 8, 10:
		pub, err := rsaPublicKey(k.Key)
		if err != nil {
			return err
		}
		h, sum := crypto.SHA256, sha256.Sum256(data)
		digest := sum[:]
		if k.Algorithm == 10 {
			s512 := sha512.Sum512(data)
			h, digest = crypto.SHA512, s512[:]
		}
		if rsa.VerifyPKCS1v15(pub, h, digest, s.Signature) != nil {
			return errBadSignature
		}
		return nil
	case 13, 14:
		curve, size := elliptic.P256(), 32
		var digest []byte
		if k.Algorithm == 13 {
			d := sha256.Sum256(data)
			digest = d[:]
		} else {
			d := sha512.Sum384(data)
			curve, size, digest = elliptic.P384(), 48, d[:]
		}
		if len(k.Key) != 2*size || len(s.Signature) != 2*size {
			return errors.New("bad ECDSA key or signature length")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, k.Key...))
		if err != nil {
			return err
		}
		r, ss := new(big.Int).SetBytes(s.Signature[:size]), new(big.Int).SetBytes(s.Signature[size:])
		if !ecdsa.Verify(pub, digest, r, ss) {
			return errBadSignature
		}
		return nil
	case 15:
		if len(k.Key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(k.Key), data, s.Signature) {
			return errBadSignature
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %d", k.Algorithm)
}

// checkValidity applies the inception/expiration window using serial-number arithmetic (RFC 1982).
func checkValidity(s *rrsig, now time.Time) error {
	t := uint32(now.Unix())
	if int32(t-s.Inception) < 0 {
		return errors.New("signature not yet valid")
	}
	if int32(s.Expiration-t) < 0 {
		return errors.New("signature expired")
	}
	return nil
}

// verifyRRset succeeds if any RRSIG made by zone with one of keys verifies the RRset.
func verifyRRset(set, sigs []RR, keys []*dnskey, zone string) error {
	t := set[0].Type
	lastErr := fmt.Errorf("no RRSIG from %s for %s %s", zone, set[0].Name, t)
	for _, sr := range sigs {
		s, err := parseRRSIG(sr.Raw)
		if err != nil {
			lastErr = err
			continue
		}
		if s.TypeCovered != t || !strings.EqualFold(sr.Name, set[0].Name) || s.Signer != zone ||
			!isSubdomain(strings.ToLower(set[0].Name), s.Signer) {
			continue
		}
		if int(s.Labels) > labelCount(set[0].Name) {
			lastErr = errors.New("RRSIG labels field larger than the owner name")
			continue
		}
		if err := checkValidity(s, time.Now()); err != nil {
			lastErr = err
			continue
		}
		data, err := signedData(s, set)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.Tag != s.KeyTag || k.Algorithm != s.Algorithm {
				continue
			}
			if err := verifySignature(s, k, data); err != nil {
				lastErr = fmt.Errorf("%s %s: %w", set[0].Name, t, err)
				continue
			}
			return nil
		}
	}
	return lastErr
}

type keyEntry struct {
	keys    []*dnskey
	sec     Security
	why     string
	expires time.Time
}

// zoneKeys returns the validated zone-signing keys of zone, walking the chain
// of DS and DNSKEY records up to the root trust anchor.
func (r *Resolver) zoneKeys(zone string, depth int) ([]*dnskey, Security, string) {
	if depth > 16 {
		return nil, SecBogus, "chain of trust too deep"
	}
	now := time.Now()
	r.mu.Lock()
	e, ok := r.keys[zone]
	r.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.keys, e.sec, e.why
	}
	keys, sec, why, ttl := r.fetchZoneKeys(zone, depth)
	if sec == SecBogus {
		ttl = 60
	}
	r.mu.Lock()
	evict(r.keys, r.MaxCacheEntries, func(e keyEntry) bool { return now.After(e.expires) })
	r.keys[zone] = keyEntry{keys, sec, why, now.Add(time.Duration(min(ttl, r.MaxTTL)) * time.Second)}
	r.mu.Unlock()
	return keys, sec, why
}

func (r *Resolver) fetchZoneKeys(zone string, depth int) ([]*dnskey, Security, string, uint32) {
	var dss []DSRecord
	if zone == "." {
		dss = r.Anchors
	} else {
		res, err := r.resolve(zone, TypeDS, 1, 0)
		if err != nil {
			return nil, SecBogus, fmt.Sprintf("cannot fetch DS for %s: %v", zone, err), 60
		}
		dsSet := filterType(res.Answers, TypeDS)
		if res.Rcode != RcodeNoError || len(dsSet) == 0 {
			r.tracef(1, "%s no DS for %s at its parent — unsigned delegation", r.c(cYellow, "»"), zone)
			return nil, SecInsecure, fmt.Sprintf("no DS record for %s (unsigned delegation)", zone), 300
		}
		parent := dsSet[0].Zone
		for _, sr := range coveredSigs(res.Sigs, TypeDS) {
			if s, err := parseRRSIG(sr.Raw); err == nil && s.Signer != zone && isSubdomain(zone, s.Signer) {
				parent = s.Signer
				break
			}
		}
		pkeys, psec, pwhy := r.zoneKeys(parent, depth+1)
		if psec != SecSecure {
			return nil, psec, pwhy, 300
		}
		if err := verifyRRset(dsSet, res.Sigs, pkeys, parent); err != nil {
			return nil, SecBogus, fmt.Sprintf("DS for %s: %v", zone, err), 60
		}
		for _, rr := range dsSet {
			if ds, err := parseDS(rr); err == nil && supportedAlgorithm(ds.Algorithm) && digester(ds.DigestType) != nil {
				dss = append(dss, ds)
			}
		}
		if len(dss) == 0 {
			return nil, SecInsecure, fmt.Sprintf("%s uses only unsupported DNSSEC algorithms", zone), 300
		}
		r.tracef(1, "%s DS for %s verified with the keys of %s", r.c(cGreen, "»"), zone, parent)
	}

	res, err := r.resolve(zone, TypeDNSKEY, 1, 0)
	if err != nil {
		return nil, SecBogus, fmt.Sprintf("cannot fetch DNSKEY for %s: %v", zone, err), 60
	}
	keyRRs := filterType(res.Answers, TypeDNSKEY)
	if len(keyRRs) == 0 {
		return nil, SecBogus, fmt.Sprintf("%s has a DS record but no DNSKEY", zone), 60
	}
	var all, trusted, zsks []*dnskey
	for _, rr := range keyRRs {
		k, err := parseDNSKEY(rr)
		if err != nil || k.Flags&0x0100 == 0 {
			continue
		}
		all = append(all, k)
		for _, ds := range dss {
			if dsMatches(ds, k) {
				trusted = append(trusted, k)
				break
			}
		}
	}
	if len(trusted) == 0 {
		return nil, SecBogus, fmt.Sprintf("no DNSKEY of %s matches its DS / trust anchor", zone), 60
	}
	if err := verifyRRset(keyRRs, res.Sigs, trusted, zone); err != nil {
		return nil, SecBogus, fmt.Sprintf("DNSKEY set of %s: %v", zone, err), 60
	}
	zsks = all
	r.tracef(1, "%s DNSKEY set of %s verified (%d keys, signed by key %d)", r.c(cGreen, "»"), zone, len(zsks), trusted[0].Tag)
	return zsks, SecSecure, "", minTTL(keyRRs)
}

func filterType(rrs []RR, t RRType) []RR {
	var out []RR
	for _, rr := range rrs {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

// validateResult checks every RRset of a positive answer; the weakest result wins.
func (r *Resolver) validateResult(res *Result) (Security, string) {
	if res.Rcode != RcodeNoError || len(res.Answers) == 0 {
		return SecUnchecked, "negative answers are not validated (NSEC/NSEC3 not implemented)"
	}
	type key struct {
		owner string
		t     RRType
	}
	var order []key
	sets := map[key][]RR{}
	for _, rr := range res.Answers {
		k := key{strings.ToLower(rr.Name), rr.Type}
		if _, ok := sets[k]; !ok {
			order = append(order, k)
		}
		sets[k] = append(sets[k], rr)
	}
	overall, note := SecSecure, "chain of trust verified from the root key"
	for _, k := range order {
		set := sets[k]
		var sigs []RR
		for _, s := range coveredSigs(res.Sigs, k.t) {
			if strings.EqualFold(s.Name, k.owner) {
				sigs = append(sigs, s)
			}
		}
		zone := set[0].Zone
		for _, sr := range sigs {
			if s, err := parseRRSIG(sr.Raw); err == nil && isSubdomain(k.owner, s.Signer) {
				zone = s.Signer
				break
			}
		}
		if zone == "" {
			zone = "."
		}
		keys, sec, why := r.zoneKeys(zone, 1)
		switch sec {
		case SecBogus:
			return SecBogus, why
		case SecInsecure:
			overall, note = SecInsecure, why
		case SecSecure:
			if err := verifyRRset(set, sigs, keys, zone); err != nil {
				return SecBogus, err.Error()
			}
		}
	}
	return overall, note
}

func (r *Resolver) traceSecurity(res *Result) {
	switch res.Security {
	case SecSecure:
		r.tracef(0, "%s %s", r.c(cGreen, "» DNSSEC: secure"), res.SecurityNote)
	case SecBogus:
		r.tracef(0, "%s %s", r.c(cRed, "» DNSSEC: BOGUS"), res.SecurityNote)
	default:
		r.tracef(0, "%s %s", r.c(cYellow, "» DNSSEC: "+res.Security.String()), res.SecurityNote)
	}
}
