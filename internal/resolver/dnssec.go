package resolver

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
	"strings"
	"time"

	"github.com/swayam5342/dnsr/internal/term"
	"github.com/swayam5342/dnsr/internal/wire"
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

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// IANA root trust anchors (root-anchors.xml): KSK-2017 and KSK-2024.
var rootAnchors = []wire.DS{
	{Owner: ".", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: mustHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")},
	{Owner: ".", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: mustHex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")},
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
func dsMatches(ds wire.DS, k *wire.DNSKEY) bool {
	if ds.KeyTag != k.Tag || ds.Algorithm != k.Algorithm || !strings.EqualFold(ds.Owner, k.Owner) {
		return false
	}
	h := digester(ds.DigestType)
	if h == nil {
		return false
	}
	owner, _ := wire.EncodeName(nil, k.Owner)
	h.Write(owner)
	h.Write(k.Raw)
	return bytes.Equal(h.Sum(nil), ds.Digest)
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
func verifySignature(s *wire.RRSIG, k *wire.DNSKEY, data []byte) error {
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
func checkValidity(s *wire.RRSIG, now time.Time) error {
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
func verifyRRset(set, sigs []wire.RR, keys []*wire.DNSKEY, zone string) error {
	t := set[0].Type
	lastErr := fmt.Errorf("no RRSIG from %s for %s %s", zone, set[0].Name, t)
	for _, sr := range sigs {
		s, err := wire.ParseRRSIG(sr.Raw)
		if err != nil {
			lastErr = err
			continue
		}
		if s.TypeCovered != t || !strings.EqualFold(sr.Name, set[0].Name) || s.Signer != zone ||
			!wire.IsSubdomain(strings.ToLower(set[0].Name), s.Signer) {
			continue
		}
		if int(s.Labels) > wire.LabelCount(set[0].Name) {
			lastErr = errors.New("RRSIG labels field larger than the owner name")
			continue
		}
		if err := checkValidity(s, time.Now()); err != nil {
			lastErr = err
			continue
		}
		data, err := wire.SignedData(s, set)
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
	keys    []*wire.DNSKEY
	sec     Security
	why     string
	expires time.Time
}

// zoneKeys returns the validated zone-signing keys of zone, walking the chain
// of DS and DNSKEY records up to the root trust anchor.
func (r *Resolver) zoneKeys(zone string, depth int) ([]*wire.DNSKEY, Security, string) {
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

func (r *Resolver) fetchZoneKeys(zone string, depth int) ([]*wire.DNSKEY, Security, string, uint32) {
	var dss []wire.DS
	if zone == "." {
		dss = r.Anchors
	} else {
		res, err := r.resolve(zone, wire.TypeDS, 1, 0)
		if err != nil {
			return nil, SecBogus, fmt.Sprintf("cannot fetch DS for %s: %v", zone, err), 60
		}
		dsSet := filterType(res.Answers, wire.TypeDS)
		if res.Rcode != wire.RcodeNoError || len(dsSet) == 0 {
			r.tracef(1, "%s no DS for %s at its parent — unsigned delegation", r.c(term.Yellow, "»"), zone)
			return nil, SecInsecure, fmt.Sprintf("no DS record for %s (unsigned delegation)", zone), 300
		}
		parent := dsSet[0].Zone
		for _, sr := range coveredSigs(res.Sigs, wire.TypeDS) {
			if s, err := wire.ParseRRSIG(sr.Raw); err == nil && s.Signer != zone && wire.IsSubdomain(zone, s.Signer) {
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
			if ds, err := wire.ParseDS(rr); err == nil && supportedAlgorithm(ds.Algorithm) && digester(ds.DigestType) != nil {
				dss = append(dss, ds)
			}
		}
		if len(dss) == 0 {
			return nil, SecInsecure, fmt.Sprintf("%s uses only unsupported DNSSEC algorithms", zone), 300
		}
		r.tracef(1, "%s DS for %s verified with the keys of %s", r.c(term.Green, "»"), zone, parent)
	}

	res, err := r.resolve(zone, wire.TypeDNSKEY, 1, 0)
	if err != nil {
		return nil, SecBogus, fmt.Sprintf("cannot fetch DNSKEY for %s: %v", zone, err), 60
	}
	keyRRs := filterType(res.Answers, wire.TypeDNSKEY)
	if len(keyRRs) == 0 {
		return nil, SecBogus, fmt.Sprintf("%s has a DS record but no DNSKEY", zone), 60
	}
	var all, trusted, zsks []*wire.DNSKEY
	for _, rr := range keyRRs {
		k, err := wire.ParseDNSKEY(rr)
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
	r.tracef(1, "%s DNSKEY set of %s verified (%d keys, signed by key %d)", r.c(term.Green, "»"), zone, len(zsks), trusted[0].Tag)
	return zsks, SecSecure, "", minTTL(keyRRs)
}

func filterType(rrs []wire.RR, t wire.RRType) []wire.RR {
	var out []wire.RR
	for _, rr := range rrs {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

// validateResult checks every RRset of a positive answer; the weakest result wins.
func (r *Resolver) validateResult(res *Result) (Security, string) {
	if res.Rcode != wire.RcodeNoError || len(res.Answers) == 0 {
		return SecUnchecked, "negative answers are not validated (NSEC/NSEC3 not implemented)"
	}
	type key struct {
		owner string
		t     wire.RRType
	}
	var order []key
	sets := map[key][]wire.RR{}
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
		var sigs []wire.RR
		for _, s := range coveredSigs(res.Sigs, k.t) {
			if strings.EqualFold(s.Name, k.owner) {
				sigs = append(sigs, s)
			}
		}
		zone := set[0].Zone
		for _, sr := range sigs {
			if s, err := wire.ParseRRSIG(sr.Raw); err == nil && wire.IsSubdomain(k.owner, s.Signer) {
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
		r.tracef(0, "%s %s", r.c(term.Green, "» DNSSEC: secure"), res.SecurityNote)
	case SecBogus:
		r.tracef(0, "%s %s", r.c(term.Red, "» DNSSEC: BOGUS"), res.SecurityNote)
	default:
		r.tracef(0, "%s %s", r.c(term.Yellow, "» DNSSEC: "+res.Security.String()), res.SecurityNote)
	}
}
