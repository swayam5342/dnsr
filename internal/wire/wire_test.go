package wire_test

import (
	"math/rand"
	"testing"

	"github.com/swayam5342/dnsr/internal/dnstest"
	"github.com/swayam5342/dnsr/internal/wire"
)

func TestNameCompression(t *testing.T) {
	pkt := []byte{
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
		0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 1, 2, 3, 4,
	}
	m, err := wire.ParseMessage(pkt)
	if err != nil || m.Answers[0].Name != "www.example.com." || m.Answers[0].Data != "1.2.3.4" {
		t.Fatalf("%+v %v", m, err)
	}
	loop := append(append([]byte{}, pkt[:12]...), 0xC0, 0x0C)
	if _, err := wire.ParseMessage(loop); err == nil {
		t.Fatal("expected loop error")
	}
}

func TestRRSIGParsesAndPrints(t *testing.T) {
	s := dnstest.NewSigner("example.com.")
	sig := s.Sign([]wire.RR{dnstest.A("www.example.com.", "10.0.0.1")})
	p, err := wire.ParseRRSIG(sig.Raw)
	if err != nil || p.Signer != "example.com." || p.TypeCovered != wire.TypeA || p.KeyTag != s.Tag {
		t.Fatalf("%+v %v", p, err)
	}
}

func seedPackets() [][]byte {
	q, _ := wire.BuildQuery(0x1234, "www.example.com.", wire.TypeA, true)
	resp := []byte{
		0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
		0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 1, 2, 3, 4,
	}
	s := dnstest.NewSigner("example.com.")
	www := dnstest.A("www.example.com.", "1.2.3.4")
	signed := wire.BuildResponse(0x1234, wire.Question{Name: "www.example.com.", Type: wire.TypeA, Class: 1}, false, 0,
		[]wire.RR{www, s.Sign([]wire.RR{www}), s.RR, s.DS()}, nil, nil)
	return [][]byte{q, resp, signed}
}

func FuzzParseMessage(f *testing.F) {
	for _, s := range seedPackets() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := wire.ParseMessage(b); err == nil {
			for _, rr := range m.Answers {
				if rr.Type == wire.TypeRRSIG {
					wire.ParseRRSIG(rr.Raw)
				}
				if rr.Type == wire.TypeDNSKEY {
					wire.ParseDNSKEY(rr)
				}
			}
		}
	})
}

func TestRandomAndMutatedPackets(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	seeds := seedPackets()
	errs, oks := 0, 0
	for i := range 1_000_000 {
		var b []byte
		if i%2 == 0 {
			b = make([]byte, rng.Intn(600))
			rng.Read(b)
		} else {
			s := seeds[rng.Intn(len(seeds))]
			b = append([]byte(nil), s...)
			for range 1 + rng.Intn(6) {
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			}
			if rng.Intn(4) == 0 {
				b = b[:rng.Intn(len(b))]
			}
		}
		if _, err := wire.ParseMessage(b); err != nil {
			errs++
		} else {
			oks++
		}
	}
	t.Logf("1,000,000 packets: %d rejected with error, %d parsed, 0 panics", errs, oks)
}

func BenchmarkParseMessage(b *testing.B) {
	p := seedPackets()[1]
	for b.Loop() {
		wire.ParseMessage(p)
	}
}

func BenchmarkBuildQuery(b *testing.B) {
	for i := 0; b.Loop(); i++ {
		wire.BuildQuery(uint16(i), "www.example.com.", wire.TypeA, false)
	}
}
