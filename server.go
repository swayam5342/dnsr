package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
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

func serve(addr string, r *Resolver) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("dnsr listening on udp://%s — try: dig @%s -p %s example.com",
		pc.LocalAddr(), strings.Split(pc.LocalAddr().String(), ":")[0], strings.Split(pc.LocalAddr().String(), ":")[1])

	buf := make([]byte, 1500)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			m, err := ParseMessage(pkt)
			if err != nil || len(m.Questions) != 1 || m.Header.QR {
				return
			}
			q := m.Questions[0]
			res, err := r.Resolve(q.Name, q.Type)
			var out []byte
			if err != nil {
				log.Printf("%-30s %-5s SERVFAIL (%v)", q.Name, q.Type, err)
				out = buildResponse(m.Header.ID, q, m.Header.RD, RcodeServFail, nil, nil, nil)
			} else {
				log.Printf("%-30s %-5s %-8s %d answer(s), %d hops, %s", q.Name, q.Type,
					rcodeString(res.Rcode), len(res.Answers), res.Hops, res.Elapsed.Round(1e6))
				out = buildResponse(m.Header.ID, q, m.Header.RD, res.Rcode, res.Answers, res.Authority, nil)
			}
			pc.WriteTo(out, client)
		}()
	}
}
