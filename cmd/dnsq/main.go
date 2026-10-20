// Command dnsq is a small stub client for trying out "dnsr serve": it sends one
// recursive query per name over UDP, TCP or DNS over TLS and prints the reply.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/swayam5342/dnsr/internal/wire"
)

func main() {
	srv := flag.String("s", "127.0.0.1:8053", "server address")
	qt := flag.String("t", "A", "record type")
	useTCP := flag.Bool("tcp", false, "query over TCP")
	useTLS := flag.Bool("tls", false, "query over DNS over TLS (certificate not verified)")
	tls12 := flag.Bool("tls12", false, "with -tls, offer at most TLS 1.2")
	do := flag.Bool("do", false, "set the DNSSEC OK bit")
	flood := flag.Int("n", 0, "send N back-to-back UDP queries and count the answers")
	timeout := flag.Duration("timeout", 20*time.Second, "reply timeout")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dnsq [-s HOST:PORT] [-t TYPE] [-tcp | -tls [-tls12]] [-do] [-n N] name...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	qtype, err := wire.ParseType(*qt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if *flood > 0 {
		answered := 0
		for range *flood {
			if _, err := exchange("udp", *srv, flag.Arg(0), qtype, *do, 300*time.Millisecond, nil); err == nil {
				answered++
			}
		}
		fmt.Printf("rate limit: %d back-to-back queries -> %d answered, %d dropped\n", *flood, answered, *flood-answered)
		return
	}

	network := "udp"
	var tcfg *tls.Config
	switch {
	case *useTLS:
		network, tcfg = "tls", &tls.Config{InsecureSkipVerify: true}
		if *tls12 {
			tcfg.MaxVersion = tls.VersionTLS12
		}
	case *useTCP:
		network = "tcp"
	}

	exit := 0
	for _, name := range flag.Args() {
		t0 := time.Now()
		m, err := exchange(network, *srv, name, qtype, *do, *timeout, tcfg)
		if err != nil {
			fmt.Printf(";; %s %s via %s %s: %v\n\n", wire.Fqdn(name), qtype, strings.ToUpper(network), *srv, err)
			exit = 1
			continue
		}
		fmt.Printf(";; %s %s via %s %s\n", wire.Fqdn(name), qtype, strings.ToUpper(network), *srv)
		fmt.Printf(";; status: %s  flags: %s  answers: %d  time: %d ms\n",
			wire.RcodeString(m.Header.Rcode), flags(m.Header), len(m.Answers), time.Since(t0).Milliseconds())
		for _, rr := range m.Answers {
			fmt.Println(rr)
		}
		for _, rr := range m.Authority {
			fmt.Println("(authority)", rr)
		}
		fmt.Println()
	}
	os.Exit(exit)
}

func flags(h wire.Header) string {
	var f []string
	for _, x := range []struct {
		on   bool
		name string
	}{{h.QR, "qr"}, {h.AA, "aa"}, {h.TC, "tc"}, {h.RD, "rd"}, {h.RA, "ra"}, {h.AD, "ad"}, {h.CD, "cd"}} {
		if x.on {
			f = append(f, x.name)
		}
	}
	return strings.Join(f, " ")
}

func exchange(network, addr, name string, qtype wire.RRType, do bool, timeout time.Duration, tcfg *tls.Config) (*wire.Message, error) {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := wire.BuildQuery(id, wire.Fqdn(name), qtype, do)
	if err != nil {
		return nil, err
	}
	q[2] |= 0x01

	var c net.Conn
	if network == "tls" {
		tc, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tcfg)
		if err != nil {
			return nil, err
		}
		st := tc.ConnectionState()
		sum := sha256.Sum256(st.PeerCertificates[0].Raw)
		fmt.Printf(";; %s, server certificate SHA-256 %X\n", tls.VersionName(st.Version), sum)
		c = tc
	} else if c, err = net.DialTimeout(network, addr, timeout); err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))

	var buf []byte
	if network == "udp" {
		if _, err := c.Write(q); err != nil {
			return nil, err
		}
		buf = make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		buf = buf[:n]
	} else {
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
			return nil, err
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return nil, err
		}
		buf = make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return nil, err
		}
	}
	m, err := wire.ParseMessage(buf)
	if err != nil {
		return nil, err
	}
	if m.Header.ID != id {
		return nil, fmt.Errorf("reply ID %d does not match query ID %d", m.Header.ID, id)
	}
	return m, nil
}
