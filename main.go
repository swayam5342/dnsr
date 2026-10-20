package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `dnsr — an iterative DNS resolver built from scratch

usage:
  dnsr [-t TYPE] [-q] [-dnssec] <name> [name...]   resolve from the root servers down
  dnsr serve [-addr 127.0.0.1:8053] [flags]        run as a recursive DNS server

flags:
  -t TYPE   record type: A, AAAA, NS, MX, TXT, CNAME, SOA, PTR, DS, DNSKEY, RRSIG (default A)
  -q        quiet: print only the final answer, no trace
  -dnssec   validate answers with DNSSEC from the root trust anchor
  -nomin    send the full name to every server (disable QNAME minimisation)
  -no0x20   do not randomise the letter case of queries
  -nocolor  disable ANSI colours

serve flags:
  -addr HOST:PORT      UDP and TCP listen address (default 127.0.0.1:8053)
  -dot HOST:PORT       also serve DNS over TLS on this address (port 853 is standard)
  -cert FILE -key FILE TLS certificate and key for -dot
  -selfsigned          use a generated self-signed certificate for -dot
  -allow LIST          clients allowed to query, e.g. 127.0.0.0/8,192.168.0.0/16
                       (default: loopback only; others get REFUSED)
  -rate N -burst N     per-client query rate limit (default 20/s, burst 40)
  -dnssec, -nomin, -no0x20, -trace

examples:
  dnsr github.com
  dnsr -t MX gmail.com
  dnsr -dnssec cloudflare.com
  dnsr serve -dnssec -dot 127.0.0.1:8853 -selfsigned
  dnsr serve -addr 0.0.0.0:8053 -allow 127.0.0.0/8,192.168.0.0/16
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
		addr := fs.String("addr", "127.0.0.1:8053", "UDP and TCP listen address")
		dot := fs.String("dot", "", "DNS over TLS listen address")
		cert := fs.String("cert", "", "TLS certificate file")
		key := fs.String("key", "", "TLS key file")
		selfSigned := fs.Bool("selfsigned", false, "generate a self-signed certificate")
		rate := fs.Float64("rate", 20, "queries per second per client")
		burst := fs.Float64("burst", 40, "burst size per client")
		dnssec := fs.Bool("dnssec", false, "validate answers with DNSSEC")
		nomin := fs.Bool("nomin", false, "disable QNAME minimisation")
		no0x20 := fs.Bool("no0x20", false, "disable 0x20 case randomisation")
		allow := fs.String("allow", "", "comma-separated client networks allowed to query")
		trace := fs.Bool("trace", false, "print full resolution trace for each query")
		fs.Parse(os.Args[2:])
		acl, err := ParseAllow(*allow)
		if err != nil {
			fmt.Fprintln(os.Stderr, "serve: bad -allow list:", err)
			os.Exit(2)
		}
		r := NewResolver()
		r.DNSSEC, r.Minimise, r.CaseRandomisation = *dnssec, !*nomin, !*no0x20
		if *trace {
			r.Trace = os.Stderr
		}
		s := NewServer(r)
		s.Rate, s.Burst, s.Allow = *rate, *burst, acl
		cfg := ServeConfig{Addr: *addr, DoTAddr: *dot, CertFile: *cert, KeyFile: *key, SelfSigned: *selfSigned}
		if err := serve(cfg, s); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
		return
	}

	qt := flag.String("t", "A", "record type")
	quiet := flag.Bool("q", false, "quiet")
	dnssec := flag.Bool("dnssec", false, "validate with DNSSEC")
	nomin := flag.Bool("nomin", false, "disable QNAME minimisation")
	no0x20 := flag.Bool("no0x20", false, "disable 0x20 case randomisation")
	nocolor := flag.Bool("nocolor", false, "disable colour")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	qtype, err := ParseType(*qt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	r := NewResolver()
	r.DNSSEC, r.Minimise, r.CaseRandomisation = *dnssec, !*nomin, !*no0x20
	if !*quiet {
		r.Trace = os.Stdout
	}
	if fi, _ := os.Stdout.Stat(); !*nocolor && fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
		r.color = true
	}

	exit := 0
	for i, name := range flag.Args() {
		if i > 0 {
			fmt.Println()
		}
		fmt.Println(r.c(cBold, fmt.Sprintf(";; resolving %s %s", printable(fqdn(name)), qtype)))
		res, err := r.Resolve(name, qtype)
		if err != nil {
			fmt.Println(r.c(cRed, ";; error: "+err.Error()))
			exit = 1
			continue
		}
		if res.Security == SecBogus {
			fmt.Println(r.c(cRed, ";; SERVFAIL · DNSSEC validation failed: "+res.SecurityNote))
			exit = 1
			continue
		}
		sec := ""
		if res.Security != SecUnchecked {
			sec = " · " + res.Security.String()
		}
		fmt.Printf("\n;; %s%s · %d hops · %s\n", rcodeString(res.Rcode), sec, res.Hops, res.Elapsed.Round(1e6))
		for _, rr := range res.Answers {
			fmt.Println(printable(rr.String()))
		}
		if len(res.Answers) == 0 {
			for _, rr := range res.Authority {
				fmt.Println(r.c(cDim, rr.String()))
			}
		}
	}
	os.Exit(exit)
}
