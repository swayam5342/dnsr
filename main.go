package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `dnsr — an iterative DNS resolver built from scratch

usage:
  dnsr [-t TYPE] [-q] <name> [name...]    resolve from the root servers down
  dnsr serve [-addr 127.0.0.1:5353]       run as a recursive DNS server

flags:
  -t TYPE   record type: A, AAAA, NS, MX, TXT, CNAME, SOA, PTR (default A)
  -q        quiet: print only the final answer, no trace
  -nocolor  disable ANSI colours

examples:
  dnsr github.com
  dnsr -t MX gmail.com
  dnsr -t AAAA www.wikipedia.org swayam.li
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:5353", "UDP listen address")
		trace := fs.Bool("trace", false, "print full resolution trace for each query")
		fs.Parse(os.Args[2:])
		r := NewResolver()
		if *trace {
			r.Trace = os.Stderr
		}
		if err := serve(*addr, r); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
		return
	}

	qt := flag.String("t", "A", "record type")
	quiet := flag.Bool("q", false, "quiet")
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
		fmt.Println(r.c(cBold, fmt.Sprintf(";; resolving %s %s", fqdn(name), qtype)))
		res, err := r.Resolve(name, qtype)
		if err != nil {
			fmt.Println(r.c(cRed, ";; error: "+err.Error()))
			exit = 1
			continue
		}
		fmt.Printf("\n;; %s · %d hops · %s\n", rcodeString(res.Rcode), res.Hops, res.Elapsed.Round(1e6))
		for _, rr := range res.Answers {
			fmt.Println(rr)
		}
		if len(res.Answers) == 0 {
			for _, rr := range res.Authority {
				fmt.Println(r.c(cDim, rr.String()))
			}
		}
	}
	os.Exit(exit)
}
