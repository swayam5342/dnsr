# dnsr

**An iterative, DNSSEC-validating DNS resolver written from scratch in Go.**

No `net.Resolver`, no `miekg/dns`, no third-party modules. dnsr encodes and decodes every
byte of the DNS wire format itself. It walks the real hierarchy from the root servers down
and validates answers against the IANA root trust anchor. It can also run as a hardened
recursive server over UDP, TCP and DNS over TLS 1.3.

```text
root (.)  ──referral──▶  TLD (com.)  ──referral──▶  github.com. NS  ──▶  answer
```

```console
$ dnsr www.github.com
;; resolving www.github.com. A
→ asking e.root-servers.net. (192.203.230.10) for com. NS
↓ e.root-servers.net. → referral to com. [a.gtld-servers.net, b.gtld-servers.net, c.gtld-servers.net, +10 more] (84ms)
→ asking j.gtld-servers.net. (192.48.79.30) for github.com. NS
↓ j.gtld-servers.net. → referral to github.com. [ns-520.awsdns-01.net, ns-421.awsdns-52.com, ns-1707.awsdns-21.co.uk, +5 more] (169ms)
→ asking ns-421.awsdns-52.com. (205.251.193.165) for www.github.com. A
↪ CNAME www.github.com. is an alias → github.com., restarting from the top
  │ ↷ starting at cached zone github.com.
  │ → asking ns-421.awsdns-52.com. (205.251.193.165) for github.com. A
  │ ✓ ns-421.awsdns-52.com. answered 1 A record(s) (76ms)

;; NOERROR · 4 hops · 388ms
www.github.com.                3600 IN CNAME github.com.
github.com.                      60 IN A     20.207.73.82
```

The root and `.com` servers only see `com. NS` and `github.com. NS`, never the full name.
That is QNAME minimisation. The exact servers differ from run to run.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Security](#security)
- [Results](#results)
- [Demo scripts](#demo-scripts)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Limitations and next steps](#limitations-and-next-steps)

## Features

| | |
|---|---|
| **Wire format** | RFC 1035 messages by hand. Name compression with loop and length limits. EDNS(0) with a 1232-byte buffer. A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, DS, DNSKEY and RRSIG records |
| **Resolution** | Iterative from the 13 root hints. Follows referrals and glue, resolves glueless delegations, chases CNAMEs, tells NXDOMAIN from NODATA, and retries truncated UDP replies over TCP |
| **Privacy** | QNAME minimisation (RFC 9156): each server sees one label more than its zone. Falls back to the full name when a server misbehaves |
| **DNSSEC** | Builds the chain of trust from the root KSKs (2017 and 2024) through DS and DNSKEY to the answer's RRSIG. Supports RSA/SHA-256/512, ECDSA P-256/P-384 and Ed25519. Each answer is reported as *secure*, *insecure* or *bogus* |
| **Caching** | Answer, delegation and DNSSEC-key caches. TTLs capped at 1 day, at most 10,000 entries each |
| **Server** | `dnsr serve` answers over UDP, TCP and DNS over TLS 1.3. Sets the AD flag on validated answers and returns SERVFAIL for bogus ones. Has an access list, a per-client rate limit and a cap on queries in flight |

## Quick start

You need Go 1.25 or later and outbound UDP/TCP port 53.

```sh
git clone https://github.com/swayam5342/dnsr.git
cd dnsr
go build -o dnsr ./cmd/dnsr
./dnsr github.com
```

Or install it directly:

```sh
go install github.com/swayam5342/dnsr/cmd/dnsr@latest
```

> **Every root server times out?** Some campus and office networks or firewalls block
> outbound DNS and force you onto their own resolver. Try another network, such as a phone
> hotspot, or allow port 53 in the firewall.

## Usage

### Lookups

```sh
dnsr github.com                         # A record, with the full trace
dnsr -t MX gmail.com                    # any type: A AAAA NS MX TXT CNAME SOA PTR DS DNSKEY RRSIG
dnsr -q -t TXT google.com               # answer only, no trace
dnsr -t AAAA www.wikipedia.org go.dev   # several names share one cache
dnsr -dnssec cloudflare.com             # validate from the root trust anchor
dnsr -nomin www.github.com              # send the full name to every server
```

| Flag | Meaning |
|---|---|
| `-t TYPE` | record type (default `A`) |
| `-q` | quiet: print only the answer |
| `-dnssec` | validate answers with DNSSEC |
| `-nomin` | turn off QNAME minimisation |
| `-no0x20` | turn off 0x20 letter-case randomisation |
| `-nocolor` | no ANSI colours |

DNSSEC results:

```console
$ dnsr -q -dnssec github.com dnssec-failed.org iana.org
;; resolving github.com. A
;; NOERROR · insecure · 3 hops · 433ms
github.com.                      60 IN A     20.207.73.82

;; resolving dnssec-failed.org. A
;; SERVFAIL · DNSSEC validation failed: no DNSKEY of dnssec-failed.org. matches its DS / trust anchor

;; resolving iana.org. A
;; NOERROR · secure · 2 hops · 639ms
iana.org.                      3600 IN A     192.0.43.8
```

### Server

```sh
dnsr serve                                                  # udp+tcp on 127.0.0.1:8053
dnsr serve -dnssec -dot 127.0.0.1:8853 -selfsigned          # validating, plus DNS over TLS 1.3
dnsr serve -dot :853 -cert cert.pem -key key.pem            # DoT with your own certificate
dnsr serve -addr 0.0.0.0:8053 -allow 127.0.0.0/8,192.168.0.0/16   # serve your LAN
```

| Flag | Meaning |
|---|---|
| `-addr HOST:PORT` | UDP and TCP listen address (default `127.0.0.1:8053`) |
| `-dot HOST:PORT` | also serve DNS over TLS (TLS 1.3 only) |
| `-cert FILE -key FILE` / `-selfsigned` | certificate for `-dot` |
| `-allow LIST` | client networks allowed to query (default: loopback only; others get REFUSED) |
| `-rate N -burst N` | per-client rate limit (default 20 queries/s, burst 40) |
| `-dnssec -nomin -no0x20` | as for lookups |
| `-trace` | print the resolution trace of every query to stderr |

The default port is 8053 because 5353 is taken by mDNS on Windows.

To query the server, use `dig @127.0.0.1 -p 8053 example.com`. If dig isn't installed, the
repo includes a small client, `dnsq`:

```console
$ go build -o dnsq ./cmd/dnsq
$ dnsq -s 127.0.0.1:8853 -tls isc.org
;; TLS 1.3, server certificate SHA-256 EFD6090F198697FDB28C082CE79C4DCE8335C97FEEB45734598BB0056569645D
;; isc.org. A via TLS 127.0.0.1:8853
;; status: NOERROR  flags: qr rd ra ad  answers: 4  time: 798 ms
isc.org.                        300 IN A     151.101.131.42
...
$ dnsq -s 127.0.0.1:8853 -tls -tls12 example.com
;; example.com. A via TLS 127.0.0.1:8853: remote error: tls: protocol version not supported
```

dnsq flags:

| Flag | Effect |
|---|---|
| `-tcp` | query over TCP |
| `-tls` | DNS over TLS |
| `-tls12` | offer at most TLS 1.2 (to check that it is refused) |
| `-do` | set the DNSSEC OK bit |
| `-n 60` | flood test for the rate limit |

## Security

dnsr is built around the attacks a resolver has to survive:

| Threat | Defence |
|---|---|
| Off-path spoofing (Kaminsky) | Query IDs from `crypto/rand`. A reply must match the ID **and** the exact question, over UDP and TCP |
| Spoofing, extra entropy | **0x20**: each letter of the name gets a random case (`wWw.GiThUb.cOm`), and the reply must echo it. Servers that don't preserve case are detected and asked again without it |
| Cache poisoning through referrals | **Bailiwick checks**: a `.com` server may only delegate names under `.com`, strictly below itself |
| Poisoned glue | Glue is used only for nameservers inside the referring zone. Glue from `.com` for `ns.dnshost.org` is ignored |
| Forged or tampered data | **DNSSEC**: every answer RRset must chain up to the root KSK. Otherwise it is *bogus*, and the server returns SERVFAIL |
| Eavesdropping between client and server | **DNS over TLS 1.3 only.** Older TLS versions are rejected |
| Open-resolver abuse and amplification | Access list (loopback by default), per-client token-bucket rate limit, at most 256 queries in flight, TC=1 for oversized UDP replies |
| Resource exhaustion (NXNSAttack and similar) | At most 3 glueless lookups per referral, TTL cap, bounded caches, bounded recursion depth |
| Malformed packets | Bounds checks everywhere, at most 64 compression jumps, 255-byte name limit. Tested with 1,000,000 random packets and Go's fuzzer |
| Terminal injection through names | Control characters in names are escaped before printing |

## Results

Measured with the demo scripts in October 2026:

| Check | Result |
|---|---|
| Response codes vs Google Public DNS (8.8.8.8), 15 popular domains | **15 / 15 match** |
| Cold lookup, typical | 230–800 ms, 3–5 hops |
| Repeat lookup within a zone (delegation cache) | 1 hop, about 55 ms |
| DNSSEC | cloudflare.com, iana.org, isc.org *secure*; github.com *insecure*; dnssec-failed.org *bogus* |
| Server rate limit, 60 back-to-back queries | 57 answered, 3 dropped |
| TLS 1.2 client against DoT | rejected |
| Client outside `-allow` | REFUSED |
| 1,000,000 random and mutated packets | 0 panics |
| Native fuzzing, 30 s | 3.2 million inputs, no failures |
| `ParseMessage` / `BuildQuery` / ECDSA P-256 verify | 440 ns / 154 ns / 55 µs |

## Demo scripts

`scripts/demo.ps1` (Windows) and `scripts/demo.sh` (Linux, macOS, Git Bash) build the binaries
into `bin/`. They then re-run every demonstration from the project report, one section at a time.

```sh
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1                  # everything
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -List            # list the sections
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 dnssec server -Pause

./scripts/demo.sh                     # everything
./scripts/demo.sh -l                  # list the sections
PAUSE=1 ./scripts/demo.sh dnssec server
```

| Section | Shows |
|---|---|
| `build`, `usage` | build both binaries, command-line help |
| `lookup`, `types`, `negative` | iterative lookup with CNAME; MX, AAAA, NS, TXT, SOA, PTR, DS, DNSKEY; NXDOMAIN and NODATA |
| `cache`, `nomin`, `glueless`, `tcp` | delegation cache, minimisation off, glueless delegation, TC → TCP |
| `dnssec` | secure, insecure and bogus answers |
| `server`, `acl` | UDP/TCP/DoT, AD flag, SERVFAIL, TLS 1.2 refused, rate limit, access list |
| `compare` | response codes vs 8.8.8.8 for 15 domains |
| `tests`, `fuzz`, `bench` | unit tests and race detector, fuzzing, benchmarks |

Server logs go to `scripts/out/`. `-Pause` (or `PAUSE=1`) waits for Enter between sections,
which helps when presenting the demo live.

## Project layout

```text
cmd/dnsr/            the resolver command (lookups and "serve")
cmd/dnsq/            small client for trying out the server (UDP, TCP, DoT)
internal/wire/       DNS message format: parse, build, names, DNSSEC record formats
internal/resolver/   iterative resolution, caches, 0x20 exchange, DNSSEC validation
internal/server/     recursive server: listeners, TLS, access list, rate limit
internal/dnstest/    fake signed DNS hierarchy on loopback, used by the tests
internal/term/       ANSI colours and escaping of untrusted names
scripts/             demo scripts
report/              project reports (PDF) and draw.io diagrams
```

## Testing

```sh
go test ./...                                                       # unit tests
go test -race ./...                                                 # race detector
go test -run '^$' -fuzz FuzzParseMessage -fuzztime 30s ./internal/wire
go test -run '^$' -bench . -benchmem ./...
```

The tests need no internet. `internal/dnstest` starts a fake DNS hierarchy on
`127.0.0.10–15` (root → com/org → example.com, glueless.com, …). The root, `com.` and
`example.com.` zones are signed with real ECDSA keys. It includes hostile servers that send
forged replies, poisoned glue, out-of-bailiwick referrals, tampered signatures, mismatched
TCP replies and case-insensitive echoes. The 34 tests cover:

- the referral chain, caches, CNAME, NXDOMAIN/NODATA and MX
- glueless delegation and TC → TCP fallback
- name compression and parser robustness
- TTL cap, cache bounds and the glueless lookup limit
- forged replies, QNAME minimisation and 0x20
- DNSSEC: secure, tampered, wrong anchor and unsigned
- the server: AD flag, truncation, record stripping, rate limit, access list, DNS over TLS 1.3

## Limitations and next steps

- **Authenticated denial of existence** (NSEC/NSEC3): negative answers and unsigned
  delegations are not proven yet; only positive answers are validated
- Negative caching (RFC 2308) and caching CNAMEs under the alias name
- IPv6 transport to nameservers (AAAA glue is parsed, but only IPv4 is queried)
- Parallel queries and RTT-based server selection, like Unbound's "smoothed RTT"
- DNS Cookies (RFC 7873), DNS over HTTPS
