# dnsr — an iterative DNS resolver from scratch, in Go

No `net.Resolver`, no `miekg/dns`. Every byte of the DNS wire format is
encoded and decoded by hand, resolution walks the real hierarchy with
QNAME minimisation, and answers can be validated with DNSSEC from the root
trust anchor:

```
root (.)  ──referral──▶  TLD (com.)  ──referral──▶  github.com. NS  ──▶  answer
```

```
$ dnsr www.github.com
;; resolving www.github.com. A
→ asking e.root-servers.net. (192.203.230.10) for com. NS
↓ e.root-servers.net. → referral to com. [a.gtld-servers.net, b.gtld-servers.net, c.gtld-servers.net, +10 more] (28ms)
→ asking m.gtld-servers.net. (192.55.83.30) for github.com. NS
↓ m.gtld-servers.net. → referral to github.com. [ns-520.awsdns-01.net, ns-421.awsdns-52.com, ns-1707.awsdns-21.co.uk, +5 more] (116ms)
→ asking ns-421.awsdns-52.com. (205.251.193.165) for www.github.com. A
↪ CNAME www.github.com. is an alias → github.com., restarting from the top
  │ ↷ starting at cached zone github.com.
  │ → asking ns-421.awsdns-52.com. (205.251.193.165) for github.com. A
  │ ✓ ns-421.awsdns-52.com. answered 1 A record(s) (40ms)

;; NOERROR · 4 hops · 222ms
www.github.com.                3600 IN CNAME github.com.
github.com.                      60 IN A     20.207.73.82
```
*(exact servers vary per run)*

## Run

Requires Go 1.25 or later.

```sh
go build -o dnsr .
./dnsr github.com
./dnsr -t MX gmail.com
./dnsr -t AAAA www.wikipedia.org swayam.li   # several names share one cache
./dnsr -q -t TXT google.com                  # answer only, no trace
./dnsr -dnssec cloudflare.com                # validate from the root trust anchor
./dnsr -nomin www.github.com                 # send the full name to every server

./dnsr serve                                 # recursive server on udp+tcp 127.0.0.1:8053
./dnsr serve -dnssec -dot 127.0.0.1:8853 -selfsigned   # …validating, plus DNS over TLS
dig @127.0.0.1 -p 8053 example.com           # query it from another terminal
```

Needs outbound UDP/TCP 53 to the internet (some campus / corporate networks
block this and force their own resolver — try a phone hotspot if every root times out).
The server defaults to port 8053 because 5353 is taken by mDNS on Windows.

## What it implements

| Piece | Where | Notes |
|---|---|---|
| Header, question, RR encode/decode | `wire.go` | RFC 1035 §4; A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, DS, DNSKEY, RRSIG |
| Name compression (`0xC0` pointers) | `wire.go: readName` | 64-jump loop limit, 255-byte name limit |
| EDNS0 OPT record, 1232-byte buffer | `wire.go: BuildQuery` | DNS Flag Day 2020 size; DO bit with `-dnssec` |
| Iterative resolution from root hints | `resolver.go: resolve` | RD=0, we are the recursor |
| QNAME minimisation | `resolver.go` | RFC 9156, falls back to the full name on odd replies |
| Referral following + glue | `resolver.go` | NS in Authority, A in Additional |
| Glueless delegations | `resolver.go` | nested lookup, at most 3 per referral |
| CNAME chasing | `resolver.go` | restarts resolution for the target |
| NXDOMAIN vs NODATA | `resolver.go` | SOA returned in authority |
| UDP → TCP on truncation (TC bit) | `resolver.go: exchangeTCP` | 2-byte length framing |
| Answer, delegation and key caches | `resolver.go`, `dnssec.go` | TTL capped at 1 day, 10,000 entries each, delegations expire |
| DNSSEC validation | `dnssec.go` | DS/DNSKEY chain from the IANA root anchors; RSA/SHA-2, ECDSA P-256/P-384, Ed25519 |
| Recursive server | `server.go` | UDP + TCP + DNS over TLS, AD flag, SERVFAIL for bogus, rate limit, TC for big UDP replies |

### Security checks (the interesting part for a cyber-security angle)

- **Random query IDs, and replies must match ID + question** — over UDP and TCP; a forged
  packet with the wrong ID or question is dropped, not trusted.
- **Bailiwick check on referrals** — a `.com` server can only delegate names under
  `.com`, strictly below itself and above the target. Blocks redirect attacks.
- **Bailiwick check on glue** — a `.com` server may vouch for `ns1.example.com`'s address,
  but glue it sends for `ns.dnshost.org` is ignored (the classic Kaminsky-era poisoning vector).
- **DNSSEC** — with `-dnssec` every answer must be signed by a key that chains up to the root
  trust anchors (KSK-2017 and KSK-2024); tampered or mis-signed data is reported as bogus.
- **Resource limits** — TTL cap, bounded caches, glueless lookup limit (NXNSAttack), and in
  server mode a per-client rate limit and a cap of 256 queries in flight.
- **Parser safety** — compression-pointer loop limit, name length limit, bounds checks everywhere.

## Tests

```sh
go test -v ./...
go test -race ./...
```

The tests spin up a **fake DNS hierarchy on loopback** (root → com/org → example.com,
glueless.com …) on `127.0.0.10–15`, with the root, `com.` and `example.com.` zones signed,
so the full walk is tested offline and deterministically: referral chain, delegation cache,
CNAME, NXDOMAIN/NODATA, MX, glueless delegation with poisoned glue, out-of-bailiwick referral,
TC→TCP fallback, name compression, TTL cap, cache bounds, glueless limit, forged replies,
mismatching TCP replies, QNAME minimisation, DNSSEC (secure, tampered, wrong anchor, unsigned),
and the server (AD flag, truncation, rate limit, DNS over TLS).

## Not (yet) implemented — good next steps

- **Authenticated denial of existence** (NSEC/NSEC3) — negative answers and unsigned
  delegations are not yet proven, only positive answers are validated
- Negative caching (RFC 2308) and caching CNAMEs under the alias name
- IPv6 transport to nameservers (AAAA glue is parsed but only IPv4 is queried)
- Parallel queries / RTT-based server selection (like Unbound's "smoothed RTT")
- 0x20 case randomisation, DNS Cookies, DNS over HTTPS
