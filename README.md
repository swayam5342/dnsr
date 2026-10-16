# dnsr — an iterative DNS resolver from scratch, in Go

No `net.Resolver`, no `miekg/dns`. Every byte of the DNS wire format is
encoded and decoded by hand, and resolution walks the real hierarchy:

```
root (.)  ──referral──▶  TLD (com.)  ──referral──▶  github.com. NS  ──▶  answer
```

```
$ dnsr www.github.com
;; resolving www.github.com. A
→ asking k.root-servers.net. (193.0.14.129) for www.github.com. A
↓ k.root-servers.net. → referral to com. [a.gtld-servers.net, b.gtld-servers.net, c.gtld-servers.net, +10 more] (31ms)
→ asking e.gtld-servers.net. (192.12.94.30) for www.github.com. A
↓ e.gtld-servers.net. → referral to github.com. [dns1.p08.nsone.net, ns-1283.awsdns-32.org, +6 more] (18ms)
⋯ no glue for github.com. — resolving a nameserver's address first
  │ → asking ...
→ asking ns-1283.awsdns-32.org. (205.251.197.3) for www.github.com. A
↪ CNAME www.github.com. is an alias → github.com., restarting from the top
  │ ↷ starting at cached zone github.com.
  │ ✓ ns-421.awsdns-52.com. answered 1 A record(s) (12ms)

;; NOERROR · 4 hops · 140ms
www.github.com.                3600 IN CNAME github.com.
github.com.                      60 IN A     140.82.121.4
```
*(illustrative — exact servers vary per run)*

## Run

```sh
go build -o dnsr .
./dnsr github.com
./dnsr -t MX gmail.com
./dnsr -t AAAA www.wikipedia.org swayam.li   # several names share one cache
./dnsr -q -t TXT google.com                  # answer only, no trace

./dnsr serve -addr 127.0.0.1:5353            # become a recursive DNS server
dig @127.0.0.1 -p 5353 example.com           # …and query it from another terminal
```

Needs outbound UDP/TCP 53 to the internet (some campus / corporate networks
block this and force their own resolver — try a phone hotspot if every root times out).

## What it implements

| Piece | Where | Notes |
|---|---|---|
| Header, question, RR encode/decode | `wire.go` | RFC 1035 §4 |
| Name compression (`0xC0` pointers) | `wire.go: readName` | with loop protection |
| EDNS0 OPT record, 1232-byte buffer | `wire.go: BuildQuery` | DNS Flag Day 2020 size |
| Iterative resolution from root hints | `resolver.go: resolve` | RD=0, we are the recursor |
| Referral following + glue | `resolver.go` | NS in Authority, A in Additional |
| Glueless delegations | `resolver.go` | nested lookup of the NS's own address |
| CNAME chasing | `resolver.go` | restarts resolution for the target |
| NXDOMAIN vs NODATA | `resolver.go` | SOA returned in authority |
| UDP → TCP on truncation (TC bit) | `resolver.go: exchangeTCP` | 2-byte length framing |
| Answer cache with TTL countdown | `resolver.go` | TTLs shrink as entries age |
| Delegation cache | `resolver.go: closestKnownZone` | 2nd `.com` lookup skips the root |
| Recursive server mode | `server.go` | re-encodes rdata names (no stale pointers) |

### Security checks (the interesting part for a cyber-security angle)

- **Random query IDs, and replies must match ID + question** — a forged packet with
  the wrong ID or question is dropped, not trusted.
- **Bailiwick check on referrals** — a `.com` server can only delegate names under
  `.com`, and only one level closer to the target. Blocks redirect attacks.
- **Bailiwick check on glue** — a `.com` server may vouch for `ns1.example.com`'s address,
  but glue it sends for `ns.dnshost.org` is ignored (the classic Kaminsky-era poisoning vector).
- **Compression-pointer loop limit** — a malicious packet can't hang the parser.

## Tests

```sh
go test -v ./...
```

The tests spin up a **fake DNS hierarchy on loopback** (root → com/org → example.com,
glueless.com …) on `127.0.0.10–15`, so the full walk is tested offline and deterministically:
referral chain, delegation cache, CNAME, NXDOMAIN/NODATA, MX, glueless delegation with
poisoned glue, out-of-bailiwick referral, TC→TCP fallback, and name compression.

## Not (yet) implemented — good next steps

- **DNSSEC validation** (DS/DNSKEY/RRSIG chain from the root trust anchor) — the big one
- IPv6 transport to nameservers (AAAA glue is parsed but only IPv4 is queried)
- Negative caching (RFC 2308) and QNAME minimisation (RFC 9156)
- Parallel queries / RTT-based server selection (like Unbound's "smoothed RTT")
