#!/usr/bin/env bash
# demo.sh - runs every demonstration shown in the project report, section by section.
#
#   ./scripts/demo.sh                 # everything
#   ./scripts/demo.sh dnssec server   # chosen sections
#   ./scripts/demo.sh -l              # list sections
#   PAUSE=1 ./scripts/demo.sh         # wait for Enter between sections
#   NOGO=1 ./scripts/demo.sh          # hide the Go toolchain (build quietly, skip tests/fuzz/bench)
#
# The live sections need outbound UDP/TCP port 53 to the internet; the test,
# fuzz and bench sections run fully offline.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="$(go env GOEXE 2>/dev/null)"
DNSR="$ROOT/bin/dnsr$EXE"
DNSQ="$ROOT/bin/dnsq$EXE"
LOGS="$ROOT/scripts/out"

GO_SECTIONS=" build tests fuzz bench "
SECTIONS=(build usage lookup types negative cache nomin glueless tcp dnssec server acl compare tests fuzz bench)
declare -A DESC=(
  [build]="Build dnsr and the dnsq test client"
  [usage]="Command-line usage"
  [lookup]="Iterative lookup from the root, with QNAME minimisation and a CNAME"
  [types]="Record types: MX, AAAA, NS, TXT, SOA, PTR, DS, DNSKEY and quiet mode"
  [negative]="NXDOMAIN and NODATA answers"
  [cache]="Answer and delegation cache across several names"
  [nomin]="The same lookup without QNAME minimisation"
  [glueless]="Glueless delegation (nameserver address resolved first)"
  [tcp]="Truncated UDP reply retried over TCP"
  [dnssec]="DNSSEC validation: secure, insecure and bogus"
  [server]="Recursive server over UDP, TCP and DNS over TLS 1.3, with rate limit"
  [acl]="Server access list: clients outside -allow get REFUSED"
  [compare]="Correctness against Google Public DNS (8.8.8.8) for 15 domains"
  [tests]="Offline unit tests on the fake DNS hierarchy (and the race detector)"
  [fuzz]="Parser robustness: 1,000,000 random packets and native fuzzing"
  [bench]="Benchmarks: parse, build query, ECDSA signature check"
)

banner() {
  printf '\n\033[36m%s\n %s: %s\n%s\033[0m\n' "$(printf '=%.0s' {1..78})" "$1" "${DESC[$1]}" "$(printf '=%.0s' {1..78})"
}

run() {
  printf '\n\033[33m$ %s\033[0m\n' "$(basename "${1%"$EXE"}") ${*:2}"
  "$@"
}

need_build() { [[ -x "$DNSR" && -x "$DNSQ" ]] || { if [[ -n "${NOGO:-}" ]]; then build_quiet; else s_build; fi; }; }

build_quiet() {
  (cd "$ROOT" && go build -o "bin/dnsr$EXE" ./cmd/dnsr && go build -o "bin/dnsq$EXE" ./cmd/dnsq) || { echo "go build failed" >&2; exit 1; }
}

start_dnsr() {
  local log="$1"; shift
  mkdir -p "$LOGS"
  printf '\n\033[33m$ dnsr serve %s &\033[0m\n' "$*"
  "$DNSR" serve "$@" 2>"$log" &
  SERVER_PID=$!
  for _ in $(seq 50); do
    grep -q 'accepting clients' "$log" 2>/dev/null && break
    sleep 0.1
  done
}

stop_dnsr() {
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  printf '\n\033[2m--- server log ---\033[0m\n'
  head -15 "$1"
  local n; n=$(wc -l <"$1")
  (( n > 15 )) && printf '\033[2m... %d more lines in %s\033[0m\n' $((n - 15)) "$1"
  return 0
}

s_build() {
  cd "$ROOT" || exit 1
  run go version
  run go build -o "bin/dnsr$EXE" ./cmd/dnsr && run go build -o "bin/dnsq$EXE" ./cmd/dnsq && echo BUILD_OK
}

s_usage() { need_build; run "$DNSR"; }
s_lookup() { need_build; run "$DNSR" www.github.com; }

s_types() {
  need_build
  run "$DNSR" -t MX gmail.com
  run "$DNSR" -t AAAA www.wikipedia.org
  run "$DNSR" -t NS vit.ac.in
  run "$DNSR" -q -t MX gmail.com yahoo.com
  run "$DNSR" -q -t TXT google.com
  run "$DNSR" -q -t SOA google.com
  run "$DNSR" -q -t PTR 8.8.8.8.in-addr.arpa
  run "$DNSR" -q -t DS cloudflare.com
  run "$DNSR" -q -t DNSKEY iana.org
}

s_negative() {
  need_build
  run "$DNSR" this-name-does-not-exist-dnsr-vit.com
  run "$DNSR" -t AAAA github.com
}

s_cache() { need_build; run "$DNSR" www.github.com api.github.com www.github.com; }
s_nomin() { need_build; run "$DNSR" -nomin www.github.com; }
s_glueless() { need_build; run "$DNSR" github.io; }
s_tcp() { need_build; run "$DNSR" -t TXT apple.com; }

s_dnssec() {
  need_build
  run "$DNSR" -dnssec cloudflare.com
  run "$DNSR" -q -dnssec github.com dnssec-failed.org iana.org
}

s_server() {
  need_build
  local log="$LOGS/serve.log"
  start_dnsr "$log" -dnssec -addr 127.0.0.1:8053 -dot 127.0.0.1:8853 -selfsigned
  run "$DNSQ" -s 127.0.0.1:8053 www.cloudflare.com
  run "$DNSQ" -s 127.0.0.1:8053 -tcp iana.org
  run "$DNSQ" -s 127.0.0.1:8853 -tls isc.org github.com
  run "$DNSQ" -s 127.0.0.1:8053 dnssec-failed.org
  run "$DNSQ" -s 127.0.0.1:8053 -do -t MX gmail.com
  run "$DNSQ" -s 127.0.0.1:8853 -tls -tls12 example.com
  run "$DNSQ" -s 127.0.0.1:8053 -n 60 www.cloudflare.com
  stop_dnsr "$log"
}

s_acl() {
  need_build
  local log="$LOGS/acl_serve.log"
  start_dnsr "$log" -addr 127.0.0.1:8054 -allow 10.0.0.0/8
  run "$DNSQ" -s 127.0.0.1:8054 example.com
  stop_dnsr "$log"
}

s_compare() {
  need_build
  local domains=(google.com www.github.com www.wikipedia.org amazon.com vit.ac.in microsoft.com cloudflare.com
    stackoverflow.com example.com gmail.com netflix.com iana.org python.org go.dev github.io)
  local same=0 d mine rc hops ms rrc ok
  printf '\n%-20s %-9s %5s %9s   %-9s %s\n' domain dnsr hops time 8.8.8.8 match
  printf '%.0s-' {1..66}; echo
  for d in "${domains[@]}"; do
    mine="$("$DNSR" -q -nocolor "$d" | grep -E '^;; [A-Z]+ ' | head -1)"
    rc="$(sed -E 's/^;; ([A-Z]+).*/\1/' <<<"$mine")"; rc="${rc:-ERROR}"
    hops="$(sed -nE 's/.* ([0-9]+) hops .*/\1/p' <<<"$mine")"
    ms="$(sed -nE 's/.* hops · (.*)$/\1/p' <<<"$mine")"
    rrc=""
    for _ in 1 2; do
      [[ -n "$rrc" ]] && break
      rrc="$("$DNSQ" -s 8.8.8.8:53 -timeout 5s "$d" | sed -nE 's/.*status: ([A-Z]+).*/\1/p')"
    done
    rrc="${rrc:-ERROR}"
    ok=NO; [[ "$rc" == "$rrc" ]] && { ok=yes; same=$((same + 1)); }
    printf '%-20s %-9s %5s %9s   %-9s %s\n' "$d" "$rc" "${hops:--}" "${ms:--}" "$rrc" "$ok"
  done
  printf '\n\033[32m%d of %d response codes match Google Public DNS\033[0m\n' "$same" "${#domains[@]}"
}

s_tests() {
  cd "$ROOT" || exit 1
  run go vet ./...
  run go test -v -count=1 ./...
  run go test -race -count=1 ./... || echo "(the race detector needs cgo and a C compiler; skip it if that is missing)"
}

s_fuzz() {
  cd "$ROOT" || exit 1
  run go test -v -count=1 -run TestRandomAndMutatedPackets ./internal/wire
  run go test -run '^$' -fuzz FuzzParseMessage -fuzztime 30s ./internal/wire
}

s_bench() {
  cd "$ROOT" || exit 1
  run go test -run '^$' -bench . -benchmem ./...
}

if [[ "${1:-}" == "-l" ]]; then
  for s in "${SECTIONS[@]}"; do printf '%-9s %s\n' "$s" "${DESC[$s]}"; done
  exit 0
fi
chosen=("$@")
if [[ ${#chosen[@]} -eq 0 ]]; then
  for s in "${SECTIONS[@]}"; do
    [[ -n "${NOGO:-}" && "$GO_SECTIONS" == *" $s "* ]] || chosen+=("$s")
  done
fi
for s in "${chosen[@]}"; do
  [[ -n "${DESC[$s]:-}" ]] || { echo "unknown section '$s' (use -l)" >&2; exit 2; }
done
[[ -n "${NOGO:-}" ]] && build_quiet
first=1
for s in "${chosen[@]}"; do
  [[ -n "${PAUSE:-}" && $first -eq 0 ]] && read -rp $'\nPress Enter for '"'$s'" _
  first=0
  banner "$s"
  "s_$s"
done
