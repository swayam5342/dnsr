# demo.ps1 - runs every demonstration shown in the project report, section by section.
#
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1              # everything
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 dnssec server # chosen sections
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -List         # list sections
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -Pause        # wait for Enter between sections
#
# The live sections need outbound UDP/TCP port 53 to the internet; the test,
# fuzz and bench sections run fully offline.

param(
    [Parameter(ValueFromRemainingArguments = $true)] [string[]] $Sections,
    [switch] $List,
    [switch] $Pause
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root 'bin'
$Dnsr = Join-Path $Bin 'dnsr.exe'
$Dnsq = Join-Path $Bin 'dnsq.exe'
$Logs = Join-Path $Root 'scripts\out'

$All = [ordered]@{
    build    = 'Build dnsr and the dnsq test client'
    usage    = 'Command-line usage'
    lookup   = 'Iterative lookup from the root, with QNAME minimisation and a CNAME'
    types    = 'Record types: MX, AAAA, NS, TXT, SOA, PTR, DS, DNSKEY and quiet mode'
    negative = 'NXDOMAIN and NODATA answers'
    cache    = 'Answer and delegation cache across several names'
    nomin    = 'The same lookup without QNAME minimisation'
    glueless = 'Glueless delegation (nameserver address resolved first)'
    tcp      = 'Truncated UDP reply retried over TCP'
    dnssec   = 'DNSSEC validation: secure, insecure and bogus'
    server   = 'Recursive server over UDP, TCP and DNS over TLS 1.3, with rate limit'
    acl      = 'Server access list: clients outside -allow get REFUSED'
    compare  = 'Correctness against Google Public DNS (8.8.8.8) for 15 domains'
    tests    = 'Offline unit tests on the fake DNS hierarchy (and the race detector)'
    fuzz     = 'Parser robustness: 1,000,000 random packets and native fuzzing'
    bench    = 'Benchmarks: parse, build query, ECDSA signature check'
}

function Banner($name) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host (" {0}: {1}" -f $name, $All[$name]) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Show-Command([string] $exe, [string[]] $argv) {
    $shown = (Split-Path -Leaf $exe) -replace '\.exe$', ''
    Write-Host ''
    Write-Host ("PS> {0} {1}" -f $shown, ($argv -join ' ')) -ForegroundColor Yellow
}

function Run([string] $exe, [string[]] $argv) {
    Show-Command $exe $argv
    & $exe @argv
}

function Start-Dnsr([string[]] $argv, [string] $log) {
    New-Item -ItemType Directory -Force $Logs | Out-Null
    Show-Command $Dnsr (@('serve') + $argv)
    $p = Start-Process -FilePath $Dnsr -ArgumentList (@('serve') + $argv) -RedirectStandardError $log `
        -RedirectStandardOutput "$log.stdout" -PassThru -NoNewWindow
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 100
        if ((Test-Path $log) -and (Select-String -Path $log -Pattern 'accepting clients' -Quiet)) { break }
    }
    return $p
}

function Stop-Dnsr($p, [string] $log) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $p.WaitForExit()
    Write-Host ''
    Write-Host '--- server log ---' -ForegroundColor DarkGray
    $lines = @(Get-Content -Encoding UTF8 $log)
    $lines | Select-Object -First 15
    if ($lines.Count -gt 15) { Write-Host ("... {0} more lines in {1}" -f ($lines.Count - 15), $log) -ForegroundColor DarkGray }
}

function Need-Build {
    if (-not (Test-Path $Dnsr) -or -not (Test-Path $Dnsq)) { Section-build }
}

function Section-build {
    Push-Location $Root
    try {
        Run 'go' @('version')
        Run 'go' @('build', '-o', 'bin\dnsr.exe', './cmd/dnsr')
        Run 'go' @('build', '-o', 'bin\dnsq.exe', './cmd/dnsq')
        if ($LASTEXITCODE -eq 0) { Write-Host 'BUILD_OK' -ForegroundColor Green }
    } finally { Pop-Location }
}

function Section-usage { Need-Build; Run $Dnsr @(); $global:LASTEXITCODE = 0 }

function Section-lookup { Need-Build; Run $Dnsr @('www.github.com') }

function Section-types {
    Need-Build
    Run $Dnsr @('-t', 'MX', 'gmail.com')
    Run $Dnsr @('-t', 'AAAA', 'www.wikipedia.org')
    Run $Dnsr @('-t', 'NS', 'vit.ac.in')
    Run $Dnsr @('-q', '-t', 'MX', 'gmail.com', 'yahoo.com')
    Run $Dnsr @('-q', '-t', 'TXT', 'google.com')
    Run $Dnsr @('-q', '-t', 'SOA', 'google.com')
    Run $Dnsr @('-q', '-t', 'PTR', '8.8.8.8.in-addr.arpa')
    Run $Dnsr @('-q', '-t', 'DS', 'cloudflare.com')
    Run $Dnsr @('-q', '-t', 'DNSKEY', 'iana.org')
}

function Section-negative {
    Need-Build
    Run $Dnsr @('this-name-does-not-exist-dnsr-vit.com')
    Run $Dnsr @('-t', 'AAAA', 'github.com')
}

function Section-cache { Need-Build; Run $Dnsr @('www.github.com', 'api.github.com', 'www.github.com') }

function Section-nomin { Need-Build; Run $Dnsr @('-nomin', 'www.github.com') }

function Section-glueless { Need-Build; Run $Dnsr @('github.io') }

function Section-tcp { Need-Build; Run $Dnsr @('-t', 'TXT', 'apple.com') }

function Section-dnssec {
    Need-Build
    Run $Dnsr @('-dnssec', 'cloudflare.com')
    Run $Dnsr @('-q', '-dnssec', 'github.com', 'dnssec-failed.org', 'iana.org')
}

function Section-server {
    Need-Build
    $log = Join-Path $Logs 'serve.log'
    $p = Start-Dnsr @('-dnssec', '-addr', '127.0.0.1:8053', '-dot', '127.0.0.1:8853', '-selfsigned') $log
    try {
        Run $Dnsq @('-s', '127.0.0.1:8053', 'www.cloudflare.com')
        Run $Dnsq @('-s', '127.0.0.1:8053', '-tcp', 'iana.org')
        Run $Dnsq @('-s', '127.0.0.1:8853', '-tls', 'isc.org', 'github.com')
        Run $Dnsq @('-s', '127.0.0.1:8053', 'dnssec-failed.org')
        Run $Dnsq @('-s', '127.0.0.1:8053', '-do', '-t', 'MX', 'gmail.com')
        Run $Dnsq @('-s', '127.0.0.1:8853', '-tls', '-tls12', 'example.com')
        Run $Dnsq @('-s', '127.0.0.1:8053', '-n', '60', 'www.cloudflare.com')
    } finally { Stop-Dnsr $p $log }
    $global:LASTEXITCODE = 0
}

function Section-acl {
    Need-Build
    $log = Join-Path $Logs 'acl_serve.log'
    $p = Start-Dnsr @('-addr', '127.0.0.1:8054', '-allow', '10.0.0.0/8') $log
    try {
        Run $Dnsq @('-s', '127.0.0.1:8054', 'example.com')
    } finally { Stop-Dnsr $p $log }
}

function Section-compare {
    Need-Build
    $domains = 'google.com', 'www.github.com', 'www.wikipedia.org', 'amazon.com', 'vit.ac.in',
        'microsoft.com', 'cloudflare.com', 'stackoverflow.com', 'example.com', 'gmail.com',
        'netflix.com', 'iana.org', 'python.org', 'go.dev', 'github.io'
    Write-Host ''
    Write-Host ("{0,-20} {1,-9} {2,5} {3,9}   {4,-9} {5}" -f 'domain', 'dnsr', 'hops', 'time', '8.8.8.8', 'match')
    Write-Host ('-' * 66)
    $same = 0
    foreach ($d in $domains) {
        $mine = (& $Dnsr -q -nocolor $d) -join "`n"
        $rc, $hops, $ms = 'ERROR', '-', '-'
        if ($mine -match ';; (\w+)(?: \S+ \w+)? \S+ (\d+) hops \S+ (\S+)') { $rc, $hops, $ms = $Matches[1], $Matches[2], $Matches[3] }
        $rrc = 'ERROR'
        for ($try = 0; $try -lt 2 -and $rrc -eq 'ERROR'; $try++) {
            $ref = (& $Dnsq -s 8.8.8.8:53 -timeout 5s $d) -join "`n"
            if ($ref -match 'status: (\w+)') { $rrc = $Matches[1] }
        }
        $ok = $rc -eq $rrc
        if ($ok) { $same++ }
        Write-Host ("{0,-20} {1,-9} {2,5} {3,9}   {4,-9} {5}" -f $d, $rc, $hops, $ms, $rrc, $(if ($ok) { 'yes' } else { 'NO' }))
    }
    Write-Host ''
    Write-Host ("{0} of {1} response codes match Google Public DNS" -f $same, $domains.Count) -ForegroundColor Green
    $global:LASTEXITCODE = 0
}

function Section-tests {
    Push-Location $Root
    try {
        Run 'go' @('vet', './...')
        Run 'go' @('test', '-v', '-count=1', './...')
        Run 'go' @('test', '-race', '-count=1', './...')
        if ($LASTEXITCODE -ne 0) { Write-Host '(the race detector needs cgo and a C compiler; skip it if that is missing)' -ForegroundColor DarkGray }
    } finally { Pop-Location }
}

function Section-fuzz {
    Push-Location $Root
    try {
        Run 'go' @('test', '-v', '-count=1', '-run', 'TestRandomAndMutatedPackets', './internal/wire')
        Run 'go' @('test', '-run', '^$', '-fuzz', 'FuzzParseMessage', '-fuzztime', '30s', './internal/wire')
    } finally { Pop-Location }
}

function Section-bench {
    Push-Location $Root
    try { Run 'go' @('test', '-run', '^$', '-bench', '.', '-benchmem', './...') } finally { Pop-Location }
}

if ($List) {
    $All.GetEnumerator() | ForEach-Object { '{0,-9} {1}' -f $_.Key, $_.Value }
    return
}
if (-not $Sections) { $Sections = @($All.Keys) }
foreach ($s in $Sections) {
    if (-not $All.Contains($s)) { throw "unknown section '$s' (use -List)" }
}
$first = $true
foreach ($s in $Sections) {
    if ($Pause -and -not $first) { Read-Host "`nPress Enter for '$s'" | Out-Null }
    $first = $false
    Banner $s
    & "Section-$s"
}
