# dnsdiff

Compare DNS answers from multiple resolvers over UDP, TCP or HTTPS. The report
groups equivalent answer sets, shows resolver errors and retains TTLs for inspection.
TTL countdowns and record order do not count as differences.

```text
$ dnsdiff example.com
example.com. A

cloudflare  https  380.61 ms  NOERROR  group 1  AD=false
  example.com.  A  172.66.147.243  TTL 212
  example.com.  A  104.20.23.154   TTL 212

google  https  161.78 ms  NOERROR  group 1  AD=false
  example.com.  A  172.66.147.243  TTL 300
  example.com.  A  104.20.23.154   TTL 300

MATCH: resolvers returned the same DNS status and answer set.
```

This is a recorded query, not fixed output. Addresses, TTLs and timings change.

## Install

Download a binary for Windows, macOS or Linux from [Releases](https://github.com/Mohamedajab/dnsdiff/releases).
Archives include the licence and dependency notices; `SHA256SUMS.txt` lists their hashes.

With Go 1.27 or later:

```sh
go install github.com/Mohamedajab/dnsdiff@latest
```

Or clone this repo and run `go build -o dnsdiff .` (`dnsdiff.exe` on Windows).

## Examples

```sh
dnsdiff example.com
dnsdiff -type AAAA cloudflare.com
dnsdiff -type MX -json example.com
dnsdiff -resolver cloudflare=udp://1.1.1.1 -resolver google=udp://8.8.8.8 example.com
dnsdiff -resolver udp=udp://1.1.1.1 -resolver tcp=tcp://1.1.1.1 example.com
dnsdiff -resolver local=udp://127.0.0.1:5353 -timeout 1s example.com
dnsdiff -resolver v6=udp://[2606:4700:4700::1111] example.com
```

Put flags before the domain. Supported query types: `A`, `AAAA`, `CNAME`, `MX`,
`TXT`, `NS` and `SOA`. ASCII names, including underscore labels and the root `.`,
are accepted. Convert international names to punycode first.

Without `-resolver`, queries go to Cloudflare and Google over HTTPS. Custom flags
replace those defaults. Up to eight uniquely named resolvers run concurrently.
UDP and TCP endpoints require literal IP addresses and default to port 53.
HTTPS endpoints use POST with DNS wireformat, verified TLS and no redirects.

The default deadline is three seconds per resolver. It covers connection setup,
response reading and UDP-to-TCP fallback. `-timeout` accepts 50 ms through 30 seconds.
Ctrl+C cancels outstanding work. Reports keep the resolver order from the command.

## Reading the result

| Exit code | Meaning |
| --- | --- |
| `0` | Every resolver completed and returned the same DNS status and answer set. |
| `1` | Completed responses differ. |
| `2` | Invalid input, a transport/protocol error, or a resolver failure such as SERVFAIL. |

`NXDOMAIN` is a completed negative answer, so two matching NXDOMAIN responses exit
zero. An empty NOERROR answer and NXDOMAIN are different. A match describes agreement;
it does not establish that the domain exists or that an answer is correct.

Groups compare record owner, type and value. Answer order, duplicates and TTLs are
excluded. DNS names are case-insensitive; TXT bytes and chunk boundaries are retained.
One failed resolver makes the report `incomplete`, while successful groups remain visible.
`-json` writes the same results, including errors and actual transport (`udp+tcp`
when a truncated UDP answer required fallback).

For JSON automation, read the report even if the exit code is non-zero. No output
file is written automatically. Shell redirection can be used to save it.

## Checks

```sh
go test -count=1 -coverprofile coverage.out ./...
go vet ./...
go test -race ./...
go test -run '^$' -fuzz FuzzDecode -fuzztime 20s -parallel 2
go test -run '^$' -bench BenchmarkDecode -benchmem -count 3
```

Tests use local UDP/TCP servers and trusted local HTTPS servers. They require no
public DNS service. CI checks Linux, macOS and Windows, with race detection,
fuzzing and vulnerability checks on Linux. Releases are built only after checks pass.

[Design notes](docs/design.md) cover framing, validation and comparison.
[Verification](docs/verification.md) records local results and real-network samples.

## Limits

- Different answers can be normal for CDNs, geographic routing, split DNS and
  cache age. A disagreement is an observation, not a diagnosis of poisoning or censorship.
- AD is the resolver's authenticated-data flag. dnsdiff does not independently
  validate DNSSEC signatures. UDP and TCP are unencrypted.
- DoH endpoint hostnames are bootstrapped through the operating system resolver.
  HTTPS proxy environment settings are respected. The selected resolvers see your queries;
  the tool has no telemetry, query history or background service.
- The tool compares the answer section. It does not walk delegation chains,
  compare authority/additional records, or implement dig's full feature set.
- Timing includes connection setup and, for DoH, TLS and endpoint-name resolution.
  A single run is not a resolver speed ranking. There is no EDNS Client Subnet or
  HTTP/3 support, and DoH responses are not cached locally.

MIT licence. Go and `golang.org/x/net` notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
