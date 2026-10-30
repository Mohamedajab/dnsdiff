# Verification

Local checks on 30 October 2026 used Go 1.27.3, Windows/amd64 and an Intel
Core i7-10875H. All network tests in the Go suite use loopback servers.

| Check | Result |
| --- | --- |
| `go test -count=1 -coverprofile coverage.out ./...` | Passed; 93.0% statement coverage |
| `go vet ./...` | Passed |
| `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` | No vulnerabilities found |
| `go test -run '^$' -fuzz FuzzDecode -fuzztime 20s -parallel 2` | Passed; 136,731 executions in approximately 21.5 seconds |
| Three `BenchmarkDecode` repeats | 1,289–1,418 ns/op, 960 B/op, 7 allocations/op |

The microbenchmark decodes one successful IPv4 response. It excludes networking,
comparison and output; it is not an end-to-end throughput result. Coverage does
not establish protocol completeness, and the bounded fuzz run does not prove the
parser cannot fail on another packet.

The suite covers transaction and question mismatches, malformed packets, all
supported record types, TTL/order differences, TXT boundaries, NXDOMAIN versus
NODATA, SERVFAIL, concurrency, cancellation, shared fallback deadlines, partial
TCP frames, DoH redirects/content types/body limits, JSON/exit codes and terminal
control characters. CI also runs the race detector on Linux.

## Real-network samples

These commands were run from the same machine on 30 October 2026:

```sh
dnsdiff -json example.com
dnsdiff -json dnsdiff-check.invalid
dnsdiff -resolver udp=udp://1.1.1.1 -resolver tcp=tcp://1.1.1.1 -timeout 3s -json example.com
```

- [example-com.json](examples/example-com.json): Cloudflare and Google over DoH,
  matching A records despite different TTLs.
- [nxdomain.json](examples/nxdomain.json): both resolvers returned NXDOMAIN.
- [transports.json](examples/transports.json): UDP and TCP returned matching answers.

All three commands exited zero. These are point-in-time responses; DNS data and
timing can change. The local truncation test exercises UDP-to-TCP fallback because
a small public A response does not reliably trigger truncation.

Release archives are cross-compiled for Linux, macOS and Windows on amd64 and
arm64. Tests run natively on the CI runner's architecture for each OS; an arm64
cross-build alone is not a native arm64 runtime test.
