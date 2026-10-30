# Design

```text
flags → validated question + resolver list
                         ↓ concurrent, one deadline each
              UDP / TCP / HTTPS exchange
                         ↓
          validate envelope → decode answer records
                         ↓
            canonical answer sets → groups → report
```

## Transport

UDP and TCP queries use cryptographically random transaction IDs. DoH queries use
ID zero, following the recommendation in [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).
DoH sends the same DNS wireformat used by the socket transports, rather than a
provider-specific JSON API.

Each resolver gets a context with one deadline. Socket reads/writes use that deadline;
cancellation closes the socket. A connected UDP socket filters the peer address,
and replies for other transaction IDs are ignored until the original deadline.

A UDP response with TC set is retried over TCP, without restarting the timeout.
The response header and question are checked before taking that fallback. TCP
uses a two-byte network-order length prefix and `io.ReadFull` for partial reads.
Short frames and truncated TCP responses fail the query.

DoH uses normal certificate verification, bounded response reads and no redirects.
HTTP 200 and `application/dns-message` are required. Body reads stop above 65,535
bytes even when Content-Length is absent. Query names are not placed in the URL.

## Parsing

`golang.org/x/net/dns/dnsmessage` handles wire decoding and compressed names. This
project handles transport, envelope validation, record presentation and comparison.
It does not implement another DNS compression parser.

Every reply must be a standard response with the expected transaction ID and exactly
one matching IN-class question. Both the record type and case-insensitive name must
match. SERVFAIL, REFUSED and other failure codes stay in the report and cause exit 2.
NXDOMAIN is kept as a valid negative answer.

## Comparison

Each answer becomes an owner/type/value tuple. DNS-name fields are lowercased,
addresses use canonical textual form, and TXT strings retain their case and chunk
boundaries. JSON serialization separates tuple fields without delimiter ambiguity.
The tuples are deduplicated, sorted and compared together with the response code.
TTLs remain in output but do not participate in equality.

Groups are numbered by first occurrence in the configured resolver order. A failed
query gets group zero; completed queries still receive groups. Errors make the
overall comparison incomplete rather than allowing one successful response to be
presented as agreement between all resolvers.

Each goroutine writes to its own result slot. Formatting happens after the wait
group completes. DNS strings and error text containing terminal control characters
are escaped before text output; JSON uses Go's encoder.

## Scope

There is one query per selected resolver, with an optional TCP retry. dnsdiff does
not run a resolver, cache responses, scan networks or decide which provider is
correct. Comparing answer sets is useful when investigating differences, but the
report needs context about the domain and network.

Protocol references: [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035),
[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766),
[Cloudflare's DoH wireformat](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/).
