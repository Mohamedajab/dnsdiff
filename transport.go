package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxMessage = 65535

type resolver struct {
	name     string
	endpoint string
	scheme   string
	address  string
}

type result struct {
	Resolver          string   `json:"resolver"`
	Endpoint          string   `json:"endpoint"`
	Transport         string   `json:"transport"`
	RCode             string   `json:"rcode,omitempty"`
	AuthenticatedData bool     `json:"ad"`
	DurationMS        float64  `json:"duration_ms"`
	Answers           []answer `json:"answers"`
	Group             int      `json:"group"`
	Error             string   `json:"error,omitempty"`
}

func parseResolver(input string) (resolver, error) {
	name, endpoint, ok := strings.Cut(input, "=")
	if !ok || len(name) == 0 || len(name) > 32 {
		return resolver{}, fmt.Errorf("resolver must be name=endpoint (name: 1–32 letters, digits, hyphens or underscores)")
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return resolver{}, fmt.Errorf("invalid resolver name %q", name)
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 4096 {
		return resolver{}, fmt.Errorf("invalid resolver URL")
	}
	if u.User != nil || u.Fragment != "" || u.Hostname() == "" || u.Opaque != "" {
		return resolver{}, fmt.Errorf("resolver URLs must have a host, without credentials or a fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return resolver{}, fmt.Errorf("resolver port must be 1–65535")
		}
	}
	r := resolver{name: name, endpoint: endpoint, scheme: u.Scheme}
	switch u.Scheme {
	case "https":
		if u.Path == "" {
			return resolver{}, fmt.Errorf("DoH endpoint must include a path such as /dns-query")
		}
	case "udp", "tcp":
		if _, err := netip.ParseAddr(u.Hostname()); err != nil {
			return resolver{}, fmt.Errorf("UDP/TCP resolver must use a literal IP address")
		}
		if u.Path != "" || u.RawQuery != "" {
			return resolver{}, fmt.Errorf("UDP/TCP resolver cannot include a path or query")
		}
		port := u.Port()
		if port == "" {
			port = "53"
		}
		r.address = net.JoinHostPort(u.Hostname(), port)
	default:
		return resolver{}, fmt.Errorf("resolver scheme must be https, udp or tcp")
	}
	return r, nil
}

func httpClient() *http.Client {
	return &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("DoH redirects are not followed") }}
}

func doh(ctx context.Context, client *http.Client, endpoint string, wire []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %d", response.StatusCode)
	}
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || contentType != "application/dns-message" {
		return nil, fmt.Errorf("DoH response must be application/dns-message")
	}
	if response.ContentLength > maxMessage {
		return nil, fmt.Errorf("DoH response exceeds 65535 bytes")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMessage+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMessage {
		return nil, fmt.Errorf("DoH response exceeds 65535 bytes")
	}
	return body, nil
}

func socket(ctx context.Context, network, address string, q query) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if network == "udp" {
		if _, err := conn.Write(q.wire); err != nil {
			return nil, err
		}
		body := make([]byte, maxMessage)
		for {
			n, err := conn.Read(body)
			if err != nil {
				return nil, err
			}
			// Ignore other transactions on the connected socket until this query's deadline.
			if n >= 2 && binary.BigEndian.Uint16(body[:2]) != q.id {
				continue
			}
			return body[:n], nil
		}
	}
	frame := make([]byte, len(q.wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(q.wire)))
	copy(frame[2:], q.wire)
	if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n < 12 {
		return nil, fmt.Errorf("DNS TCP frame is shorter than its header")
	}
	body := make([]byte, n)
	_, err = io.ReadFull(conn, body)
	return body, err
}

func lookup(ctx context.Context, name dnsmessage.Name, kind dnsmessage.Type, r resolver, client *http.Client) (out result) {
	out = result{Resolver: r.name, Endpoint: r.endpoint, Transport: r.scheme, Answers: []answer{}}
	started := time.Now()
	defer func() { out.DurationMS = float64(time.Since(started).Microseconds()) / 1000 }()
	q, err := makeQuery(name, kind, r.scheme == "https")
	if err != nil {
		out.Error = err.Error()
		return
	}
	var wire []byte
	if r.scheme == "https" {
		wire, err = doh(ctx, client, r.endpoint, q.wire)
	} else {
		wire, err = socket(ctx, r.scheme, r.address, q)
	}
	if err != nil {
		out.Error = err.Error()
		return
	}
	h, err := envelope(wire, q)
	if err != nil {
		out.Error = err.Error()
		return
	}
	if h.Truncated && r.scheme == "udp" {
		out.Transport = "udp+tcp"
		wire, err = socket(ctx, "tcp", r.address, q)
		if err != nil {
			out.Error = fmt.Sprintf("TCP fallback: %v", err)
			return
		}
	}
	h, answers, err := decode(wire, q)
	if err != nil {
		out.Error = err.Error()
		return
	}
	out.RCode = rcodeName(h.RCode)
	out.AuthenticatedData = h.AuthenticData
	out.Answers = answers
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		out.Error = "resolver returned " + out.RCode
	}
	return
}
