package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func queryFromWire(wire []byte) query {
	var m dnsmessage.Message
	if err := m.Unpack(wire); err != nil || len(m.Questions) != 1 {
		panic("invalid test query")
	}
	return query{question: m.Questions[0], wire: wire, id: m.ID}
}

func readFrame(conn net.Conn) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	_, err := io.ReadFull(conn, wire)
	return wire, err
}

func writeFrame(conn net.Conn, wire []byte) {
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
	// Deliberately split the length prefix and body across writes.
	conn.Write(prefix[:1])
	conn.Write(prefix[1:])
	conn.Write(wire[:3])
	conn.Write(wire[3:])
}

func tcpServer(t *testing.T, respond func(query) []byte) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				wire, err := readFrame(conn)
				if err != nil {
					return
				}
				response := respond(queryFromWire(wire))
				if len(response) >= 3 {
					writeFrame(conn, response)
				}
			}()
		}
	}()
	return listener
}

func TestResolverValidation(t *testing.T) {
	for _, input := range []string{"cf=https://cloudflare-dns.com/dns-query", "a=udp://1.1.1.1", "b=tcp://127.0.0.1:5300", "v6=udp://[2606:4700:4700::1111]"} {
		if _, err := parseResolver(input); err != nil {
			t.Errorf("%s: %v", input, err)
		}
	}
	for _, input := range []string{"no-equals", "=https://a/dns-query", "bad name=udp://1.1.1.1", "a=http://example.com/dns-query", "a=https://user:pass@example.com/dns-query", "a=https://example.com/dns-query#fragment", "a=https:///dns-query", "a=https://example.com", "a=udp://example.com", "a=udp://1.1.1.1/path", "a=udp://1.1.1.1?foo=bar", "a=tcp://1.1.1.1:0", "a=tcp://1.1.1.1:65536", "a=tcp://1.1.1.1:abc"} {
		if _, err := parseResolver(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	r, _ := parseResolver("v6=udp://[::1]")
	if r.address != "[::1]:53" {
		t.Fatal(r.address)
	}
}

func TestTCPFragmentedFrameAndRcodes(t *testing.T) {
	for _, code := range []dnsmessage.RCode{dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError, dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused} {
		t.Run(rcodeName(code), func(t *testing.T) {
			listener := tcpServer(t, func(q query) []byte { return reply(q, code) })
			r, _ := parseResolver("local=tcp://" + listener.Addr().String())
			q := testQuery(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient())
			if out.RCode != rcodeName(code) {
				t.Fatalf("%+v", out)
			}
			shouldFail := code != dnsmessage.RCodeSuccess && code != dnsmessage.RCodeNameError
			if (out.Error != "") != shouldFail {
				t.Fatalf("%+v", out)
			}
		})
	}
}

func TestUDPTruncationFallsBackToTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	listener := tcpServer(t, func(q query) []byte {
		tcpCalls.Add(1)
		return reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 9))
	})
	udp, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		body := make([]byte, maxMessage)
		n, address, err := udp.ReadFrom(body)
		if err != nil {
			return
		}
		q := queryFromWire(body[:n])
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.id, Response: true, Truncated: true}, Questions: []dnsmessage.Question{q.question}}
		wire, _ := m.Pack()
		udp.WriteTo(wire, address)
	}()
	r, _ := parseResolver("local=udp://" + listener.Addr().String())
	q := testQuery(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient())
	if out.Error != "" || out.Transport != "udp+tcp" || len(out.Answers) != 1 || out.Answers[0].Value != "192.0.2.9" || tcpCalls.Load() != 1 {
		t.Fatalf("%+v; TCP calls %d", out, tcpCalls.Load())
	}
}

func TestUDPIgnoresOtherTransaction(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		body := make([]byte, maxMessage)
		n, address, err := udp.ReadFrom(body)
		if err != nil {
			return
		}
		q := queryFromWire(body[:n])
		wrong := q
		wrong.id++
		udp.WriteTo(reply(wrong, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 2)), address)
		udp.WriteTo(reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1)), address)
	}()
	r, _ := parseResolver("local=udp://" + udp.LocalAddr().String())
	q := testQuery(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient())
	if out.Error != "" || len(out.Answers) != 1 || out.Answers[0].Value != "192.0.2.1" {
		t.Fatalf("%+v", out)
	}
}

func TestUDPCancellation(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	r, _ := parseResolver("local=udp://" + udp.LocalAddr().String())
	q := testQuery(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	started := time.Now()
	out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient())
	if out.Error == "" || time.Since(started) > time.Second {
		t.Fatalf("cancellation was not bounded: %+v", out)
	}
}

func TestDoH(t *testing.T) {
	q := testQuery(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Accept") != "application/dns-message" {
			http.Error(w, "wrong request", 400)
			return
		}
		wire, _ := io.ReadAll(r.Body)
		incoming := queryFromWire(wire)
		if incoming.id != 0 {
			http.Error(w, "DoH ID must be zero", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(reply(incoming, dnsmessage.RCodeSuccess, addressAnswer(incoming, 90, 3)))
	}))
	defer server.Close()
	r, _ := parseResolver("local=" + server.URL + "/dns-query")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := lookup(ctx, q.question.Name, q.question.Type, r, server.Client())
	if out.Error != "" || len(out.Answers) != 1 || out.Answers[0].Value != "192.0.2.3" {
		t.Fatalf("%+v", out)
	}
}

func TestDoHFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"HTTP failure", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, "status 503"},
		{"wrong content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		}, "application/dns-message"},
		{"large content length", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Header().Set("Content-Length", "65536")
		}, "exceeds 65535"},
		{"chunked oversized body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.(http.Flusher).Flush()
			w.Write(bytes.Repeat([]byte{0}, maxMessage+1))
		}, "exceeds 65535"},
		{"malformed DNS", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write([]byte{0, 0})
		}, "invalid DNS"},
		{"slow response body", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}, "context deadline exceeded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			q := testQuery(t)
			r, _ := parseResolver("local=" + server.URL + "/dns-query")
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			out := lookup(ctx, q.question.Name, q.question.Type, r, server.Client())
			if !strings.Contains(out.Error, test.want) {
				t.Fatalf("got %q, want %q", out.Error, test.want)
			}
		})
	}
}

func TestDoHDoesNotFollowRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/destination" {
			destinationCalls.Add(1)
			return
		}
		http.Redirect(w, r, "/destination", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = httpClient().CheckRedirect
	q := testQuery(t)
	r, _ := parseResolver("local=" + server.URL + "/dns-query")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := lookup(ctx, q.question.Name, q.question.Type, r, client)
	if !strings.Contains(out.Error, "redirect") || destinationCalls.Load() != 0 {
		t.Fatalf("%+v; redirected %d", out, destinationCalls.Load())
	}
}

func TestTCPFallbackSharesDeadline(t *testing.T) {
	listener := tcpServer(t, func(q query) []byte { time.Sleep(400 * time.Millisecond); return reply(q, dnsmessage.RCodeSuccess) })
	udp, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		body := make([]byte, maxMessage)
		n, address, err := udp.ReadFrom(body)
		if err != nil {
			return
		}
		q := queryFromWire(body[:n])
		time.Sleep(200 * time.Millisecond)
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.id, Response: true, Truncated: true}, Questions: []dnsmessage.Question{q.question}}
		wire, _ := m.Pack()
		udp.WriteTo(wire, address)
	}()
	r, _ := parseResolver("local=udp://" + listener.Addr().String())
	q := testQuery(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient())
	if out.Error == "" || out.Transport != "udp+tcp" || time.Since(started) > 430*time.Millisecond {
		t.Fatalf("fallback reset the deadline: %+v", out)
	}
}

func TestTCPMalformedFrames(t *testing.T) {
	for _, frame := range [][]byte{{0, 1, 0}, {0, 12, 0, 0}} {
		t.Run(fmt.Sprint(frame), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				readFrame(conn)
				conn.Write(frame)
			}()
			q := testQuery(t)
			r, _ := parseResolver("local=tcp://" + listener.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if out := lookup(ctx, q.question.Name, q.question.Type, r, httpClient()); out.Error == "" {
				t.Fatal("accepted short frame")
			}
		})
	}
}
