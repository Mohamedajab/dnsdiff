package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-version"}} {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), args, &out, &stderr); code != 0 {
			t.Fatalf("%v: %d %s", args, code, stderr.String())
		}
	}
	tests := [][]string{
		nil, {"-unknown"}, {"example.com", "extra"}, {"https://example.com"},
		{"-type", "ANY", "example.com"}, {"-timeout", "1ms", "example.com"},
		{"-timeout", "31s", "example.com"}, {"-timeout", "bad", "example.com"},
		{"-resolver", "a=udp://hostname", "example.com"},
		{"-resolver", "a=udp://1.1.1.1", "-resolver", "a=tcp://8.8.8.8", "example.com"},
	}
	tooMany := []string{}
	for i := 0; i < 9; i++ {
		tooMany = append(tooMany, "-resolver", "a=udp://1.1.1.1")
	}
	tests = append(tests, append(tooMany, "example.com"))
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, stderr bytes.Buffer
			if code := run(context.Background(), args, &out, &stderr); code != 2 || stderr.Len() == 0 {
				t.Fatalf("code %d, stderr %q", code, stderr.String())
			}
		})
	}
}

func TestCLIExitCodesAndJSON(t *testing.T) {
	tests := []struct {
		name       string
		secondCode dnsmessage.RCode
		secondIP   byte
		exit       int
		agreement  string
	}{
		{"match", dnsmessage.RCodeSuccess, 1, 0, "match"},
		{"different", dnsmessage.RCodeSuccess, 2, 1, "different"},
		{"NXDOMAIN versus answer", dnsmessage.RCodeNameError, 0, 1, "different"},
		{"resolver failure", dnsmessage.RCodeServerFailure, 0, 2, "incomplete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := tcpServer(t, func(q query) []byte { return reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1)) })
			b := tcpServer(t, func(q query) []byte {
				if test.secondCode != dnsmessage.RCodeSuccess {
					return reply(q, test.secondCode)
				}
				return reply(q, test.secondCode, addressAnswer(q, 4, test.secondIP))
			})
			args := []string{"-resolver", "first=tcp://" + a.Addr().String(), "-resolver", "second=tcp://" + b.Addr().String(), "-json", "EXAMPLE.COM"}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), args, &stdout, &stderr)
			if code != test.exit || stderr.Len() != 0 {
				t.Fatalf("code %d, error %s", code, stderr.String())
			}
			var output report
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			if output.Agreement != test.agreement || output.Domain != "example.com." || len(output.Results) != 2 || output.Results[0].Resolver != "first" {
				t.Fatalf("%+v", output)
			}
		})
	}
}

func TestQueriesRunConcurrently(t *testing.T) {
	gate := make(chan struct{})
	var once sync.Once
	slow := tcpServer(t, func(q query) []byte { <-gate; return reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1)) })
	fast := tcpServer(t, func(q query) []byte {
		once.Do(func() { close(gate) })
		return reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 1, 1))
	})
	a, _ := parseResolver("slow=tcp://" + slow.Addr().String())
	b, _ := parseResolver("fast=tcp://" + fast.Addr().String())
	q := testQuery(t)
	output := check(context.Background(), q.question.Name, q.question.Type, []resolver{a, b}, 500*time.Millisecond)
	if output.Agreement != "match" || output.Results[0].Error != "" {
		t.Fatalf("queries serialized: %+v", output)
	}
}

func TestTextReportAndTerminalEscapes(t *testing.T) {
	var output bytes.Buffer
	r := report{Domain: "example.com.", Type: "TXT", Agreement: "different", Results: []result{
		{Resolver: "one", Transport: "https", RCode: "NOERROR", Group: 1, Answers: []answer{{Name: "example.com.", Type: "TXT", Value: "\x1b[31m\nmalicious", TTL: 50}}},
		{Resolver: "two", Transport: "tcp", Error: "bad\r\npacket"},
	}}
	if err := printReport(&output, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "bad\r\npacket") || !strings.Contains(output.String(), "\\x1b") || !strings.Contains(output.String(), "DIFFERENT") {
		t.Fatalf("unsafe output: %q", output.String())
	}
	for _, agreement := range []string{"match", "incomplete"} {
		r.Agreement = agreement
		output.Reset()
		if err := printReport(&output, r, false); err != nil || !strings.Contains(output.String(), strings.ToUpper(agreement)) {
			t.Fatalf("%s %v", output.String(), err)
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write(_ []byte) (int, error) { return 0, errors.New("broken pipe") }

func TestReportWriteErrors(t *testing.T) {
	for _, jsonOutput := range []bool{true, false} {
		if err := printReport(failedWriter{}, report{}, jsonOutput); err == nil {
			t.Fatal("write error lost")
		}
	}
}
