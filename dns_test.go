package main

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func testQuery(t testing.TB) query {
	t.Helper()
	name, err := domainName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	q, err := makeQuery(name, dnsmessage.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func reply(q query, code dnsmessage.RCode, resources ...dnsmessage.Resource) []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.id, Response: true, RecursionAvailable: true, RCode: code}, Questions: []dnsmessage.Question{q.question}, Answers: resources}
	wire, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return wire
}

func addressAnswer(q query, ttl uint32, last byte) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.question.Name, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, last}}}
}

func TestDomainName(t *testing.T) {
	for _, input := range []string{"Example.COM", "example.com.", "selector._domainkey.example.com", "."} {
		if _, err := domainName(input); err != nil {
			t.Errorf("%q: %v", input, err)
		}
	}
	for _, input := range []string{"", " example.com", "example.com\n", "https://example.com", "éxample.com", "a..com", strings.Repeat("a", 64) + ".com", strings.Repeat("x.", 128)} {
		if _, err := domainName(input); err == nil {
			t.Errorf("accepted invalid name %q", input)
		}
	}
	name, _ := domainName("EXAMPLE.COM.")
	if name.String() != "example.com." {
		t.Fatal(name.String())
	}
}

func TestQueryAndEnvelope(t *testing.T) {
	q := testQuery(t)
	if q.id != 0 {
		t.Fatal("DoH queries should use ID zero")
	}
	var packed dnsmessage.Message
	if err := packed.Unpack(q.wire); err != nil {
		t.Fatal(err)
	}
	if !packed.RecursionDesired || len(packed.Questions) != 1 {
		t.Fatal(packed)
	}
	valid := reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1))
	h, answers, err := decode(valid, q)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 || answers[0].Value != "192.0.2.1" {
		t.Fatalf("%+v, %+v, %v", h, answers, err)
	}
	tests := map[string]func(*dnsmessage.Message){
		"wrong ID":                  func(m *dnsmessage.Message) { m.ID++ },
		"query instead of response": func(m *dnsmessage.Message) { m.Response = false },
		"wrong opcode":              func(m *dnsmessage.Message) { m.OpCode = 1 },
		"no question":               func(m *dnsmessage.Message) { m.Questions = nil },
		"two questions":             func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) },
		"wrong name":                func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.") },
		"wrong type":                func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA },
		"wrong class":               func(m *dnsmessage.Message) { m.Questions[0].Class = 3 },
		"truncated":                 func(m *dnsmessage.Message) { m.Truncated = true },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var m dnsmessage.Message
			if err := m.Unpack(valid); err != nil {
				t.Fatal(err)
			}
			mutate(&m)
			wire, _ := m.Pack()
			if _, _, err := decode(wire, q); err == nil {
				t.Fatal("accepted mismatched response")
			}
		})
	}
	for _, wire := range [][]byte{nil, {0, 1}, valid[:len(valid)-1]} {
		if _, _, err := decode(wire, q); err == nil {
			t.Fatal("accepted malformed packet")
		}
	}
}

func TestRecordTypes(t *testing.T) {
	q := testQuery(t)
	name := dnsmessage.MustNewName("UPPER.Example.")
	tests := []struct {
		name  string
		body  dnsmessage.ResourceBody
		value string
	}{
		{"A", &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}, "192.0.2.1"},
		{"AAAA", &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}, "2001:db8::1"},
		{"CNAME", &dnsmessage.CNAMEResource{CNAME: name}, "upper.example."},
		{"NS", &dnsmessage.NSResource{NS: name}, "upper.example."},
		{"MX", &dnsmessage.MXResource{Pref: 10, MX: name}, "10 upper.example."},
		{"TXT", &dnsmessage.TXTResource{TXT: []string{"a\nb", "Case"}}, `"a\nb" "Case"`},
		{"SOA", &dnsmessage.SOAResource{NS: name, MBox: name, Serial: 1, Refresh: 2, Retry: 3, Expire: 4, MinTTL: 5}, "upper.example. upper.example. 1 2 3 4 5"},
		{"TYPE99", &dnsmessage.UnknownResource{Type: 99, Data: []byte{1, 2}}, "0102"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := reply(q, dnsmessage.RCodeSuccess, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 45}, Body: test.body})
			_, answers, err := decode(wire, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(answers) != 1 || answers[0].Value != test.value || answers[0].Type != test.name || answers[0].Name != "upper.example." || answers[0].TTL != 45 {
				t.Fatalf("%+v", answers)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	q := testQuery(f)
	f.Add(reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1)))
	f.Add([]byte{0, 0, 0xc0, 0x0c})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maxMessage {
			t.Skip()
		}
		_, _, _ = decode(wire, q)
	})
}

func BenchmarkDecode(b *testing.B) {
	q := testQuery(b)
	wire := reply(q, dnsmessage.RCodeSuccess, addressAnswer(q, 60, 1))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := decode(wire, q); err != nil {
			b.Fatal(err)
		}
	}
}
