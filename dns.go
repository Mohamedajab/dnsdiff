package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

var queryTypes = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME,
	"MX": dnsmessage.TypeMX, "TXT": dnsmessage.TypeTXT, "NS": dnsmessage.TypeNS, "SOA": dnsmessage.TypeSOA,
}

type answer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

type query struct {
	question dnsmessage.Question
	wire     []byte
	id       uint16
}

func domainName(input string) (dnsmessage.Name, error) {
	if input == "." {
		return dnsmessage.NewName(input)
	}
	input = strings.ToLower(strings.TrimSuffix(input, "."))
	if len(input) == 0 || len(input) > 253 {
		return dnsmessage.Name{}, fmt.Errorf("domain must contain 1–253 ASCII characters")
	}
	for _, label := range strings.Split(input, ".") {
		if len(label) == 0 || len(label) > 63 {
			return dnsmessage.Name{}, fmt.Errorf("domain labels must contain 1–63 characters")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return dnsmessage.Name{}, fmt.Errorf("use an ASCII DNS name; convert international names to punycode first")
			}
		}
	}
	return dnsmessage.NewName(input + ".")
}

func makeQuery(name dnsmessage.Name, kind dnsmessage.Type, doh bool) (query, error) {
	var id uint16
	if !doh {
		var bytes [2]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return query{}, err
		}
		id = binary.BigEndian.Uint16(bytes[:])
	}
	question := dnsmessage.Question{Name: name, Type: kind, Class: dnsmessage.ClassINET}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	wire, err := message.Pack()
	return query{question: question, wire: wire, id: id}, err
}

func envelope(wire []byte, q query) (dnsmessage.Header, error) {
	var parser dnsmessage.Parser
	h, err := parser.Start(wire)
	if err != nil {
		return h, fmt.Errorf("invalid DNS header: %w", err)
	}
	if !h.Response || h.OpCode != 0 || h.ID != q.id {
		return h, fmt.Errorf("DNS response flag, opcode or transaction ID does not match")
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return h, fmt.Errorf("invalid DNS question: %w", err)
	}
	if len(questions) != 1 || !strings.EqualFold(questions[0].Name.String(), q.question.Name.String()) || questions[0].Type != q.question.Type || questions[0].Class != dnsmessage.ClassINET {
		return h, fmt.Errorf("DNS response question does not match")
	}
	return h, nil
}

func decode(wire []byte, q query) (dnsmessage.Header, []answer, error) {
	h, err := envelope(wire, q)
	if err != nil {
		return h, nil, err
	}
	if h.Truncated {
		return h, nil, fmt.Errorf("response is still truncated")
	}
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil {
		return h, nil, fmt.Errorf("invalid DNS message: %w", err)
	}
	answers := make([]answer, 0, len(message.Answers))
	for _, resource := range message.Answers {
		value := ""
		switch body := resource.Body.(type) {
		case *dnsmessage.AResource:
			value = netip.AddrFrom4(body.A).String()
		case *dnsmessage.AAAAResource:
			value = netip.AddrFrom16(body.AAAA).String()
		case *dnsmessage.CNAMEResource:
			value = strings.ToLower(body.CNAME.String())
		case *dnsmessage.NSResource:
			value = strings.ToLower(body.NS.String())
		case *dnsmessage.MXResource:
			value = fmt.Sprintf("%d %s", body.Pref, strings.ToLower(body.MX.String()))
		case *dnsmessage.TXTResource:
			parts := make([]string, len(body.TXT))
			for i, part := range body.TXT {
				parts[i] = strconv.Quote(part)
			}
			value = strings.Join(parts, " ")
		case *dnsmessage.SOAResource:
			value = fmt.Sprintf("%s %s %d %d %d %d %d", strings.ToLower(body.NS.String()), strings.ToLower(body.MBox.String()), body.Serial, body.Refresh, body.Retry, body.Expire, body.MinTTL)
		case *dnsmessage.UnknownResource:
			value = hex.EncodeToString(body.Data)
		default:
			return h, nil, fmt.Errorf("unsupported answer type %d", resource.Header.Type)
		}
		answers = append(answers, answer{Name: strings.ToLower(resource.Header.Name.String()), Type: typeName(resource.Header.Type), Value: value, TTL: resource.Header.TTL})
	}
	return h, answers, nil
}

func typeName(kind dnsmessage.Type) string {
	for name, value := range queryTypes {
		if value == kind {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", kind)
}

func rcodeName(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}
