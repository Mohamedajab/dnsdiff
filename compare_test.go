package main

import "testing"

func TestComparison(t *testing.T) {
	a := answer{Name: "example.com.", Type: "A", Value: "192.0.2.1", TTL: 60}
	b := answer{Name: "example.com.", Type: "A", Value: "192.0.2.2", TTL: 60}
	old := a
	old.TTL = 4
	tests := []struct {
		name      string
		results   []result
		agreement string
	}{
		{"TTL order duplicates", []result{{RCode: "NOERROR", Answers: []answer{a, b}}, {RCode: "NOERROR", Answers: []answer{b, old, a}}}, "match"},
		{"different IP", []result{{RCode: "NOERROR", Answers: []answer{a}}, {RCode: "NOERROR", Answers: []answer{b}}}, "different"},
		{"negative versus empty", []result{{RCode: "NXDOMAIN"}, {RCode: "NOERROR"}}, "different"},
		{"negative agreement", []result{{RCode: "NXDOMAIN"}, {RCode: "NXDOMAIN"}}, "match"},
		{"one resolver failed", []result{{RCode: "NOERROR", Answers: []answer{a}}, {Error: "timeout"}}, "incomplete"},
		{"all resolvers failed", []result{{Error: "timeout"}, {Error: "bad packet"}}, "incomplete"},
		{"owner matters", []result{{RCode: "NOERROR", Answers: []answer{a}}, {RCode: "NOERROR", Answers: []answer{{Name: "other.example.", Type: "A", Value: a.Value}}}}, "different"},
		{"TXT case matters", []result{{RCode: "NOERROR", Answers: []answer{{Name: a.Name, Type: "TXT", Value: `"Case"`}}}, {RCode: "NOERROR", Answers: []answer{{Name: a.Name, Type: "TXT", Value: `"case"`}}}}, "different"},
		{"TXT chunk boundaries matter", []result{{RCode: "NOERROR", Answers: []answer{{Name: a.Name, Type: "TXT", Value: `"ab" "c"`}}}, {RCode: "NOERROR", Answers: []answer{{Name: a.Name, Type: "TXT", Value: `"a" "bc"`}}}}, "different"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := compare(test.results); got != test.agreement {
				t.Fatalf("got %s, want %s", got, test.agreement)
			}
			if test.results[0].Error == "" && test.results[0].Group != 1 {
				t.Fatal("group order is not stable")
			}
		})
	}
}
