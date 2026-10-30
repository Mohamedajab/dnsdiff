package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type report struct {
	Domain    string   `json:"domain"`
	Type      string   `json:"type"`
	Agreement string   `json:"agreement"`
	Results   []result `json:"results"`
}

func signature(r result) string {
	// TTLs count down in caches; answer order and duplicate records carry no new data.
	unique := make(map[string]bool)
	for _, a := range r.Answers {
		fields, _ := json.Marshal([]string{a.Name, a.Type, a.Value})
		unique[string(fields)] = true
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return r.RCode + "\n" + strings.Join(keys, "\n")
}

func compare(results []result) string {
	groups := make(map[string]int)
	incomplete := false
	for i := range results {
		if results[i].Error != "" {
			incomplete = true
			continue
		}
		key := signature(results[i])
		if groups[key] == 0 {
			groups[key] = len(groups) + 1
		}
		results[i].Group = groups[key]
	}
	if incomplete {
		return "incomplete"
	}
	if len(groups) > 1 {
		return "different"
	}
	return "match"
}

func check(ctx context.Context, name dnsmessage.Name, kind dnsmessage.Type, resolvers []resolver, timeout time.Duration) report {
	out := report{Domain: name.String(), Type: typeName(kind), Results: make([]result, len(resolvers))}
	client := httpClient()
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	for i, r := range resolvers {
		wg.Add(1)
		go func(i int, r resolver) {
			defer wg.Done()
			queryCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			out.Results[i] = lookup(queryCtx, name, kind, r, client)
		}(i, r)
	}
	wg.Wait()
	out.Agreement = compare(out.Results)
	return out
}
