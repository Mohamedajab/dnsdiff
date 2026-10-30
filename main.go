package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

var version = "dev"

type resolverFlags []string

func (r *resolverFlags) String() string         { return strings.Join(*r, ", ") }
func (r *resolverFlags) Set(value string) error { *r = append(*r, value); return nil }

func safeText(value string) string {
	if strings.ContainsFunc(value, unicode.IsControl) {
		return strconv.QuoteToASCII(value)
	}
	return value
}

func printReport(out io.Writer, r report, jsonOutput bool) error {
	if jsonOutput {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(r)
	}
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%s %s\n\n", r.Domain, r.Type)
	for _, result := range r.Results {
		fmt.Fprintf(&buffer, "%s  %s  %.2f ms", result.Resolver, result.Transport, result.DurationMS)
		if result.Error != "" {
			fmt.Fprintf(&buffer, "  ERROR: %s\n\n", safeText(result.Error))
			continue
		}
		fmt.Fprintf(&buffer, "  %s  group %d  AD=%t\n", result.RCode, result.Group, result.AuthenticatedData)
		if len(result.Answers) == 0 {
			fmt.Fprintln(&buffer, "  (no answer records)")
		}
		writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
		for _, a := range result.Answers {
			fmt.Fprintf(writer, "  %s\t%s\t%s\tTTL %d\n", safeText(a.Name), a.Type, safeText(a.Value), a.TTL)
		}
		writer.Flush()
		fmt.Fprintln(&buffer)
	}
	switch r.Agreement {
	case "match":
		fmt.Fprintln(&buffer, "MATCH: resolvers returned the same DNS status and answer set.")
	case "different":
		fmt.Fprintln(&buffer, "DIFFERENT: resolvers returned different DNS statuses or answer sets.")
	default:
		fmt.Fprintln(&buffer, "INCOMPLETE: at least one resolver failed; remaining groups are still shown.")
	}
	fmt.Fprintln(&buffer, "TTL and answer order are excluded from comparison. Different answers can be normal for CDNs.")
	_, err := io.Copy(out, &buffer)
	return err
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dnsdiff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var configured resolverFlags
	flags.Var(&configured, "resolver", "name=https://host/dns-query, name=udp://IP:port or name=tcp://IP:port (repeat up to 8 times)")
	kindFlag := flags.String("type", "A", "A, AAAA, CNAME, MX, TXT, NS or SOA")
	timeout := flags.Duration("timeout", 3*time.Second, "deadline per resolver, including TCP fallback (50ms–30s)")
	jsonOutput := flags.Bool("json", false, "write a JSON report")
	showVersion := flags.Bool("version", false, "print version")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: dnsdiff [flags] domain\n\nCompare DNS answers. Defaults: Cloudflare and Google over HTTPS.\nFlags must come before the domain.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "dnsdiff "+version)
		return 0
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	name, err := domainName(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	kind, ok := queryTypes[strings.ToUpper(*kindFlag)]
	if !ok {
		fmt.Fprintln(stderr, "unsupported record type")
		return 2
	}
	if *timeout < 50*time.Millisecond || *timeout > 30*time.Second {
		fmt.Fprintln(stderr, "timeout must be between 50ms and 30s")
		return 2
	}
	if len(configured) == 0 {
		configured = resolverFlags{"cloudflare=https://cloudflare-dns.com/dns-query", "google=https://dns.google/dns-query"}
	}
	if len(configured) > 8 {
		fmt.Fprintln(stderr, "at most 8 resolvers are supported")
		return 2
	}
	resolvers := make([]resolver, 0, len(configured))
	names := make(map[string]bool)
	for _, value := range configured {
		r, err := parseResolver(value)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if names[r.name] {
			fmt.Fprintln(stderr, "resolver names must be unique")
			return 2
		}
		names[r.name] = true
		resolvers = append(resolvers, r)
	}
	r := check(ctx, name, kind, resolvers, *timeout)
	if err := printReport(stdout, r, *jsonOutput); err != nil {
		fmt.Fprintln(stderr, "write report:", err)
		return 2
	}
	if r.Agreement == "incomplete" {
		return 2
	}
	if r.Agreement == "different" {
		return 1
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
