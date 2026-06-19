// Command toolgraph is a queryable registry of security/OSINT tools modeled as
// a directed graph. It supports registering tools, querying them by
// category/tag/language, traversing typed relations, auditing tool URLs with
// HTTP HEAD requests, and printing registry statistics.
//
// Original Cognis Digital IP. Standard library only. Defensive/analytical use.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cognis-digital/toolgraph/internal/graph"
	"github.com/cognis-digital/toolgraph/internal/registry"
)

const defaultFile = "toolgraph.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point. It returns a process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "add":
		return cmdAdd(rest, stdout, stderr)
	case "query":
		return cmdQuery(rest, stdout, stderr)
	case "related":
		return cmdRelated(rest, stdout, stderr)
	case "audit":
		return cmdAudit(rest, stdout, stderr)
	case "stats":
		return cmdStats(rest, stdout, stderr)
	case "list":
		return cmdQuery(rest, stdout, stderr) // alias: list == unfiltered query
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "toolgraph: unknown command %q\n\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `toolgraph - a queryable graph registry of security/OSINT tools

Usage:
  toolgraph <command> [flags]

Commands:
  add       Register a tool (or add a relation to an existing one)
  query     List tools, optionally filtered by category/tag/language
  related   Show tools related to a given tool (traverses relations)
  audit     Check each tool URL via HTTP HEAD and flag OK/STALE/DEAD links
  stats     Print registry statistics
  help      Show this help

Global:
  Most commands accept -file <path> (default ./toolgraph.json) and -json.

Examples:
  toolgraph add -name nmap -category scanning -lang C -url https://nmap.org -tags network,recon
  toolgraph add -name masscan -relation alternative-to -target nmap
  toolgraph query -category scanning
  toolgraph related nmap -relation alternative-to
  toolgraph audit -timeout 5s
  toolgraph stats

License: COCL 1.0
`)
}

// cmdAdd registers a tool and/or a relation. It can do either or both in one
// invocation: provide tool fields to create a node, and/or -relation/-target to
// link an (existing or just-created) tool to another.
func cmdAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file     = fs.String("file", defaultFile, "registry file path")
		name     = fs.String("name", "", "tool name (required)")
		category = fs.String("category", "", "tool category (e.g. scanning, osint)")
		lang     = fs.String("lang", "", "implementation language")
		url      = fs.String("url", "", "homepage / source URL")
		tags     = fs.String("tags", "", "comma-separated tags")
		relation = fs.String("relation", "", "relation type: alternative-to|complements|depends-on")
		target   = fs.String("target", "", "target tool name for the relation")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(stderr, "add: -name is required")
		return 2
	}

	g, err := registry.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, "add:", err)
		return 1
	}

	t := graph.Tool{
		Name:     strings.TrimSpace(*name),
		Category: strings.TrimSpace(*category),
		Language: strings.TrimSpace(*lang),
		URL:      strings.TrimSpace(*url),
		Tags:     splitTags(*tags),
	}

	if _, exists := g.GetTool(t.Name); exists {
		// Update fields only when explicitly provided so a relation-only add
		// does not wipe existing metadata.
		cur, _ := g.GetTool(t.Name)
		if *category != "" {
			cur.Category = t.Category
		}
		if *lang != "" {
			cur.Language = t.Language
		}
		if *url != "" {
			cur.URL = t.URL
		}
		if *tags != "" {
			cur.Tags = t.Tags
		}
		g.UpsertTool(cur)
		fmt.Fprintf(stdout, "updated %q\n", cur.Name)
	} else {
		if err := g.AddTool(t); err != nil {
			fmt.Fprintln(stderr, "add:", err)
			return 1
		}
		fmt.Fprintf(stdout, "added %q\n", t.Name)
	}

	if *relation != "" || *target != "" {
		if *relation == "" || *target == "" {
			fmt.Fprintln(stderr, "add: -relation and -target must be used together")
			return 2
		}
		rel := graph.RelationType(*relation)
		if !graph.ValidRelation(rel) {
			fmt.Fprintf(stderr, "add: unknown relation %q (want one of %s)\n", *relation, relationList())
			return 2
		}
		if _, ok := g.GetTool(*target); !ok {
			fmt.Fprintf(stderr, "add: target tool %q not found; register it first\n", *target)
			return 1
		}
		if err := g.AddRelation(t.Name, *target, rel); err != nil {
			fmt.Fprintln(stderr, "add relation:", err)
			return 1
		}
		fmt.Fprintf(stdout, "linked %q --%s--> %q\n", t.Name, rel, *target)
	}

	if err := registry.Save(*file, g); err != nil {
		fmt.Fprintln(stderr, "add:", err)
		return 1
	}
	return 0
}

func cmdQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file     = fs.String("file", defaultFile, "registry file path")
		category = fs.String("category", "", "filter by category")
		tag      = fs.String("tag", "", "filter by tag")
		lang     = fs.String("lang", "", "filter by language")
		asJSON   = fs.Bool("json", false, "output JSON")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	g, err := registry.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, "query:", err)
		return 1
	}
	tools := g.Query(graph.Filter{Category: *category, Tag: *tag, Language: *lang})

	if *asJSON {
		return emitJSON(stdout, stderr, tools)
	}
	if len(tools) == 0 {
		fmt.Fprintln(stdout, "no tools match")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCATEGORY\tLANG\tTAGS\tURL")
	for _, t := range tools {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			t.Name, dash(t.Category), dash(t.Language), dash(strings.Join(t.Tags, ",")), dash(t.URL))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d tool(s)\n", len(tools))
	return 0
}

func cmdRelated(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("related", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file     = fs.String("file", defaultFile, "registry file path")
		relation = fs.String("relation", "", "limit to a relation type")
		depth    = fs.Int("depth", 1, "traversal depth (1 = direct neighbors)")
		dir      = fs.String("direction", "out", "edge direction: out|in|both")
		asJSON   = fs.Bool("json", false, "output JSON")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "related: a tool name is required")
		return 2
	}
	name := fs.Arg(0)
	rel := graph.RelationType(*relation)
	if *relation != "" && !graph.ValidRelation(rel) {
		fmt.Fprintf(stderr, "related: unknown relation %q (want one of %s)\n", *relation, relationList())
		return 2
	}

	g, err := registry.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, "related:", err)
		return 1
	}

	if *depth > 1 {
		tools, err := g.Reachable(name, rel, *dir, *depth)
		if err != nil {
			fmt.Fprintln(stderr, "related:", err)
			return 1
		}
		if *asJSON {
			return emitJSON(stdout, stderr, tools)
		}
		if len(tools) == 0 {
			fmt.Fprintf(stdout, "no tools reachable from %q\n", name)
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tCATEGORY\tLANG\tURL")
		for _, t := range tools {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, dash(t.Category), dash(t.Language), dash(t.URL))
		}
		tw.Flush()
		fmt.Fprintf(stdout, "\n%d tool(s) within depth %d of %q\n", len(tools), *depth, name)
		return 0
	}

	entries, err := g.Related(name, rel)
	if err != nil {
		fmt.Fprintln(stderr, "related:", err)
		return 1
	}
	if *asJSON {
		type out struct {
			Name      string             `json:"name"`
			Relation  graph.RelationType `json:"relation"`
			Direction string             `json:"direction"`
			Category  string             `json:"category"`
			URL       string             `json:"url"`
		}
		var os_ []out
		for _, e := range entries {
			os_ = append(os_, out{e.Tool.Name, e.Relation, e.Direction, e.Tool.Category, e.Tool.URL})
		}
		return emitJSON(stdout, stderr, os_)
	}
	if len(entries) == 0 {
		fmt.Fprintf(stdout, "no relations for %q\n", name)
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RELATION\tDIR\tTOOL\tCATEGORY\tURL")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			e.Relation, e.Direction, e.Tool.Name, dash(e.Tool.Category), dash(e.Tool.URL))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d relation(s) for %q\n", len(entries), name)
	return 0
}

func cmdAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file    = fs.String("file", defaultFile, "registry file path")
		timeout = fs.Duration("timeout", 8*time.Second, "per-request timeout")
		workers = fs.Int("workers", 6, "concurrent HEAD requests")
		asJSON  = fs.Bool("json", false, "output JSON")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	g, err := registry.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, "audit:", err)
		return 1
	}
	results := registry.Audit(g, nil, *timeout, *workers)
	sum := registry.Summarize(results)

	if *asJSON {
		payload := struct {
			Results []registry.AuditResult `json:"results"`
			Summary registry.Summary       `json:"summary"`
		}{results, sum}
		return emitJSON(stdout, stderr, payload)
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tHTTP\tLATENCY\tNAME\tURL")
	for _, r := range results {
		http := "-"
		if r.HTTPStatus != 0 {
			http = fmt.Sprintf("%d", r.HTTPStatus)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.Status, http, dash(r.Latency), r.Name, dash(r.URL))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\nsummary: %d OK, %d STALE, %d DEAD, %d SKIPPED (of %d)\n",
		sum.OK, sum.Stale, sum.Dead, sum.Skipped, sum.Total)
	if sum.Dead > 0 {
		return 1 // non-zero exit signals dead links (useful in CI/cron)
	}
	return 0
}

func cmdStats(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		file   = fs.String("file", defaultFile, "registry file path")
		asJSON = fs.Bool("json", false, "output JSON")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	g, err := registry.Load(*file)
	if err != nil {
		fmt.Fprintln(stderr, "stats:", err)
		return 1
	}

	cats := g.Categories()
	langs := g.Languages()
	tags := g.TagCounts()

	if *asJSON {
		payload := struct {
			Tools      int            `json:"tools"`
			Relations  int            `json:"relations"`
			Categories map[string]int `json:"categories"`
			Languages  map[string]int `json:"languages"`
			Tags       map[string]int `json:"tags"`
		}{g.Len(), g.EdgeCount(), cats, langs, tags}
		return emitJSON(stdout, stderr, payload)
	}

	fmt.Fprintf(stdout, "tools:     %d\n", g.Len())
	fmt.Fprintf(stdout, "relations: %d\n", g.EdgeCount())
	printCounts(stdout, "categories", cats)
	printCounts(stdout, "languages", langs)
	printCounts(stdout, "tags", tags)
	return 0
}

// --- helpers ---

func printCounts(w io.Writer, title string, m map[string]int) {
	fmt.Fprintf(w, "\n%s:\n", title)
	type kv struct {
		k string
		v int
	}
	var rows []kv
	for k, v := range m {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].v != rows[j].v {
			return rows[i].v > rows[j].v
		}
		return rows[i].k < rows[j].k
	})
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%d\n", r.k, r.v)
	}
	tw.Flush()
}

func emitJSON(stdout, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "encode json:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

func splitTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func relationList() string {
	var ss []string
	for _, r := range graph.RelationTypes() {
		ss = append(ss, string(r))
	}
	return strings.Join(ss, "|")
}
