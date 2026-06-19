package graph

import (
	"testing"
)

// buildSample constructs a small graph used across tests.
func buildSample(t *testing.T) *Graph {
	t.Helper()
	g := New()
	tools := []Tool{
		{Name: "nmap", Category: "scanning", Language: "C", URL: "https://nmap.org", Tags: []string{"network", "recon"}},
		{Name: "masscan", Category: "scanning", Language: "C", URL: "https://example.test/masscan", Tags: []string{"network", "fast"}},
		{Name: "rustscan", Category: "scanning", Language: "Rust", URL: "https://example.test/rustscan", Tags: []string{"network"}},
		{Name: "wireshark", Category: "analysis", Language: "C", URL: "https://www.wireshark.org", Tags: []string{"network", "pcap"}},
		{Name: "tshark", Category: "analysis", Language: "C", URL: "https://www.wireshark.org/docs/man-pages/tshark.html", Tags: []string{"pcap"}},
	}
	for _, tool := range tools {
		if err := g.AddTool(tool); err != nil {
			t.Fatalf("AddTool(%s): %v", tool.Name, err)
		}
	}
	rels := []struct {
		from, to string
		rel      RelationType
	}{
		{"masscan", "nmap", AlternativeTo},
		{"rustscan", "nmap", AlternativeTo},
		{"tshark", "wireshark", AlternativeTo},
		{"wireshark", "nmap", Complements},
		{"tshark", "wireshark", DependsOn},
	}
	for _, r := range rels {
		if err := g.AddRelation(r.from, r.to, r.rel); err != nil {
			t.Fatalf("AddRelation(%s->%s): %v", r.from, r.to, err)
		}
	}
	return g
}

func TestAddToolDuplicateAndCaseInsensitive(t *testing.T) {
	g := New()
	if err := g.AddTool(Tool{Name: "Nmap"}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := g.AddTool(Tool{Name: "nmap"}); err != ErrToolExists {
		t.Fatalf("want ErrToolExists, got %v", err)
	}
	if _, ok := g.GetTool("NMAP"); !ok {
		t.Fatalf("case-insensitive lookup failed")
	}
	if err := g.AddTool(Tool{Name: "  "}); err != ErrEmptyName {
		t.Fatalf("want ErrEmptyName, got %v", err)
	}
}

func TestAddRelationValidation(t *testing.T) {
	g := New()
	_ = g.AddTool(Tool{Name: "a"})
	_ = g.AddTool(Tool{Name: "b"})

	if err := g.AddRelation("a", "b", "bogus"); err != ErrBadRelation {
		t.Fatalf("want ErrBadRelation, got %v", err)
	}
	if err := g.AddRelation("a", "a", Complements); err != ErrSelfRelation {
		t.Fatalf("want ErrSelfRelation, got %v", err)
	}
	if err := g.AddRelation("a", "missing", Complements); err != ErrToolNotFound {
		t.Fatalf("want ErrToolNotFound, got %v", err)
	}
	if err := g.AddRelation("a", "b", Complements); err != nil {
		t.Fatalf("valid relation: %v", err)
	}
	if err := g.AddRelation("a", "b", Complements); err != ErrEdgeDuplicate {
		t.Fatalf("want ErrEdgeDuplicate, got %v", err)
	}
}

func TestQueryFilters(t *testing.T) {
	g := buildSample(t)

	if got := g.Query(Filter{Category: "scanning"}); len(got) != 3 {
		t.Fatalf("category scanning: want 3, got %d", len(got))
	}
	if got := g.Query(Filter{Language: "rust"}); len(got) != 1 || got[0].Name != "rustscan" {
		t.Fatalf("lang rust filter wrong: %+v", got)
	}
	if got := g.Query(Filter{Tag: "pcap"}); len(got) != 2 {
		t.Fatalf("tag pcap: want 2, got %d", len(got))
	}
	// Combined filter: scanning + tag network + lang C => nmap, masscan.
	got := g.Query(Filter{Category: "scanning", Tag: "network", Language: "c"})
	if len(got) != 2 {
		t.Fatalf("combined filter: want 2, got %d (%+v)", len(got), got)
	}
	// No match.
	if got := g.Query(Filter{Category: "nope"}); len(got) != 0 {
		t.Fatalf("expected empty result, got %d", len(got))
	}
}

func TestRelatedDirectAndFiltered(t *testing.T) {
	g := buildSample(t)

	// nmap has incoming alternative-to from masscan and rustscan, plus an
	// incoming complements from wireshark.
	all, err := g.Related("nmap", "")
	if err != nil {
		t.Fatalf("Related: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("nmap neighbors: want 3, got %d (%+v)", len(all), all)
	}

	alts, err := g.Related("nmap", AlternativeTo)
	if err != nil {
		t.Fatalf("Related filtered: %v", err)
	}
	if len(alts) != 2 {
		t.Fatalf("nmap alternatives: want 2, got %d", len(alts))
	}
	names := map[string]bool{}
	for _, e := range alts {
		names[e.Tool.Name] = true
		if e.Direction != "in" {
			t.Fatalf("expected incoming direction for %s, got %s", e.Tool.Name, e.Direction)
		}
	}
	if !names["masscan"] || !names["rustscan"] {
		t.Fatalf("missing expected alternatives: %+v", names)
	}

	if _, err := g.Related("ghost", ""); err != ErrToolNotFound {
		t.Fatalf("want ErrToolNotFound, got %v", err)
	}
}

func TestReachableTraversal(t *testing.T) {
	g := buildSample(t)

	// From tshark, following outgoing edges of any type:
	// tshark -> wireshark (alternative-to, depends-on); wireshark -> nmap (complements).
	// Depth 1: wireshark only. Depth 2: wireshark + nmap.
	d1, err := g.Reachable("tshark", "", "out", 1)
	if err != nil {
		t.Fatalf("Reachable d1: %v", err)
	}
	if len(d1) != 1 || d1[0].Name != "wireshark" {
		t.Fatalf("depth 1 from tshark: want [wireshark], got %+v", d1)
	}

	d2, err := g.Reachable("tshark", "", "out", 2)
	if err != nil {
		t.Fatalf("Reachable d2: %v", err)
	}
	if len(d2) != 2 {
		t.Fatalf("depth 2 from tshark: want 2, got %d (%+v)", len(d2), d2)
	}

	// Incoming alternatives to nmap reachable via "in" direction at depth 1.
	in1, err := g.Reachable("nmap", AlternativeTo, "in", 1)
	if err != nil {
		t.Fatalf("Reachable in: %v", err)
	}
	if len(in1) != 2 {
		t.Fatalf("incoming alternatives to nmap: want 2, got %d", len(in1))
	}

	if _, err := g.Reachable("ghost", "", "out", 1); err != ErrToolNotFound {
		t.Fatalf("want ErrToolNotFound, got %v", err)
	}
}

func TestStatsCounts(t *testing.T) {
	g := buildSample(t)
	if g.Len() != 5 {
		t.Fatalf("Len: want 5, got %d", g.Len())
	}
	if g.EdgeCount() != 5 {
		t.Fatalf("EdgeCount: want 5, got %d", g.EdgeCount())
	}
	if c := g.Categories(); c["scanning"] != 3 || c["analysis"] != 2 {
		t.Fatalf("Categories wrong: %+v", c)
	}
	if l := g.Languages(); l["C"] != 4 || l["Rust"] != 1 {
		t.Fatalf("Languages wrong: %+v", l)
	}
	if tc := g.TagCounts(); tc["network"] != 4 || tc["pcap"] != 2 {
		t.Fatalf("TagCounts wrong: %+v", tc)
	}
}

func TestNormalizeTags(t *testing.T) {
	g := New()
	_ = g.AddTool(Tool{Name: "x", Tags: []string{"  Recon ", "recon", "NET", ""}})
	tool, _ := g.GetTool("x")
	if len(tool.Tags) != 2 {
		t.Fatalf("want 2 normalized tags, got %+v", tool.Tags)
	}
	if tool.Tags[0] != "net" || tool.Tags[1] != "recon" {
		t.Fatalf("tags not normalized/sorted: %+v", tool.Tags)
	}
}
