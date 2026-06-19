package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// runCmd executes the CLI with args and returns code, stdout, stderr.
func runCmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIAddQueryRelatedStats(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "tg.json")

	// Add two tools and a relation.
	if code, _, e := runCmd("add", "-file", reg, "-name", "nmap", "-category", "scanning", "-lang", "C", "-url", "https://nmap.org", "-tags", "network,recon"); code != 0 {
		t.Fatalf("add nmap failed: code=%d err=%s", code, e)
	}
	if code, _, e := runCmd("add", "-file", reg, "-name", "masscan", "-category", "scanning", "-lang", "C", "-url", "https://example.test/masscan", "-relation", "alternative-to", "-target", "nmap"); code != 0 {
		t.Fatalf("add masscan failed: code=%d err=%s", code, e)
	}

	// Query by category.
	code, out, _ := runCmd("query", "-file", reg, "-category", "scanning")
	if code != 0 {
		t.Fatalf("query failed: %d", code)
	}
	if !strings.Contains(out, "nmap") || !strings.Contains(out, "masscan") {
		t.Fatalf("query output missing tools: %s", out)
	}
	if !strings.Contains(out, "2 tool(s)") {
		t.Fatalf("query count wrong: %s", out)
	}

	// Query JSON by tag.
	code, out, _ = runCmd("query", "-file", reg, "-tag", "recon", "-json")
	if code != 0 || !strings.Contains(out, "\"name\": \"nmap\"") {
		t.Fatalf("json query failed: code=%d out=%s", code, out)
	}

	// Related traversal.
	code, out, _ = runCmd("related", "-file", reg, "nmap", "-relation", "alternative-to")
	if code != 0 {
		t.Fatalf("related failed: %d", code)
	}
	if !strings.Contains(out, "masscan") {
		t.Fatalf("related missing masscan: %s", out)
	}

	// Stats.
	code, out, _ = runCmd("stats", "-file", reg)
	if code != 0 {
		t.Fatalf("stats failed: %d", code)
	}
	if !strings.Contains(out, "tools:     2") || !strings.Contains(out, "relations: 1") {
		t.Fatalf("stats output wrong: %s", out)
	}
}

func TestCLIErrors(t *testing.T) {
	if code, _, _ := runCmd(); code != 2 {
		t.Fatalf("no args: want exit 2, got %d", code)
	}
	if code, _, _ := runCmd("bogus"); code != 2 {
		t.Fatalf("unknown command: want exit 2, got %d", code)
	}
	dir := t.TempDir()
	reg := filepath.Join(dir, "tg.json")
	if code, _, e := runCmd("add", "-file", reg); code != 2 || !strings.Contains(e, "-name is required") {
		t.Fatalf("add without name: code=%d err=%s", code, e)
	}
	// related on unknown tool from an empty (fresh) registry => not found.
	if code, _, e := runCmd("related", "-file", reg, "ghost"); code != 1 || !strings.Contains(e, "not found") {
		t.Fatalf("related ghost: code=%d err=%s", code, e)
	}
}
