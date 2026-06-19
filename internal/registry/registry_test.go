package registry

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cognis-digital/toolgraph/internal/graph"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	g := graph.New()
	_ = g.AddTool(graph.Tool{Name: "nmap", Category: "scanning", Language: "C", URL: "https://nmap.org", Tags: []string{"recon", "network"}})
	_ = g.AddTool(graph.Tool{Name: "masscan", Category: "scanning", Language: "C", URL: "https://example.test/masscan"})
	if err := g.AddRelation("masscan", "nmap", graph.AlternativeTo); err != nil {
		t.Fatalf("AddRelation: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "reg.json")
	if err := Save(path, g); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("registry file missing: %v", err)
	}

	g2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g2.Len() != 2 {
		t.Fatalf("loaded tools: want 2, got %d", g2.Len())
	}
	if g2.EdgeCount() != 1 {
		t.Fatalf("loaded relations: want 1, got %d", g2.EdgeCount())
	}
	rel, err := g2.Related("nmap", graph.AlternativeTo)
	if err != nil || len(rel) != 1 || rel[0].Tool.Name != "masscan" {
		t.Fatalf("relation not preserved: %v %+v", err, rel)
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	g, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if g.Len() != 0 {
		t.Fatalf("want empty graph, got %d tools", g.Len())
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		code int
		want AuditStatus
	}{
		{200, StatusOK},
		{204, StatusOK},
		{301, StatusStale},
		{302, StatusStale},
		{401, StatusStale},
		{403, StatusStale},
		{405, StatusStale},
		{404, StatusDead},
		{410, StatusDead},
		{500, StatusDead},
		{503, StatusDead},
	}
	for _, c := range cases {
		if got := classify(c.code); got != c.want {
			t.Errorf("classify(%d) = %s, want %s", c.code, got, c.want)
		}
	}
}

func TestAuditWithHTTPTest(t *testing.T) {
	// A test server that returns different statuses by path. HEAD is used by
	// the auditor, so we respond accordingly.
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := graph.New()
	_ = g.AddTool(graph.Tool{Name: "alive", URL: srv.URL + "/ok"})
	_ = g.AddTool(graph.Tool{Name: "dead", URL: srv.URL + "/gone"})
	_ = g.AddTool(graph.Tool{Name: "guarded", URL: srv.URL + "/auth"})
	_ = g.AddTool(graph.Tool{Name: "nourl", URL: ""})

	results := Audit(g, srv.Client(), 5*time.Second, 4)
	if len(results) != 4 {
		t.Fatalf("want 4 results, got %d", len(results))
	}

	byName := map[string]AuditResult{}
	for _, r := range results {
		byName[r.Name] = r
	}
	if byName["alive"].Status != StatusOK {
		t.Errorf("alive: want OK, got %s", byName["alive"].Status)
	}
	if byName["dead"].Status != StatusDead {
		t.Errorf("dead: want DEAD, got %s", byName["dead"].Status)
	}
	if byName["guarded"].Status != StatusStale {
		t.Errorf("guarded: want STALE, got %s", byName["guarded"].Status)
	}
	if byName["nourl"].Status != StatusSkipped {
		t.Errorf("nourl: want SKIPPED, got %s", byName["nourl"].Status)
	}

	sum := Summarize(results)
	if sum.OK != 1 || sum.Dead != 1 || sum.Stale != 1 || sum.Skipped != 1 || sum.Total != 4 {
		t.Fatalf("summary wrong: %+v", sum)
	}
}

func TestAuditUnreachableHostIsDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the address refuses connections

	g := graph.New()
	_ = g.AddTool(graph.Tool{Name: "down", URL: url})

	results := Audit(g, &http.Client{}, 2*time.Second, 1)
	if len(results) != 1 || results[0].Status != StatusDead {
		t.Fatalf("unreachable host should be DEAD, got %+v", results)
	}
}
