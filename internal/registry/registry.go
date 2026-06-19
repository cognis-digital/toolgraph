// Package registry handles persistence of the tool graph to a JSON file and the
// link-audit logic that checks each tool URL with an HTTP HEAD request.
//
// Original Cognis Digital IP. Standard library only.
package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/cognis-digital/toolgraph/internal/graph"
)

// fileFormat is the on-disk JSON shape. It is intentionally simple and
// pretty-printable: a list of tools and a list of relations.
type fileFormat struct {
	Version   int          `json:"version"`
	Tools     []graph.Tool `json:"tools"`
	Relations []graph.Edge `json:"relations"`
}

const formatVersion = 1

// Load reads a registry from path and returns the reconstructed graph. A
// missing file yields an empty graph and no error, so the first `add` works on
// a fresh machine.
func Load(path string) (*graph.Graph, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return graph.New(), nil
		}
		return nil, fmt.Errorf("read registry %q: %w", path, err)
	}
	var ff fileFormat
	if err := json.Unmarshal(b, &ff); err != nil {
		return nil, fmt.Errorf("parse registry %q: %w", path, err)
	}
	g := graph.New()
	for _, t := range ff.Tools {
		// UpsertTool tolerates duplicates so a hand-edited file never blocks load.
		g.UpsertTool(t)
	}
	for _, e := range ff.Relations {
		// Ignore individual bad edges (e.g. dangling endpoints) rather than
		// failing the whole load; AddRelation validates endpoints and type.
		_ = g.AddRelation(e.From, e.To, e.Relation)
	}
	return g, nil
}

// Save writes g to path as pretty-printed JSON. It writes to a temporary file
// in the same directory and renames it into place for atomicity.
func Save(path string, g *graph.Graph) error {
	ff := fileFormat{
		Version:   formatVersion,
		Tools:     g.Tools(),
		Relations: g.Edges(),
	}
	b, err := json.MarshalIndent(ff, "", "  ")
	if err != nil {
		return fmt.Errorf("encode registry: %w", err)
	}
	b = append(b, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write temp registry: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace registry: %w", err)
	}
	return nil
}

// AuditStatus is the outcome of checking a single tool's URL.
type AuditStatus string

const (
	// StatusOK means the URL responded with a 2xx status.
	StatusOK AuditStatus = "OK"
	// StatusStale means the URL resolved but returned a redirect (3xx) or a
	// client/server status that still indicates the resource exists in some
	// form (for example 401/403/405) — reachable but worth a look.
	StatusStale AuditStatus = "STALE"
	// StatusDead means the URL could not be reached or returned 404/410 or a
	// hard server failure.
	StatusDead AuditStatus = "DEAD"
	// StatusSkipped means the tool has no URL to check.
	StatusSkipped AuditStatus = "SKIPPED"
)

// AuditResult records the audit outcome for one tool.
type AuditResult struct {
	Name       string      `json:"name"`
	URL        string      `json:"url"`
	Status     AuditStatus `json:"status"`
	HTTPStatus int         `json:"http_status,omitempty"`
	Detail     string      `json:"detail,omitempty"`
	Latency    string      `json:"latency,omitempty"`
}

// classify maps an HTTP status code to an AuditStatus.
func classify(code int) AuditStatus {
	switch {
	case code >= 200 && code < 300:
		return StatusOK
	case code == http.StatusNotFound || code == http.StatusGone:
		return StatusDead
	case code >= 300 && code < 400:
		return StatusStale
	case code == http.StatusUnauthorized,
		code == http.StatusForbidden,
		code == http.StatusMethodNotAllowed,
		code == http.StatusTooManyRequests:
		// Reachable but not a clean 2xx; flag for review rather than declaring dead.
		return StatusStale
	case code >= 500:
		return StatusDead
	default:
		return StatusStale
	}
}

// checkOne performs a single HEAD request against url using client and returns
// the audit result for the given tool name.
func checkOne(client *http.Client, name, url string) AuditResult {
	res := AuditResult{Name: name, URL: url}
	if url == "" {
		res.Status = StatusSkipped
		res.Detail = "no url"
		return res
	}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		res.Status = StatusDead
		res.Detail = "invalid url: " + err.Error()
		return res
	}
	req.Header.Set("User-Agent", "toolgraph-audit/1.0 (+defensive link checker)")

	start := time.Now()
	resp, err := client.Do(req)
	res.Latency = time.Since(start).Round(time.Millisecond).String()
	if err != nil {
		res.Status = StatusDead
		res.Detail = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.HTTPStatus = resp.StatusCode
	res.Status = classify(resp.StatusCode)
	res.Detail = resp.Status
	return res
}

// Audit checks every tool URL in g using HTTP HEAD requests, bounded by the
// per-request timeout. The supplied client is used as-is (after its Timeout is
// set) so callers — including tests with httptest — can inject behavior. If
// client is nil a default client is constructed.
//
// Concurrency is bounded by workers (minimum 1). Results are returned sorted by
// tool name.
func Audit(g *graph.Graph, client *http.Client, timeout time.Duration, workers int) []AuditResult {
	if client == nil {
		client = &http.Client{}
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	if workers < 1 {
		workers = 1
	}

	tools := g.Tools()
	results := make([]AuditResult, len(tools))

	type job struct {
		idx  int
		tool graph.Tool
	}
	jobs := make(chan job)
	done := make(chan struct{})

	for w := 0; w < workers; w++ {
		go func() {
			for j := range jobs {
				results[j.idx] = checkOne(client, j.tool.Name, j.tool.URL)
			}
			done <- struct{}{}
		}()
	}
	for i, t := range tools {
		jobs <- job{idx: i, tool: t}
	}
	close(jobs)
	for w := 0; w < workers; w++ {
		<-done
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

// Summary tallies audit results by status.
type Summary struct {
	OK      int `json:"ok"`
	Stale   int `json:"stale"`
	Dead    int `json:"dead"`
	Skipped int `json:"skipped"`
	Total   int `json:"total"`
}

// Summarize counts results by status.
func Summarize(results []AuditResult) Summary {
	var s Summary
	for _, r := range results {
		s.Total++
		switch r.Status {
		case StatusOK:
			s.OK++
		case StatusStale:
			s.Stale++
		case StatusDead:
			s.Dead++
		case StatusSkipped:
			s.Skipped++
		}
	}
	return s
}
