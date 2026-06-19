// Package graph provides an in-memory directed graph of security/OSINT tools.
//
// Nodes are tools; edges are typed relations between tools (for example
// "alternative-to", "complements", "depends-on"). The graph is the analytical
// core of toolgraph: it supports filtered queries and relation traversal.
//
// This is original Cognis Digital IP and depends only on the Go standard
// library.
package graph

import (
	"errors"
	"sort"
	"strings"
)

// RelationType enumerates the supported edge kinds. Unknown values are rejected
// at insert time so the registry stays internally consistent.
type RelationType string

const (
	// AlternativeTo means the two tools solve a similar problem and one may be
	// used in place of the other.
	AlternativeTo RelationType = "alternative-to"
	// Complements means the tools are commonly used together.
	Complements RelationType = "complements"
	// DependsOn means the source tool requires the target tool to function.
	DependsOn RelationType = "depends-on"
)

// ValidRelation reports whether r is a recognized relation type.
func ValidRelation(r RelationType) bool {
	switch r {
	case AlternativeTo, Complements, DependsOn:
		return true
	default:
		return false
	}
}

// RelationTypes returns the supported relation types in stable order.
func RelationTypes() []RelationType {
	return []RelationType{AlternativeTo, Complements, DependsOn}
}

// Tool is a node in the graph: a single security or OSINT tool entry.
type Tool struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Language string   `json:"language"`
	URL      string   `json:"url"`
	Tags     []string `json:"tags,omitempty"`
}

// Edge is a typed, directed relation from one tool to another.
type Edge struct {
	From     string       `json:"from"`
	To       string       `json:"to"`
	Relation RelationType `json:"relation"`
}

// Graph is a directed multigraph of tools and relations. The zero value is not
// usable; construct with New.
type Graph struct {
	nodes map[string]Tool // keyed by normalized name
	edges []Edge
}

// New returns an empty graph ready for use.
func New() *Graph {
	return &Graph{nodes: map[string]Tool{}}
}

// Common errors returned by graph operations.
var (
	ErrEmptyName     = errors.New("tool name must not be empty")
	ErrToolExists    = errors.New("tool already exists")
	ErrToolNotFound  = errors.New("tool not found")
	ErrBadRelation   = errors.New("unknown relation type")
	ErrSelfRelation  = errors.New("a tool cannot relate to itself")
	ErrEdgeDuplicate = errors.New("identical relation already exists")
)

// normKey returns the lookup key for a tool name: trimmed and lower-cased so
// that "Nmap" and "nmap" resolve to the same node while the original casing is
// preserved on the stored Tool.
func normKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// AddTool inserts a new tool. It returns ErrToolExists if a tool with the same
// (normalized) name is already present.
func (g *Graph) AddTool(t Tool) error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return ErrEmptyName
	}
	key := normKey(t.Name)
	if _, ok := g.nodes[key]; ok {
		return ErrToolExists
	}
	t.Tags = normalizeTags(t.Tags)
	g.nodes[key] = t
	return nil
}

// UpsertTool inserts or replaces a tool, preserving the original name spelling
// of the incoming tool. Edges referencing it are left untouched.
func (g *Graph) UpsertTool(t Tool) {
	t.Name = strings.TrimSpace(t.Name)
	t.Tags = normalizeTags(t.Tags)
	g.nodes[normKey(t.Name)] = t
}

// GetTool returns the tool with the given name (case-insensitive).
func (g *Graph) GetTool(name string) (Tool, bool) {
	t, ok := g.nodes[normKey(name)]
	return t, ok
}

// AddRelation records a typed edge from one existing tool to another. Both
// endpoints must already exist, the relation type must be valid, and exact
// duplicates are rejected.
func (g *Graph) AddRelation(from, to string, rel RelationType) error {
	if !ValidRelation(rel) {
		return ErrBadRelation
	}
	fk, tk := normKey(from), normKey(to)
	if fk == tk {
		return ErrSelfRelation
	}
	if _, ok := g.nodes[fk]; !ok {
		return ErrToolNotFound
	}
	if _, ok := g.nodes[tk]; !ok {
		return ErrToolNotFound
	}
	for _, e := range g.edges {
		if normKey(e.From) == fk && normKey(e.To) == tk && e.Relation == rel {
			return ErrEdgeDuplicate
		}
	}
	// Store canonical names from the node table for tidy output.
	g.edges = append(g.edges, Edge{
		From:     g.nodes[fk].Name,
		To:       g.nodes[tk].Name,
		Relation: rel,
	})
	return nil
}

// Tools returns all tools sorted by name (case-insensitive).
func (g *Graph) Tools() []Tool {
	out := make([]Tool, 0, len(g.nodes))
	for _, t := range g.nodes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		return normKey(out[i].Name) < normKey(out[j].Name)
	})
	return out
}

// Edges returns all relations sorted by (from, relation, to).
func (g *Graph) Edges() []Edge {
	out := make([]Edge, len(g.edges))
	copy(out, g.edges)
	sort.Slice(out, func(i, j int) bool {
		if a, b := normKey(out[i].From), normKey(out[j].From); a != b {
			return a < b
		}
		if out[i].Relation != out[j].Relation {
			return out[i].Relation < out[j].Relation
		}
		return normKey(out[i].To) < normKey(out[j].To)
	})
	return out
}

// Len reports the number of tools in the graph.
func (g *Graph) Len() int { return len(g.nodes) }

// EdgeCount reports the number of relations in the graph.
func (g *Graph) EdgeCount() int { return len(g.edges) }

// Filter describes the optional constraints for a query. An empty field means
// "do not filter on this attribute". Matching is case-insensitive.
type Filter struct {
	Category string
	Tag      string
	Language string
}

// Query returns the tools matching all set fields of f, sorted by name.
func (g *Graph) Query(f Filter) []Tool {
	cat := normKey(f.Category)
	tag := normKey(f.Tag)
	lang := normKey(f.Language)

	var out []Tool
	for _, t := range g.Tools() {
		if cat != "" && normKey(t.Category) != cat {
			continue
		}
		if lang != "" && normKey(t.Language) != lang {
			continue
		}
		if tag != "" && !hasTag(t.Tags, tag) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// RelatedEntry pairs a neighboring tool with the relation connecting it.
type RelatedEntry struct {
	Tool     Tool
	Relation RelationType
	// Direction is "out" when name is the source of the edge and "in" when name
	// is the target. This lets callers distinguish "X depends-on Y" from
	// "Y is depended on by X".
	Direction string
}

// Related returns the immediate neighbors of name in both directions,
// optionally filtered to a single relation type when rel != "". Results are
// sorted by neighbor name then relation. It returns ErrToolNotFound if the
// named tool does not exist.
func (g *Graph) Related(name string, rel RelationType) ([]RelatedEntry, error) {
	key := normKey(name)
	if _, ok := g.nodes[key]; !ok {
		return nil, ErrToolNotFound
	}
	if rel != "" && !ValidRelation(rel) {
		return nil, ErrBadRelation
	}

	var out []RelatedEntry
	for _, e := range g.edges {
		if rel != "" && e.Relation != rel {
			continue
		}
		switch key {
		case normKey(e.From):
			if t, ok := g.nodes[normKey(e.To)]; ok {
				out = append(out, RelatedEntry{Tool: t, Relation: e.Relation, Direction: "out"})
			}
		case normKey(e.To):
			if t, ok := g.nodes[normKey(e.From)]; ok {
				out = append(out, RelatedEntry{Tool: t, Relation: e.Relation, Direction: "in"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := normKey(out[i].Tool.Name), normKey(out[j].Tool.Name); a != b {
			return a < b
		}
		return out[i].Relation < out[j].Relation
	})
	return out, nil
}

// Reachable performs a breadth-first traversal from name following edges in the
// given direction up to maxDepth hops. Direction "out" follows From->To,
// "in" follows To->From, and "both" follows either. A maxDepth <= 0 means
// unlimited. The starting tool is never included in the result. Results are
// sorted by name. It returns ErrToolNotFound if name is absent.
func (g *Graph) Reachable(name string, rel RelationType, direction string, maxDepth int) ([]Tool, error) {
	start := normKey(name)
	if _, ok := g.nodes[start]; !ok {
		return nil, ErrToolNotFound
	}
	if rel != "" && !ValidRelation(rel) {
		return nil, ErrBadRelation
	}
	if direction == "" {
		direction = "out"
	}

	type item struct {
		key   string
		depth int
	}
	seen := map[string]bool{start: true}
	queue := []item{{start, 0}}
	var out []Tool

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if maxDepth > 0 && cur.depth >= maxDepth {
			continue
		}
		for _, e := range g.edges {
			if rel != "" && e.Relation != rel {
				continue
			}
			var next string
			switch direction {
			case "out":
				if normKey(e.From) == cur.key {
					next = normKey(e.To)
				}
			case "in":
				if normKey(e.To) == cur.key {
					next = normKey(e.From)
				}
			case "both":
				if normKey(e.From) == cur.key {
					next = normKey(e.To)
				} else if normKey(e.To) == cur.key {
					next = normKey(e.From)
				}
			}
			if next == "" || seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, item{next, cur.depth + 1})
			out = append(out, g.nodes[next])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return normKey(out[i].Name) < normKey(out[j].Name)
	})
	return out, nil
}

// Categories returns the distinct categories with a count of tools in each.
func (g *Graph) Categories() map[string]int {
	m := map[string]int{}
	for _, t := range g.nodes {
		c := strings.TrimSpace(t.Category)
		if c == "" {
			c = "(uncategorized)"
		}
		m[c]++
	}
	return m
}

// Languages returns the distinct languages with a count of tools in each.
func (g *Graph) Languages() map[string]int {
	m := map[string]int{}
	for _, t := range g.nodes {
		l := strings.TrimSpace(t.Language)
		if l == "" {
			l = "(unknown)"
		}
		m[l]++
	}
	return m
}

// TagCounts returns the distinct tags with a count of tools carrying each.
func (g *Graph) TagCounts() map[string]int {
	m := map[string]int{}
	for _, t := range g.nodes {
		for _, tag := range t.Tags {
			m[tag]++
		}
	}
	return m
}

// normalizeTags trims, lower-cases, de-duplicates and sorts tags.
func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// hasTag reports whether tags contains the already-normalized tag want.
func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
