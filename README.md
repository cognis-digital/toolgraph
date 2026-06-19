# toolgraph

A queryable registry of security/OSINT tools modeled as a directed graph — register tools, filter them, traverse typed relations, and audit their links.

`toolgraph` keeps a catalog of security and OSINT tools as a graph: each tool is
a **node** (name, category, language, URL, tags) and each **relation** is a typed
**edge** between tools — `alternative-to`, `complements`, or `depends-on`. You can
query the catalog by category/tag/language, ask "what are the alternatives to
nmap?", and audit every URL with HTTP HEAD requests to flag dead or stale links.
The registry is a single pretty-printed JSON file you can commit, diff, and edit
by hand.

Built by Cognis Digital. Standard library only, no external dependencies.
Defensive and analytical use only.

## Install

```sh
# install the CLI (Go 1.22+)
go install github.com/cognis-digital/toolgraph/cmd/toolgraph@latest
```

Or build from a clone:

```sh
git clone https://github.com/cognis-digital/toolgraph
cd toolgraph
go build ./...
go build -o toolgraph ./cmd/toolgraph
```

Get started against the bundled seed catalog:

```sh
cp examples/seed.json toolgraph.json
toolgraph stats
```

## Features

- **Graph data model** — tools as nodes, typed relations as directed edges, with
  breadth-first traversal.
- **`add`** — register a tool (`-name -category -lang -url -tags`) and/or link one
  to another (`-relation -target`). Re-adding an existing tool updates only the
  fields you pass.
- **`query`** — list tools, filtered by `--category`, `--tag`, and/or `--lang`;
  `--json` for machine output.
- **`related`** — show a tool's neighbors (direct or to a `--depth`), optionally
  limited to one `--relation` and a `--direction` (`out`/`in`/`both`).
- **`audit`** — check each tool's URL with a HEAD request (bounded `--timeout`,
  concurrent `--workers`) and classify it `OK` / `STALE` / `DEAD` / `SKIPPED`.
  Exits non-zero when any link is dead (handy in CI/cron).
- **`stats`** — counts of tools, relations, categories, languages, and tags.
- **JSON or table output** on every read command (`--json`).
- **Atomic, pretty-printed JSON** persistence (default `./toolgraph.json`).
- **Seed catalog** of 14 well-known tools in `examples/seed.json`.

## Usage

```text
toolgraph <command> [flags]

Commands:
  add       Register a tool (or add a relation to an existing one)
  query     List tools, optionally filtered by category/tag/language
  related   Show tools related to a given tool (traverses relations)
  audit     Check each tool URL via HTTP HEAD and flag OK/STALE/DEAD links
  stats     Print registry statistics
  help      Show this help
```

Most commands accept `-file <path>` (default `./toolgraph.json`) and `-json`.

### Register tools and relations

```sh
toolgraph add -name nmap -category network-scanning -lang C -url https://nmap.org -tags network,recon
toolgraph add -name masscan -category network-scanning -lang C \
  -url https://github.com/robertdavidgraham/masscan \
  -relation alternative-to -target nmap
```

### Query by category

```text
$ toolgraph query -category osint
NAME          CATEGORY  LANG    TAGS                        URL
amass         osint     Go      dns,footprint,subdomains    https://github.com/owasp-amass/amass
spiderfoot    osint     Python  automation,footprint,recon  https://www.spiderfoot.net
subfinder     osint     Go      dns,passive,subdomains      https://github.com/projectdiscovery/subfinder
theharvester  osint     Python  email,footprint,recon       https://github.com/laramies/theHarvester

4 tool(s)
```

### Traverse relations

```text
$ toolgraph related nmap
RELATION        DIR  TOOL      CATEGORY          URL
alternative-to  in   masscan   network-scanning  https://github.com/robertdavidgraham/masscan
alternative-to  in   rustscan  network-scanning  https://github.com/RustScan/RustScan

2 relation(s) for "nmap"
```

`DIR` is `in` when another tool points at this one (here, masscan and rustscan are
registered as alternatives *to* nmap). Use `-depth 2 -direction both` to walk
further across the graph.

### Audit links

```sh
toolgraph audit -timeout 5s -workers 8
```

```text
STATUS  HTTP  LATENCY  NAME       URL
OK      200   142ms    nmap       https://nmap.org
DEAD    -     2.0s     oldtool    https://example.invalid/gone
STALE   403   88ms     guarded    https://example.com/protected

summary: 1 OK, 1 STALE, 1 DEAD, 1 SKIPPED (of 4)
```

`STALE` covers redirects and reachable-but-guarded responses (401/403/405/429);
`DEAD` covers 404/410, 5xx, and unreachable hosts; `SKIPPED` is an entry with no
URL.

### Statistics

```text
$ toolgraph stats
tools:     14
relations: 11

categories:
  osint                4
  network-scanning     3
  traffic-analysis     3
  intrusion-detection  2
  web-testing          2

languages:
  C       6
  Python  3
  Go      2
  C++     1
  Java    1
  Rust    1
```

## Registry format

`toolgraph.json` is plain, pretty-printed JSON — safe to commit and edit by hand:

```json
{
  "version": 1,
  "tools": [
    { "name": "nmap", "category": "network-scanning", "language": "C",
      "url": "https://nmap.org", "tags": ["discovery", "network", "ports", "recon"] }
  ],
  "relations": [
    { "from": "masscan", "to": "nmap", "relation": "alternative-to" }
  ]
}
```

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

Tests are network-free: the audit path is exercised with `net/http/httptest`.

## License

License: COCL 1.0
