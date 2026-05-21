**English** | [日本語](cli.ja.md)

# CLI Reference (`ioc-vault`)

`ioc-vault` is a single-binary CLI. Specify the database with `--db <PATH>`; when omitted, it uses `~/.ioc-vault/vault.db`.

```
ioc-vault <COMMAND> [OPTIONS]
```

| Command | Description |
|----------|------|
| `init` | Create the database and apply migrations |
| `source` | List / add / enable / disable sources |
| `update` | Ingest IoCs from feeds |
| `lookup` | Instant single-value lookup |
| `search` | Compound-condition search |
| `export` | Export to CSV / JSONL / STIX 2.1 / MISP |
| `decay` | Recompute time-decay scores |
| `stats` | Show statistics |

## init

```bash
ioc-vault init                          # create at the default path
ioc-vault init --db ./vault.db          # specify a path
```

## source

```bash
ioc-vault source list
ioc-vault source add demo --url https://example/demo --feed-type csv --confidence 80
ioc-vault source enable urlhaus
ioc-vault source disable threatfox
```

By default, three sources are registered: `urlhaus` / `threatfox` / `cisa-kev`.

## update

```bash
ioc-vault update --all --since 7d                  # all sources, last 7 days
ioc-vault update --source threatfox --since 2026-04-01
```

`--since` accepts either a relative number of days like `7d` or a date in `YYYY-MM-DD` format. It supports incremental fetching (ETag / Last-Modified) and skips when nothing has changed.

## lookup

```bash
ioc-vault lookup 203.0.113.42
ioc-vault lookup evil.example.com --format json
```

## search

```bash
ioc-vault search \
    --type ipv4 \
    --source urlhaus,threatfox \
    --threat-type c2 \
    --since 30d \
    --min-confidence 70 \
    --cidr 203.0.113.0/24 \
    --format json

# full-text search (FTS5); quote terms that contain hyphens
ioc-vault search --fts "emotet OR qakbot" --limit 100
```

### Filter flags (shared by search / export)

| Flag | Meaning |
|--------|------|
| `--type <t>` | IoC type (comma-separated / repeatable) |
| `--source <s>` | Observation source name |
| `--threat-type <s>` | Threat type (e.g. `c2`, `phishing`) |
| `--malware-family <s>` | Malware family |
| `--tag <s>` | Tag |
| `--cve <id>` | Related CVE |
| `--since <Nd\|YYYY-MM-DD>` | Lower bound on `last_seen` |
| `--min-confidence <0-100>` | Lower bound on aggregated confidence |
| `--min-decay <0.0-1.0>` | Lower bound on the time-decay score |
| `--cidr <net>` | IPs contained in the CIDR range |
| `--regex <re>` | Regex match on the value |
| `--contains` / `--prefix` / `--exact <s>` | Substring / prefix / exact match on the value |
| `--fts <q>` | FTS5 full-text search query |
| `--limit <n>` | Maximum number of results |
| `--order <...>` | `last-seen-desc` / `last-seen-asc` / `first-seen-desc` / `confidence-desc` / `decay-desc` |

For `lookup` / `search`, `--format` is `table` (default) / `json` / `jsonl`.

## export

```bash
ioc-vault export --format stix --since 7d --out feed.json
ioc-vault export --format misp --threat-type phishing --out phishing.misp.json
ioc-vault export --format csv --type ipv4 --min-confidence 80 --out ipv4.csv
ioc-vault export --format jsonl --min-confidence 80          # writes to stdout when --out is omitted
```

`--format` is `csv` / `jsonl` / `stix` (`stix2`, `stix2.1` also accepted) / `misp`. The filter flags are the same as for `search`.

## decay / stats

```bash
ioc-vault decay     # recompute time-decay scores for all IoCs
ioc-vault stats     # total count, breakdown by type, etc.
```
