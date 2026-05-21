**English** | [日本語](cli.ja.md)

# CLI Reference (`ioc-vault`)

`ioc-vault` is a single-binary CLI. Three global options are available on every command: `--db <PATH>` selects the database (default `~/.ioc-vault/vault.db`), `--config <PATH>` selects the config file (default `~/.ioc-vault/config.toml`), and `--no-defang` disables the display safety described below.

## Display safety (defanging)

Threat indicators are hostile by nature, and many terminals, log viewers, and chat clients turn a URL, IP, domain, or email address into a clickable link. To prevent an accidental click or copy-paste from reaching live malware or a phishing page, **all output is defanged by default**: structural characters are rewritten into inert placeholders so the value can no longer be followed as a link.

| Original | Defanged |
|----------|----------|
| `http` / `https` | `hxxp` / `hxxps` |
| `://` | `[://]` |
| `.` | `[.]` |
| `@` | `[at]` |
| `:` (IPv6) | `[:]` |

```bash
ioc-vault lookup http://evil.example.com/login@phish
# value: hxxp[://]evil[.]example[.]com/login[at]phish
```

Defanging covers every format: in `table` output the indicator value is rewritten, and in `json` / `jsonl` output **every string is recursively defanged** — not only the top-level `value`, but also nested feed payloads (`raw_data`) and `metadata`, so no live link survives anywhere in the document. Numbers, booleans, object keys, and timestamps are left untouched.

Pass `--no-defang` to emit raw, clickable values — for example when copying a real indicator, or when piping `json` / `jsonl` into downstream tools such as `jq` that need the original strings:

```bash
ioc-vault --no-defang lookup http://evil.example.com               # value: http://evil.example.com
ioc-vault --no-defang search --type url --format json | jq '.[].value'
```

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

### Authentication (ThreatFox)

The ThreatFox API requires an abuse.ch Auth-Key. Get a free key at <https://auth.abuse.ch/>, then supply it in one of two ways (the environment variable takes precedence):

```bash
# 1. Environment variable
export THREATFOX_AUTH_KEY="your-auth-key"
ioc-vault update --all --since 7d
```

```toml
# 2. Config file at ~/.ioc-vault/config.toml
#    (copy the repo's config.toml.example as a starting point)
[threatfox]
auth_key = "your-auth-key"
```

The config file is read from `~/.ioc-vault/config.toml` by default. To use a config file elsewhere (for example the `config.toml` in a project directory), point to it with `--config`:

```bash
ioc-vault update --all --since 7d --config ./config.toml
```

Without a key, the `threatfox` source fails fast with a clear error (the other sources are unaffected).

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

---
*This file was generated by Claude Code.*
