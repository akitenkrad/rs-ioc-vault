<p align="center">
  <img src="docs/assets/hero.svg" alt="rs-ioc-vault — OSINT Indicator-of-Compromise store in Rust" width="100%">
</p>

**English** | [日本語](README.ja.md)

# rs-ioc-vault

A lightweight IoC store that normalizes and deduplicates OSINT-derived threat indicators (IoCs) and consolidates them into a single SQLite file. It ships a single binary `ioc-vault` (CLI) and a public library `rs-ioc-vault`, ingests feeds such as URLhaus / ThreatFox / CISA KEV, and supports compound-condition search, time-decay scoring, and export to STIX 2.1 / MISP / CSV / JSONL.

## Installation

A Rust toolchain (with edition 2024 support) is required.

```bash
# Install the CLI binary ioc-vault
cargo install --git https://github.com/akitenkrad/rs-ioc-vault ioc-vault-cli
```

To build from source:

```bash
git clone https://github.com/akitenkrad/rs-ioc-vault
cd rs-ioc-vault
cargo build --release          # binary at target/release/ioc-vault
cargo test --workspace         # tests
```

Verify the installation:

```bash
ioc-vault init
ioc-vault source list
```

## Documentation

- [Use Cases](docs/usecases.md) — representative usage scenarios
- [CLI Reference](docs/cli.md) — all `ioc-vault` commands
- [Library Usage](docs/library.md) — add `rs-ioc-vault` as a dependency and use it
- [Architecture](docs/architecture.md) — crate layout and data flow

## License

Apache-2.0
