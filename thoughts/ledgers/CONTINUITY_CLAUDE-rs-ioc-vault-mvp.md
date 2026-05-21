# 継続台帳: rs-ioc-vault MVP 実装

## Goal
設計書 `~/Documents/Obsidian/設計書/rs-ioc-vault_IoCストア設計書.md` に基づき，OSINT IoC ストア `rs-ioc-vault` の v0.1 MVP を実装する．
- 公開ライブラリ ( ファサード) クレート = `rs-ioc-vault`
- CLI バイナリ = `ioc-vault`
- 単一バイナリ + 単一 SQLite ファイル ( WAL + FTS5)
- "done" = `cargo build` / `cargo nextest run` がパスし，`ioc-vault init/update/lookup/search/export` が動作する

## Constraints
- edition 2024，license Apache-2.0 ( ハウススタイル準拠)
- workspace 継承 ( `edition.workspace = true` 等)
- Makefile.toml ( cargo-make): taplo fmt / cargo fmt / cargo nextest
- DB アクセスは sqlx ( sqlite, runtime-tokio)．マイグレーションは `migrations/` + `sqlx::migrate!`
- アプリ層 anyhow / ライブラリ層 thiserror
- リモート: git@github.com:akitenkrad/rs-ioc-vault.git ( push はユーザ承認後)

## Key Decisions
- 内部クレートは `ioc-vault-*` プレフィックス，公開ファサードのみ `rs-ioc-vault`
- MVP アダプタは urlhaus / threatfox / cisa-kev の 3 つに絞る
- 設計書の edition 2021/rust 1.75 ではなく，ハウススタイルの edition 2024 を採用

## State
- Done:
  - [x] Phase 1: Workspace 構造 + Core types + SQLite schema/migration
    - ioc-vault-core (types/normalize/query/error) + ioc-vault-store (open/migrate/upsert/bulk_upsert/lookup/link_cve)
    - migrations/0001_init.sql ( 設計 §5.2 の全テーブル + FTS5 + トリガ)
    - 14 tests green ( cargo test --workspace)
  - [x] Phase 2: Collector trait + URLhaus/ThreatFox/KEV アダプタ + facade + CLI
    - ioc-vault-collect (Collector trait/SourceMetadata/CollectionContext/CollectionResult/FeedType/HealthStatus)
    - ioc-vault-adapters (feature-gated: urlhaus/threatfox/cisa-kev; 各々 pure parse fn + 単体テスト)
    - rs-ioc-vault facade (IocVault/builder/UpdateOptions/update_source/update_all/lookup; KEV は cves テーブルへ特別処理)
    - ioc-vault-cli ( bin: ioc-vault) init/source/update/lookup/stats．CLI offline スモーク済み
    - 24 tests green ( core10/store8/adapters4/facade2)
  - [x] Phase 3: 検索エンジン + 確信度 Bayes 集約 + 減衰
    - core: decay.rs ( DecayModel，半減期 0.5^(age/τ) セマンティクス)
    - store: search(&SearchQuery) ( QueryBuilder; IN/時刻/conf/decay/allowlist/FTS/Exact/Prefix/Contains を SQL，Regex/Cidr は Rust 後段フィルタ)，recompute_confidence ( Bayes，weight=1.0)，apply_decay
    - facade: search / apply_decay．CLI: search ( 多数フラグ) / decay サブコマンド
    - 35 tests green，clippy clean．CLI search/decay スモーク済み
  - [x] Phase 4: エクスポート + examples + README
    - ioc-vault-export ( ExportFormat{Csv,Jsonl,Stix,Misp}，write_csv/jsonl/stix/misp + dispatcher write)
    - STIX 2.1 bundle ( indicator SDO，type別 pattern，id は value_hash 由来で uuid 依存なし)
    - MISP single event ( Attribute 配列，type/category マッピング)
    - facade: export<W: Write>(format, &SearchQuery, w)．CLI: export ( search と同じ FilterArgs を flatten + --format/--out)
    - crates/rs-ioc-vault/examples/quickstart.rs，README.md ( 日本語，フッタ付き)
    - 40 tests green，clippy clean，examples build，CLI export 4形式スモーク済み，quickstart 実行確認

## ✅ v0.1 MVP 完了 ( 2026-05-21)
- 全 4 フェーズ完了．40 tests green / clippy clean / examples build
- バイナリ ioc-vault: init/source/update/lookup/search/export/decay/stats 動作
- 未コミット ( ユーザの /commit 運用に従い承認待ち)
- 次の候補 ( v0.2+): enrich クレート ( CVE/EPSS/KEV/PassiveDNS)，scheduler，TUI，REST API，
  per-source 確信度重み，search_stream，実ネットワーク統合テスト ( wiremock)

## Phase 3 で確定した実装事実
- 確信度は Bayes 集約 ( round(100*(1-Π(1-conf_i/100))))．max ではない
- decay は 0.5^(age_days/half_life)．DecayModel::default() は §11.2 準拠
- store.search は候補 id 収集 → hydrate．Regex/Cidr 指定時は limit/offset を Rust 側で適用
- FTS のハイフン語は呼び出し側で要クォート ( 例 "botnet-c2")
- IocRecord は Serialize 可 ( search --format json/jsonl が依存)

## Phase 2 で確定した実装事実 ( 後続が依存)
- ioc-vault-store に追加されたメソッド: list_sources/register_source/set_source_enabled/
  get_source_cache/update_source_cache/record_run/upsert_cve/count_iocs/counts_by_type，struct SourceInfo
- facade: IocVault::builder().database(path)/.in_memory()/.with_collector(Box<dyn Collector>)/
  .with_default_collectors()/.build()．UpdateOptions::since_days(n)
- CLI の DB 既定パスは $HOME/.ioc-vault/vault.db．--db で上書き
- adapters は default-features=false で workspace 参照．デフォルト feature で 3 つ有効
- KEV collector は IoC を 0 件返す設計．facade が parse_kev で cves に upsert
- Phase 3 でやること: store.search(&SearchQuery) 本実装 ( FTS5/CIDR/regex/ファセット)，
  確信度 Bayes 集約 ( 現状 max)，apply_decay ( 種別別半減期)，CLI search サブコマンド

## Phase 1 で確定した実装事実 ( 後続が依存)
- IocType: kebab-case 文字列 ( as_str / FromStr)．email は "email-address" 等
- normalize(ioc_type, &str) -> Result<String>; value_hash(ioc_type, &str)=SHA256(type||":"||value) hex
- IPv4 は手動で octet 毎 decimal parse ( 先頭ゼロ除去)
- RawIoc::new(value, ioc_type) で生成．first/last_seen None は upsert 時に now 補完
- timestamps は TEXT( RFC3339, UTC) 格納．min()/max() で集約
- 確信度は暫定 max 集約 ( Phase 3 で Bayes に置換)
- IocStore は Clone 可．pool() で SqlitePool 借用可
- DB 内 source 未登録なら upsert 時に feed_type='unknown', confidence_default=50 で自動作成

## Open Questions
- UNCONFIRMED: push のタイミング ( ユーザ承認待ち)

## Working Set
- ルート: ~/Documents/workspace/rust/rs-ioc-vault
- branch: main
- test: `cargo nextest run --workspace` / `cargo build`
- 設計書: ~/Documents/Obsidian/設計書/rs-ioc-vault_IoCストア設計書.md
