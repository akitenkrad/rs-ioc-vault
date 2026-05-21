# アーキテクチャ

`rs-ioc-vault` は Cargo workspace として複数クレートに分割され，利用者は必要なものだけ依存できます．依存方向は上位 → 下位の一方向で，下位の I/O はトレイトの裏に隠されます．

## クレート構成

| クレート | レイヤー | 役割 |
|----------|---------|------|
| `ioc-vault-core` | Domain | I/O を持たないドメインモデル (IoC 型・正規化・dedup ハッシュ・検索クエリ・減衰モデル) |
| `ioc-vault-store` | Infrastructure | SQLite (sqlx) 永続化・検索エンジン・確信度集約・時間減衰 |
| `ioc-vault-collect` | Domain | コレクタトレイトと収集コンテキスト (差分取得 / 304) |
| `ioc-vault-adapters` | Adapter | 個別フィードのアダプタ (URLhaus / ThreatFox / CISA KEV)。feature-gated |
| `ioc-vault-export` | Adapter | CSV / JSONL / STIX 2.1 / MISP へのエクスポート |
| `rs-ioc-vault` | Application | 上記を束ねる公開ファサード `IocVault` |
| `ioc-vault-cli` | UI | 単一バイナリ `ioc-vault` |

## データの流れ

```
OSINT feeds → Collector → 正規化 / dedup → SQLite (WAL + FTS5) → Query / Export → CLI · STIX · MISP
```

1. **収集**: `Collector` が ETag / Last-Modified を尊重してフィードを取得し，`RawIoc` のストリームを返します．
2. **正規化と重複排除**: IoC 種別ごとの規則で値を正規化し，`SHA-256(type || ":" || value)` を dedup キーとして 1 レコードに集約します．
3. **永続化**: 単一の SQLite ファイル (WAL モード，FTS5 全文検索) に格納します．
4. **集約**: 複数ソースの観測を独立証拠とみなして確信度を Bayes 風に集約し，IoC 種別ごとの半減期で時間減衰スコアを算出します．
5. **検索 / エクスポート**: 複合条件検索 (種別・期間・確信度・CIDR・正規表現・FTS5) と標準形式エクスポート (STIX 2.1 / MISP / CSV / JSONL) を提供します．

## 永続化の方針

- 単一 SQLite ファイルで完結し，外部 DB サーバを必要としません．
- WAL モード + バッチコミットでバルク取り込みを高速化します．
- 全文検索はトリガで本体テーブルと同期される FTS5 仮想テーブルを利用します．
- スキーマは `migrations/` のマイグレーションでバージョン管理されます．

## 設計上の選択

- ドメイン層 (`ioc-vault-core`) は I/O 依存を持たず，テスト容易性を保ちます．
- アダプタは feature flag で個別に有効化でき，未使用ソースのコンパイルコストを排除します．
- エラーはアプリ層で `anyhow`，ライブラリ層で `thiserror` の二層構成とします．
- IoC 型は STIX 2.1 Cyber-observable の命名に準拠し，エクスポート時の写像を単純化します．
