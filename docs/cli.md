# CLI リファレンス (`ioc-vault`)

`ioc-vault` は単一バイナリの CLI です．データベースは `--db <PATH>` で指定し，省略時は `~/.ioc-vault/vault.db` を使用します．

```
ioc-vault <COMMAND> [OPTIONS]
```

| コマンド | 説明 |
|----------|------|
| `init` | データベースを作成しマイグレーションを適用 |
| `source` | ソースの一覧・追加・有効/無効化 |
| `update` | フィードから IoC を取り込み |
| `lookup` | 単一値の即時照会 |
| `search` | 複合条件検索 |
| `export` | CSV / JSONL / STIX 2.1 / MISP へエクスポート |
| `decay` | 時間減衰スコアを再計算 |
| `stats` | 統計情報を表示 |

## init

```bash
ioc-vault init                          # 既定パスに作成
ioc-vault init --db ./vault.db          # パス指定
```

## source

```bash
ioc-vault source list
ioc-vault source add demo --url https://example/demo --feed-type csv --confidence 80
ioc-vault source enable urlhaus
ioc-vault source disable threatfox
```

既定で `urlhaus` / `threatfox` / `cisa-kev` の 3 ソースが登録されます．

## update

```bash
ioc-vault update --all --since 7d                  # 全ソース，直近 7 日分
ioc-vault update --source threatfox --since 2026-04-01
```

`--since` は `7d` のような相対日数か `YYYY-MM-DD` 形式の日付を受け付けます．差分取得 (ETag / Last-Modified) に対応し，変更がなければスキップします．

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

# 全文検索 (FTS5)。ハイフンを含む語はクォートする
ioc-vault search --fts "emotet OR qakbot" --limit 100
```

### フィルタフラグ (search / export 共通)

| フラグ | 意味 |
|--------|------|
| `--type <t>` | IoC 種別 (カンマ区切り / 繰り返し可) |
| `--source <s>` | 観測ソース名 |
| `--threat-type <s>` | 脅威種別 (例 `c2`, `phishing`) |
| `--malware-family <s>` | マルウェアファミリ |
| `--tag <s>` | タグ |
| `--cve <id>` | 関連 CVE |
| `--since <Nd\|YYYY-MM-DD>` | `last_seen` の下限 |
| `--min-confidence <0-100>` | 集約確信度の下限 |
| `--min-decay <0.0-1.0>` | 時間減衰スコアの下限 |
| `--cidr <net>` | CIDR レンジに含まれる IP |
| `--regex <re>` | 値の正規表現一致 |
| `--contains` / `--prefix` / `--exact <s>` | 値の部分/前方/完全一致 |
| `--fts <q>` | FTS5 全文検索クエリ |
| `--limit <n>` | 最大件数 |
| `--order <...>` | `last-seen-desc` / `last-seen-asc` / `first-seen-desc` / `confidence-desc` / `decay-desc` |

`lookup` / `search` の `--format` は `table` (既定) / `json` / `jsonl`．

## export

```bash
ioc-vault export --format stix --since 7d --out feed.json
ioc-vault export --format misp --threat-type phishing --out phishing.misp.json
ioc-vault export --format csv --type ipv4 --min-confidence 80 --out ipv4.csv
ioc-vault export --format jsonl --min-confidence 80          # --out 省略時は標準出力
```

`--format` は `csv` / `jsonl` / `stix` (`stix2`, `stix2.1` も可) / `misp`．フィルタフラグは `search` と共通です．

## decay / stats

```bash
ioc-vault decay     # 全 IoC の時間減衰スコアを再計算
ioc-vault stats     # 総件数・種別内訳など
```
