[English](usecases.md) | **日本語**

# ユースケース

`rs-ioc-vault` は OSINT 由来の IoC を 1 つの SQLite ファイルに集約し，CLI とライブラリの両方から扱える IoC ストアです．以下に代表的な利用シナリオを示します．

## 1. SOC アナリストによるローカル即時照会

調査中の IP / ドメイン / ハッシュが既知の脅威かどうかを，外部 API に依存せずローカルで即座に確認します．

```bash
# 初期化と取り込み (初回のみ)
ioc-vault init
ioc-vault update --all --since 7d

# 単一値の照会
ioc-vault lookup 203.0.113.42
ioc-vault lookup evil.example.com --format json

# 標準入力からの一括照会
cat suspicious_hosts.txt | while read v; do ioc-vault lookup "$v"; done
```

照会結果には集約確信度・観測ソース・脅威種別・関連 CVE・時間減衰スコアが含まれます．

## 2. 検知パイプラインへのライブラリ組み込み

検知エンジンやバッチジョブに `rs-ioc-vault` をライブラリとして組み込み，高頻度の照会・検索を行います．ストアはステートレスに開閉でき，in-memory モードも利用できます．

```rust
use rs_ioc_vault::{IocVault, SearchQuery, IocType};

let vault = IocVault::builder().database("vault.db").build().await?;

let q = SearchQuery::builder()
    .ioc_type(IocType::Ipv4)
    .min_confidence(70)
    .last_seen_within(chrono::Duration::days(30))
    .build();
let hits = vault.search(&q).await?;
```

詳細は [library.ja.md](library.ja.md) を参照してください．

## 3. TIP / SIEM 連携用の定期エクスポート

蓄積した IoC を STIX 2.1 バンドルや MISP イベントとして定期的に書き出し，TIP・SIEM・SOAR に取り込みます．

```bash
# 直近 7 日分を STIX 2.1 バンドルで出力
ioc-vault export --format stix --since 7d --out feed.json

# フィッシング系のみ MISP イベントで出力
ioc-vault export --format misp --threat-type phishing --out phishing.misp.json

# 高確信度 IPv4 を CSV で出力
ioc-vault export --format csv --type ipv4 --min-confidence 80 --out ipv4.csv
```

`export` は `search` と同一のフィルタを受け付けるため，検索条件をそのまま配信内容に反映できます．

## 4. 差分更新と監査可能な収集ログ

フィードは ETag / Last-Modified を尊重した差分取得を行い，変更がなければスキップします．各収集ランは記録され，いつ・どのソースから・何件取り込んだかを後から追跡できます．

```bash
# 特定ソースを期間指定で差分更新
ioc-vault update --source threatfox --since 2026-04-01

# 取り込み状況・件数の確認
ioc-vault stats
ioc-vault source list
```

## 5. 確信度集約と時間減衰によるノイズ低減

同一 IoC が複数ソースから観測された場合，独立証拠とみなして確信度を集約します．また IoC 種別ごとの半減期に基づき時間減衰スコアを再計算し，古い指標の重みを下げられます．

```bash
# 時間減衰スコアの再計算
ioc-vault decay

# 減衰スコアの高い (=新しく信頼度の高い) 指標を抽出
ioc-vault search --type url --min-decay 0.5 --order decay-desc --limit 100
```

## 6. データレイクの最下層 (Bronze layer) として運用

正規化・重複排除済みの raw IoC ストアとして運用し，下流の分析パイプライン (エンリッチ・相関分析・スコアリング) に JSONL / CSV で供給します．

```bash
ioc-vault export --format jsonl --since 1d > bronze/iocs-$(date +%F).jsonl
```

---

関連ドキュメント: [CLI リファレンス](cli.ja.md) ・ [ライブラリ利用](library.ja.md) ・ [アーキテクチャ](architecture.ja.md)
