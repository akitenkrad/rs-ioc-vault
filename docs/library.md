# ライブラリ利用 (`rs-ioc-vault`)

`rs-ioc-vault` は CLI と同一のコアロジックを公開ファサード `IocVault` として提供します．依存スタックが重いアダプタやエクスポータは feature flag で個別に有効化できます．

## 依存の追加

```toml
[dependencies]
rs-ioc-vault = { git = "https://github.com/akitenkrad/rs-ioc-vault" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

## クイックスタート

```rust
use rs_ioc_vault::{ExportFormat, IocVault, SearchQuery};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 既定アダプタ (URLhaus / ThreatFox / CISA KEV) を登録して構築
    let vault = IocVault::builder()
        .database("vault.db")
        .with_default_collectors()
        .build()
        .await?;

    // フィードを取り込み
    vault.update_all(rs_ioc_vault::UpdateOptions::since_days(7)).await?;

    // 単一値の照会
    if let Some(rec) = vault.lookup("203.0.113.42").await? {
        println!("{} (confidence {})", rec.value, rec.confidence);
    }

    // 複合検索とエクスポート
    let q = SearchQuery::builder().min_confidence(70).limit(100).build();
    let stdout = std::io::stdout();
    let n = vault.export(ExportFormat::Stix, &q, stdout.lock()).await?;
    eprintln!("exported {n} records");
    Ok(())
}
```

## 主な API

| 項目 | 説明 |
|------|------|
| `IocVault::builder()` | `.database(path)` / `.in_memory()` / `.with_collector(..)` / `.with_default_collectors()` / `.build().await` |
| `update_source(name, &opts)` / `update_all(opts)` | フィードからの取り込み |
| `lookup(value)` | 単一値の照会 (`Option<IocRecord>`) |
| `search(&SearchQuery)` | 複合条件検索 (`Vec<IocRecord>`) |
| `export(format, &SearchQuery, writer)` | 検索結果を指定形式で書き出し |
| `apply_decay(&DecayModel)` | 時間減衰スコアの再計算 |
| `store()` | 低レベル `IocStore` への参照 |

`SearchQuery::builder()` はフィルタ (種別・ソース・脅威種別・期間・確信度・CIDR・正規表現・FTS など) を流暢に組み立てられます．`DecayModel::default()` は IoC 種別ごとの既定半減期を持ちます．

## in-memory での利用

テストや一時処理には `.in_memory()` が便利です．

```rust
let vault = IocVault::builder().in_memory().build().await?;
vault.store().bulk_upsert(records, "manual").await?;
```

## feature flags

アダプタはそれぞれ feature で切り替えられます (既定で全て有効)．不要なソースを外すとビルド時間とバイナリサイズを削減できます．

```toml
rs-ioc-vault = { git = "https://github.com/akitenkrad/rs-ioc-vault", default-features = false, features = ["urlhaus"] }
```
