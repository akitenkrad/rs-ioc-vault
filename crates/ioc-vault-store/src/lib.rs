//! SQLite-backed persistence for `rs-ioc-vault`.
//!
//! [`IocStore`] owns a `sqlx` SQLite pool with WAL + foreign keys enabled and
//! exposes write (upsert, link) and read (lookup) operations over the schema
//! defined in `migrations/`. Confidence aggregation and the full search engine
//! are layered on in later phases.

mod error;

use std::path::Path;
use std::str::FromStr;

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ioc_vault_core::{
    DecayModel, IocRecord, IocType, OrderBy, RawIoc, Relationship, SearchQuery, SourceSighting,
    Tlp, UpsertStats, ValueMatcher, normalize, value_hash,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};

pub use error::{Result, StoreError};

/// Summary of a configured source row (design §5.2).
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub name: String,
    pub url: String,
    pub feed_type: String,
    pub enabled: bool,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub confidence_default: u8,
}

/// Embedded migrations from the workspace `migrations/` directory.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Handle to the IoC store backed by a single SQLite database.
#[derive(Clone)]
pub struct IocStore {
    pool: SqlitePool,
}

impl IocStore {
    /// Open (creating if missing) a file-backed store with WAL + foreign keys.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    /// Open an ephemeral in-memory store (single connection).
    pub async fn open_in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    /// Apply all pending migrations.
    pub async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Borrow the underlying pool (for higher layers needing custom queries).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Resolve a source id by name, auto-creating a minimal row if absent.
    async fn resolve_source(&self, name: &str) -> Result<(i64, u8)> {
        if let Some(row) = sqlx::query("SELECT id, confidence_default FROM sources WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
        {
            let id: i64 = row.try_get("id")?;
            let conf: i64 = row.try_get("confidence_default")?;
            return Ok((id, conf.clamp(0, 100) as u8));
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO sources (name, url, feed_type, confidence_default) \
             VALUES (?, '', 'unknown', 50) RETURNING id",
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await?;
        Ok((id, 50))
    }

    /// Insert or merge a single indicator observed from `source`.
    ///
    /// Returns the IoC row id.
    pub async fn upsert(&self, raw: RawIoc, source: &str) -> Result<i64> {
        let (source_id, default_conf) = self.resolve_source(source).await?;
        let mut tx = self.pool.begin().await?;
        let (id, _added) = upsert_in_tx(&mut tx, &raw, source_id, default_conf).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Insert or merge many indicators from `source` in a single transaction.
    pub async fn bulk_upsert(
        &self,
        raws: impl IntoIterator<Item = RawIoc>,
        source: &str,
    ) -> Result<UpsertStats> {
        let (source_id, default_conf) = self.resolve_source(source).await?;
        let mut stats = UpsertStats::default();
        let mut tx = self.pool.begin().await?;
        for raw in raws {
            let (_id, added) = upsert_in_tx(&mut tx, &raw, source_id, default_conf).await?;
            if added {
                stats.added += 1;
            } else {
                stats.updated += 1;
            }
        }
        tx.commit().await?;
        Ok(stats)
    }

    /// Link an IoC to a CVE, creating a stub CVE row if needed.
    pub async fn link_cve(&self, ioc_id: i64, cve: &str, rel: Relationship) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT OR IGNORE INTO cves (id) VALUES (?)")
            .bind(cve)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO ioc_cves (ioc_id, cve_id, relationship) VALUES (?, ?, ?) \
             ON CONFLICT(ioc_id, cve_id) DO UPDATE SET relationship = excluded.relationship",
        )
        .bind(ioc_id)
        .bind(cve)
        .bind(rel.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Look up a single indicator by its (raw) value across all types.
    ///
    /// The value is matched against the normalized `value` column directly.
    pub async fn lookup(&self, value: &str) -> Result<Option<IocRecord>> {
        let row = sqlx::query("SELECT id FROM iocs WHERE value = ? LIMIT 1")
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => {
                let id: i64 = r.try_get("id")?;
                Ok(Some(self.hydrate(id).await?))
            }
            None => Ok(None),
        }
    }

    /// Fetch a fully-hydrated record by row id.
    pub async fn get(&self, id: i64) -> Result<Option<IocRecord>> {
        let exists = sqlx::query("SELECT 1 FROM iocs WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        if exists.is_none() {
            return Ok(None);
        }
        Ok(Some(self.hydrate(id).await?))
    }

    /// Build a full [`IocRecord`] including sources, tags and CVE refs.
    async fn hydrate(&self, id: i64) -> Result<IocRecord> {
        let row = sqlx::query(
            "SELECT id, value, ioc_type, first_seen, last_seen, confidence, tlp, \
                    threat_type, malware_family, decay_score, is_allowlisted, metadata \
             FROM iocs WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        let ioc_type_s: String = row.try_get("ioc_type")?;
        let ioc_type = IocType::from_str(&ioc_type_s)?;
        let tlp_s: Option<String> = row.try_get("tlp")?;
        let tlp = tlp_s
            .as_deref()
            .map(Tlp::from_str)
            .transpose()?
            .unwrap_or_default();
        let metadata_s: Option<String> = row.try_get("metadata")?;
        let metadata = match metadata_s {
            Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
        let confidence: i64 = row.try_get("confidence")?;
        let decay: f64 = row.try_get("decay_score")?;
        let allow: i64 = row.try_get("is_allowlisted")?;

        let sources = self.sources_for(id).await?;
        let tags = self.tags_for(id).await?;
        let cve_refs = self.cves_for(id).await?;

        Ok(IocRecord {
            id: Some(row.try_get("id")?),
            value: row.try_get("value")?,
            ioc_type,
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
            confidence: confidence.clamp(0, 100) as u8,
            tlp,
            threat_type: row.try_get("threat_type")?,
            malware_family: row.try_get("malware_family")?,
            tags,
            sources,
            cve_refs,
            decay_score: decay as f32,
            is_allowlisted: allow != 0,
            metadata,
        })
    }

    async fn sources_for(&self, id: i64) -> Result<Vec<SourceSighting>> {
        let rows = sqlx::query(
            "SELECT s.name AS name, x.first_seen AS first_seen, x.last_seen AS last_seen, \
                    x.confidence AS confidence, x.raw_data AS raw_data \
             FROM ioc_sources x JOIN sources s ON s.id = x.source_id \
             WHERE x.ioc_id = ? ORDER BY s.name",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let conf: i64 = r.try_get("confidence")?;
            let raw_s: Option<String> = r.try_get("raw_data")?;
            let raw_data = raw_s.and_then(|s| serde_json::from_str(&s).ok());
            out.push(SourceSighting {
                source_name: r.try_get("name")?,
                first_seen: r.try_get("first_seen")?,
                last_seen: r.try_get("last_seen")?,
                confidence: conf.clamp(0, 100) as u8,
                raw_data,
            });
        }
        Ok(out)
    }

    async fn tags_for(&self, id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT t.name AS name FROM ioc_tags it JOIN tags t ON t.id = it.tag_id \
             WHERE it.ioc_id = ? ORDER BY t.name",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| r.try_get::<String, _>("name").map_err(Into::into))
            .collect()
    }

    async fn cves_for(&self, id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT cve_id FROM ioc_cves WHERE ioc_id = ? ORDER BY cve_id")
            .bind(id)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|r| r.try_get::<String, _>("cve_id").map_err(Into::into))
            .collect()
    }

    /// List all configured sources.
    pub async fn list_sources(&self) -> Result<Vec<SourceInfo>> {
        let rows = sqlx::query(
            "SELECT name, url, feed_type, enabled, last_fetched_at, etag, last_modified, \
                    confidence_default FROM sources ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let enabled: i64 = r.try_get("enabled")?;
            let conf: i64 = r.try_get("confidence_default")?;
            out.push(SourceInfo {
                name: r.try_get("name")?,
                url: r.try_get("url")?,
                feed_type: r.try_get("feed_type")?,
                enabled: enabled != 0,
                last_fetched_at: r.try_get("last_fetched_at")?,
                etag: r.try_get("etag")?,
                last_modified: r.try_get("last_modified")?,
                confidence_default: conf.clamp(0, 100) as u8,
            });
        }
        Ok(out)
    }

    /// Register (or update) a source by name.
    ///
    /// Returns the source row id.
    pub async fn register_source(
        &self,
        name: &str,
        url: &str,
        feed_type: &str,
        default_confidence: u8,
        tlp: Tlp,
    ) -> Result<i64> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO sources (name, url, feed_type, confidence_default, tlp) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(name) DO UPDATE SET \
                 url = excluded.url, \
                 feed_type = excluded.feed_type, \
                 confidence_default = excluded.confidence_default, \
                 tlp = excluded.tlp \
             RETURNING id",
        )
        .bind(name)
        .bind(url)
        .bind(feed_type)
        .bind(default_confidence as i64)
        .bind(tlp.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Enable or disable a source by name.
    pub async fn set_source_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE sources SET enabled = ? WHERE name = ?")
            .bind(if enabled { 1_i64 } else { 0 })
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Read the cached `(etag, last_modified)` validators for a source.
    pub async fn get_source_cache(
        &self,
        name: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>> {
        let row = sqlx::query("SELECT etag, last_modified FROM sources WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some((r.try_get("etag")?, r.try_get("last_modified")?))),
            None => Ok(None),
        }
    }

    /// Update a source's cache validators and stamp `last_fetched_at = now`.
    pub async fn update_source_cache(
        &self,
        name: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sources SET etag = ?, last_modified = ?, last_fetched_at = ? WHERE name = ?",
        )
        .bind(etag)
        .bind(last_modified)
        .bind(Utc::now())
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a collection run for `source`.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_run(
        &self,
        source: &str,
        started_at: DateTime<Utc>,
        finished_at: DateTime<Utc>,
        status: &str,
        added: u64,
        updated: u64,
        error: Option<&str>,
    ) -> Result<()> {
        let (source_id, _) = self.resolve_source(source).await?;
        sqlx::query(
            "INSERT INTO collection_runs \
                (source_id, started_at, finished_at, status, iocs_added, iocs_updated, error_message) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(source_id)
        .bind(started_at)
        .bind(finished_at)
        .bind(status)
        .bind(added as i64)
        .bind(updated as i64)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Insert or update a CVE row, optionally setting KEV membership/date.
    pub async fn upsert_cve(
        &self,
        cve_id: &str,
        date_added: Option<&str>,
        in_kev: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT OR IGNORE INTO cves (id) VALUES (?)")
            .bind(cve_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE cves SET in_kev = ?, kev_date_added = COALESCE(?, kev_date_added) WHERE id = ?",
        )
        .bind(if in_kev { 1_i64 } else { 0 })
        .bind(date_added)
        .bind(cve_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Total number of stored IoCs.
    pub async fn count_iocs(&self) -> Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM iocs")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    /// IoC counts grouped by `ioc_type`, descending by count.
    pub async fn counts_by_type(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT ioc_type, COUNT(*) AS n FROM iocs GROUP BY ioc_type ORDER BY n DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let t: String = r.try_get("ioc_type")?;
            let n: i64 = r.try_get("n")?;
            out.push((t, n));
        }
        Ok(out)
    }

    /// Execute a composable [`SearchQuery`], returning hydrated records.
    ///
    /// Most filters are pushed into SQL via [`QueryBuilder`]. `Regex` and
    /// `Cidr` value matchers cannot be expressed in SQLite, so candidates are
    /// fetched (without SQL `LIMIT`/`OFFSET`) and post-filtered in Rust, with
    /// `limit`/`offset` applied afterwards.
    pub async fn search(&self, q: &SearchQuery) -> Result<Vec<IocRecord>> {
        let post_filter = matches!(q.value_match, ValueMatcher::Regex(_) | ValueMatcher::Cidr(_));

        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT iocs.id FROM iocs WHERE 1=1");

        if !q.ioc_types.is_empty() {
            qb.push(" AND iocs.ioc_type IN (");
            let mut sep = qb.separated(", ");
            for t in &q.ioc_types {
                sep.push_bind(t.as_str());
            }
            qb.push(")");
        }

        if !q.threat_types.is_empty() {
            qb.push(" AND iocs.threat_type IN (");
            let mut sep = qb.separated(", ");
            for v in &q.threat_types {
                sep.push_bind(v.clone());
            }
            qb.push(")");
        }

        if !q.malware_families.is_empty() {
            qb.push(" AND iocs.malware_family IN (");
            let mut sep = qb.separated(", ");
            for v in &q.malware_families {
                sep.push_bind(v.clone());
            }
            qb.push(")");
        }

        if let Some(t) = q.first_seen_after {
            qb.push(" AND iocs.first_seen >= ").push_bind(t);
        }
        if let Some(t) = q.first_seen_before {
            qb.push(" AND iocs.first_seen <= ").push_bind(t);
        }
        if let Some(t) = q.last_seen_after {
            qb.push(" AND iocs.last_seen >= ").push_bind(t);
        }
        if let Some(t) = q.last_seen_before {
            qb.push(" AND iocs.last_seen <= ").push_bind(t);
        }

        if let Some(c) = q.min_confidence {
            qb.push(" AND iocs.confidence >= ").push_bind(c as i64);
        }
        if let Some(d) = q.min_decay_score {
            qb.push(" AND iocs.decay_score >= ").push_bind(d as f64);
        }

        if !q.include_allowlisted {
            qb.push(" AND iocs.is_allowlisted = 0");
        }

        if !q.sources.is_empty() {
            qb.push(
                " AND EXISTS (SELECT 1 FROM ioc_sources x JOIN sources s ON s.id = x.source_id \
                 WHERE x.ioc_id = iocs.id AND s.name IN (",
            );
            let mut sep = qb.separated(", ");
            for s in &q.sources {
                sep.push_bind(s.clone());
            }
            qb.push("))");
        }

        if !q.tags.is_empty() {
            qb.push(
                " AND EXISTS (SELECT 1 FROM ioc_tags it JOIN tags t ON t.id = it.tag_id \
                 WHERE it.ioc_id = iocs.id AND t.name IN (",
            );
            let mut sep = qb.separated(", ");
            for t in &q.tags {
                sep.push_bind(t.clone());
            }
            qb.push("))");
        }

        if !q.cve_ids.is_empty() {
            qb.push(" AND EXISTS (SELECT 1 FROM ioc_cves WHERE ioc_id = iocs.id AND cve_id IN (");
            let mut sep = qb.separated(", ");
            for c in &q.cve_ids {
                sep.push_bind(c.clone());
            }
            qb.push("))");
        }

        if let Some(fts) = &q.fts_query {
            qb.push(" AND iocs.id IN (SELECT rowid FROM iocs_fts WHERE iocs_fts MATCH ")
                .push_bind(fts.clone())
                .push(")");
        }

        // Value matchers that map cleanly to SQL.
        match &q.value_match {
            ValueMatcher::Any | ValueMatcher::Regex(_) | ValueMatcher::Cidr(_) => {}
            ValueMatcher::Exact(v) => {
                // Normalize only when a single ioc_type is specified; otherwise
                // match the raw value as given.
                let needle = if q.ioc_types.len() == 1 {
                    normalize(q.ioc_types[0], v).unwrap_or_else(|_| v.clone())
                } else {
                    v.clone()
                };
                qb.push(" AND iocs.value = ").push_bind(needle);
            }
            ValueMatcher::Prefix(v) => {
                let pat = format!("{}%", escape_like(v));
                qb.push(" AND iocs.value LIKE ")
                    .push_bind(pat)
                    .push(" ESCAPE '\\'");
            }
            ValueMatcher::Contains(v) => {
                let pat = format!("%{}%", escape_like(v));
                qb.push(" AND iocs.value LIKE ")
                    .push_bind(pat)
                    .push(" ESCAPE '\\'");
            }
        }

        qb.push(order_by_clause(q.order_by));

        // Only apply SQL paging when there is no Rust post-filter.
        if !post_filter && let Some(limit) = q.limit {
            qb.push(" LIMIT ").push_bind(limit as i64);
            if let Some(offset) = q.offset {
                qb.push(" OFFSET ").push_bind(offset as i64);
            }
        }

        let rows = qb.build().fetch_all(&self.pool).await?;
        let ids: Vec<i64> = rows
            .into_iter()
            .map(|r| r.try_get::<i64, _>("id"))
            .collect::<std::result::Result<_, _>>()?;

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.hydrate(id).await?);
        }

        if post_filter {
            out = post_filter_records(out, &q.value_match)?;
            let offset = q.offset.unwrap_or(0);
            if offset > 0 {
                out = out.into_iter().skip(offset).collect();
            }
            if let Some(limit) = q.limit {
                out.truncate(limit);
            }
        }

        Ok(out)
    }

    /// Recompute and persist `decay_score` for every stored IoC.
    ///
    /// Returns the number of rows updated.
    pub async fn apply_decay(&self, model: &DecayModel) -> Result<usize> {
        let rows =
            sqlx::query("SELECT id, ioc_type, last_seen FROM iocs").fetch_all(&self.pool).await?;
        let now = Utc::now();
        let mut tx = self.pool.begin().await?;
        let mut updated = 0usize;
        for r in rows {
            let id: i64 = r.try_get("id")?;
            let ioc_type_s: String = r.try_get("ioc_type")?;
            let ioc_type = IocType::from_str(&ioc_type_s)?;
            let last_seen: DateTime<Utc> = r.try_get("last_seen")?;
            let age_days = (now - last_seen).num_seconds() as f64 / 86_400.0;
            let score = model.score(ioc_type, age_days);
            sqlx::query("UPDATE iocs SET decay_score = ? WHERE id = ?")
                .bind(score as f64)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            updated += 1;
        }
        tx.commit().await?;
        Ok(updated)
    }
}

/// SQL `ORDER BY` clause for an [`OrderBy`].
fn order_by_clause(order: OrderBy) -> &'static str {
    match order {
        OrderBy::LastSeenDesc => " ORDER BY iocs.last_seen DESC",
        OrderBy::LastSeenAsc => " ORDER BY iocs.last_seen ASC",
        OrderBy::FirstSeenDesc => " ORDER BY iocs.first_seen DESC",
        OrderBy::ConfidenceDesc => " ORDER BY iocs.confidence DESC",
        OrderBy::DecayScoreDesc => " ORDER BY iocs.decay_score DESC",
    }
}

/// Escape `%`, `_` and `\` for a `LIKE ... ESCAPE '\'` pattern.
fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Apply a `Regex` or `Cidr` value matcher to hydrated candidate records.
fn post_filter_records(records: Vec<IocRecord>, matcher: &ValueMatcher) -> Result<Vec<IocRecord>> {
    match matcher {
        ValueMatcher::Regex(pattern) => {
            let re = regex::Regex::new(pattern)
                .map_err(|e| StoreError::Integrity(format!("invalid regex: {e}")))?;
            Ok(records.into_iter().filter(|r| re.is_match(&r.value)).collect())
        }
        ValueMatcher::Cidr(net) => Ok(records
            .into_iter()
            .filter(|r| match r.ioc_type {
                IocType::Ipv4 | IocType::Ipv6 => {
                    r.value.parse::<IpAddr>().map(|ip| net.contains(&ip)).unwrap_or(false)
                }
                _ => false,
            })
            .collect()),
        _ => Ok(records),
    }
}

/// Upsert a single indicator within a transaction. Returns `(ioc_id, added)`.
async fn upsert_in_tx(
    conn: &mut SqliteConnection,
    raw: &RawIoc,
    source_id: i64,
    default_conf: u8,
) -> Result<(i64, bool)> {
    let value = normalize(raw.ioc_type, &raw.value)?;
    let vh = value_hash(raw.ioc_type, &value);

    let now = Utc::now();
    let first_seen: DateTime<Utc> = raw.first_seen.unwrap_or(now);
    let last_seen: DateTime<Utc> = raw.last_seen.unwrap_or(now);
    let confidence = raw.confidence.unwrap_or(default_conf) as i64;
    let metadata = match &raw.raw {
        serde_json::Value::Null => None,
        v => Some(serde_json::to_string(v)?),
    };

    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM iocs WHERE value_hash = ?")
        .bind(&vh)
        .fetch_optional(&mut *conn)
        .await?;
    let added = existing.is_none();

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO iocs \
            (value, ioc_type, value_hash, first_seen, last_seen, confidence, \
             threat_type, malware_family, metadata) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(value_hash) DO UPDATE SET \
             first_seen     = min(iocs.first_seen, excluded.first_seen), \
             last_seen      = max(iocs.last_seen, excluded.last_seen), \
             confidence     = max(iocs.confidence, excluded.confidence), \
             threat_type    = COALESCE(iocs.threat_type, excluded.threat_type), \
             malware_family = COALESCE(iocs.malware_family, excluded.malware_family) \
         RETURNING id",
    )
    .bind(&value)
    .bind(raw.ioc_type.as_str())
    .bind(&vh)
    .bind(first_seen)
    .bind(last_seen)
    .bind(confidence)
    .bind(&raw.threat_type)
    .bind(&raw.malware_family)
    .bind(&metadata)
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO ioc_sources (ioc_id, source_id, first_seen, last_seen, confidence, raw_data) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(ioc_id, source_id) DO UPDATE SET \
             first_seen = min(ioc_sources.first_seen, excluded.first_seen), \
             last_seen  = max(ioc_sources.last_seen, excluded.last_seen), \
             confidence = excluded.confidence, \
             raw_data   = excluded.raw_data",
    )
    .bind(id)
    .bind(source_id)
    .bind(first_seen)
    .bind(last_seen)
    .bind(confidence)
    .bind(&metadata)
    .execute(&mut *conn)
    .await?;

    // Recompute the aggregated confidence over ALL source sightings using
    // Bayesian independent-evidence combination (design §11.1):
    //   conf_agg = 100 * (1 - Π(1 - conf_i / 100))
    // Per-source evidence weights are fixed at 1.0 for the MVP; weighting is
    // future work.
    recompute_confidence(conn, id).await?;

    // Link tags (namespace NULL for collector-provided tags).
    for tag in &raw.tags {
        sqlx::query("INSERT OR IGNORE INTO tags (name, namespace) VALUES (?, NULL)")
            .bind(tag)
            .execute(&mut *conn)
            .await?;
        let tag_id: i64 =
            sqlx::query_scalar("SELECT id FROM tags WHERE name = ? AND namespace IS NULL")
                .bind(tag)
                .fetch_one(&mut *conn)
                .await?;
        sqlx::query("INSERT OR IGNORE INTO ioc_tags (ioc_id, tag_id) VALUES (?, ?)")
            .bind(id)
            .bind(tag_id)
            .execute(&mut *conn)
            .await?;
    }

    // Link CVE references (stub CVE row if unknown).
    for cve in &raw.cve_refs {
        sqlx::query("INSERT OR IGNORE INTO cves (id) VALUES (?)")
            .bind(cve)
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO ioc_cves (ioc_id, cve_id) VALUES (?, ?)")
            .bind(id)
            .bind(cve)
            .execute(&mut *conn)
            .await?;
    }

    Ok((id, added))
}

/// Recompute and persist the aggregated confidence for `ioc_id`.
///
/// Aggregation is Bayesian independent-evidence combination (design §11.1):
/// `conf_agg = round(100 * (1 - Π(1 - conf_i / 100)))` over every row in
/// `ioc_sources`. Per-source weights are 1.0 for the MVP (future work).
async fn recompute_confidence(conn: &mut SqliteConnection, ioc_id: i64) -> Result<()> {
    let confidences: Vec<i64> =
        sqlx::query_scalar("SELECT confidence FROM ioc_sources WHERE ioc_id = ?")
            .bind(ioc_id)
            .fetch_all(&mut *conn)
            .await?;
    if confidences.is_empty() {
        return Ok(());
    }
    let mut complement = 1.0_f64;
    for c in confidences {
        let p = (c.clamp(0, 100) as f64) / 100.0;
        complement *= 1.0 - p;
    }
    let agg = ((1.0 - complement) * 100.0).round().clamp(0.0, 100.0) as i64;
    sqlx::query("UPDATE iocs SET confidence = ? WHERE id = ?")
        .bind(agg)
        .bind(ioc_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioc_vault_core::IocType;

    async fn store() -> IocStore {
        let s = IocStore::open_in_memory().await.unwrap();
        s.migrate().await.unwrap();
        s
    }

    #[tokio::test]
    async fn upsert_then_lookup_roundtrip() {
        let store = store().await;
        let mut raw = RawIoc::new("203.0.113.42", IocType::Ipv4);
        raw.confidence = Some(80);
        raw.threat_type = Some("c2".into());
        raw.tags = vec!["botnet".into()];
        raw.cve_refs = vec!["CVE-2026-0001".into()];

        let id = store.upsert(raw, "urlhaus").await.unwrap();
        let rec = store.lookup("203.0.113.42").await.unwrap().unwrap();

        assert_eq!(rec.id, Some(id));
        assert_eq!(rec.ioc_type, IocType::Ipv4);
        assert_eq!(rec.confidence, 80);
        assert_eq!(rec.threat_type.as_deref(), Some("c2"));
        assert_eq!(rec.tags, vec!["botnet".to_string()]);
        assert_eq!(rec.cve_refs, vec!["CVE-2026-0001".to_string()]);
        assert_eq!(rec.sources.len(), 1);
        assert_eq!(rec.sources[0].source_name, "urlhaus");
    }

    #[tokio::test]
    async fn normalization_dedups_across_sources() {
        let store = store().await;
        // Same IP in different textual form, from two sources.
        let mut a = RawIoc::new("192.168.001.001", IocType::Ipv4);
        a.confidence = Some(40);
        let mut b = RawIoc::new("192.168.1.1", IocType::Ipv4);
        b.confidence = Some(90);

        store.upsert(a, "feodo").await.unwrap();
        store.upsert(b, "threatfox").await.unwrap();

        let rec = store.lookup("192.168.1.1").await.unwrap().unwrap();
        // One deduped row, two source sightings. Confidence is the Bayesian
        // aggregate: 1 - (1 - 0.4)(1 - 0.9) = 0.94 -> 94.
        assert_eq!(rec.sources.len(), 2);
        assert_eq!(rec.confidence, 94);
    }

    #[tokio::test]
    async fn confidence_aggregates_two_sources() {
        let store = store().await;
        let mut a = RawIoc::new("203.0.113.9", IocType::Ipv4);
        a.confidence = Some(80);
        let mut b = RawIoc::new("203.0.113.9", IocType::Ipv4);
        b.confidence = Some(60);

        store.upsert(a, "feodo").await.unwrap();
        store.upsert(b, "threatfox").await.unwrap();

        let rec = store.lookup("203.0.113.9").await.unwrap().unwrap();
        // 1 - (1 - 0.8)(1 - 0.6) = 1 - 0.08 = 0.92 -> 92.
        assert_eq!(rec.sources.len(), 2);
        assert_eq!(rec.confidence, 92);
    }

    #[tokio::test]
    async fn bulk_upsert_counts_added_vs_updated() {
        let store = store().await;
        let batch1 = vec![
            RawIoc::new("a.example.com", IocType::Domain),
            RawIoc::new("b.example.com", IocType::Domain),
        ];
        let s1 = store.bulk_upsert(batch1, "openphish").await.unwrap();
        assert_eq!(s1.added, 2);
        assert_eq!(s1.updated, 0);

        let batch2 = vec![
            RawIoc::new("b.example.com", IocType::Domain),
            RawIoc::new("c.example.com", IocType::Domain),
        ];
        let s2 = store.bulk_upsert(batch2, "openphish").await.unwrap();
        assert_eq!(s2.added, 1);
        assert_eq!(s2.updated, 1);
    }

    #[tokio::test]
    async fn lookup_missing_returns_none() {
        let store = store().await;
        assert!(store.lookup("nope.example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn register_and_list_sources() {
        let store = store().await;
        store
            .register_source("urlhaus", "https://example/feed", "csv", 90, Tlp::Clear)
            .await
            .unwrap();
        // Upsert path: update url + confidence.
        store
            .register_source("urlhaus", "https://example/feed2", "csv", 80, Tlp::Green)
            .await
            .unwrap();
        let sources = store.list_sources().await.unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "urlhaus");
        assert_eq!(sources[0].url, "https://example/feed2");
        assert_eq!(sources[0].confidence_default, 80);
        assert!(sources[0].enabled);
    }

    #[tokio::test]
    async fn enable_disable_and_cache_roundtrip() {
        let store = store().await;
        store
            .register_source("threatfox", "https://api", "json", 75, Tlp::Clear)
            .await
            .unwrap();
        store.set_source_enabled("threatfox", false).await.unwrap();
        assert!(!store.list_sources().await.unwrap()[0].enabled);

        assert_eq!(
            store.get_source_cache("threatfox").await.unwrap(),
            Some((None, None))
        );
        store
            .update_source_cache("threatfox", Some("etag-1"), Some("Mon, 01 Jan 2024 00:00:00 GMT"))
            .await
            .unwrap();
        let cache = store.get_source_cache("threatfox").await.unwrap().unwrap();
        assert_eq!(cache.0.as_deref(), Some("etag-1"));
        assert!(store.list_sources().await.unwrap()[0].last_fetched_at.is_some());
        assert!(store.get_source_cache("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn record_run_and_upsert_cve() {
        let store = store().await;
        let now = Utc::now();
        store
            .record_run("urlhaus", now, now, "success", 3, 1, None)
            .await
            .unwrap();
        let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM collection_runs")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(runs, 1);

        store
            .upsert_cve("CVE-2021-44228", Some("2021-12-10"), true)
            .await
            .unwrap();
        // idempotent re-upsert.
        store
            .upsert_cve("CVE-2021-44228", None, true)
            .await
            .unwrap();
        let in_kev: i64 = sqlx::query_scalar("SELECT in_kev FROM cves WHERE id = ?")
            .bind("CVE-2021-44228")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(in_kev, 1);
    }

    #[tokio::test]
    async fn search_filters_by_type_and_min_confidence() {
        let store = store().await;
        let mut hi = RawIoc::new("203.0.113.10", IocType::Ipv4);
        hi.confidence = Some(95);
        let mut lo = RawIoc::new("203.0.113.11", IocType::Ipv4);
        lo.confidence = Some(40);
        let dom = RawIoc::new("evil.example.com", IocType::Domain);
        store.upsert(hi, "feed").await.unwrap();
        store.upsert(lo, "feed").await.unwrap();
        store.upsert(dom, "feed").await.unwrap();

        let q = SearchQuery::builder()
            .ioc_type(IocType::Ipv4)
            .min_confidence(70)
            .build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "203.0.113.10");
    }

    #[tokio::test]
    async fn search_filters_by_source() {
        let store = store().await;
        store.upsert(RawIoc::new("a.example.com", IocType::Domain), "alpha").await.unwrap();
        store.upsert(RawIoc::new("b.example.com", IocType::Domain), "beta").await.unwrap();

        let q = SearchQuery::builder().source("alpha").build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "a.example.com");
    }

    #[tokio::test]
    async fn search_filters_by_tag() {
        let store = store().await;
        let mut tagged = RawIoc::new("c.example.com", IocType::Domain);
        tagged.tags = vec!["phishing".into()];
        store.upsert(tagged, "feed").await.unwrap();
        store.upsert(RawIoc::new("d.example.com", IocType::Domain), "feed").await.unwrap();

        let q = SearchQuery::builder().tag("phishing").build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "c.example.com");
    }

    #[tokio::test]
    async fn search_cidr_match() {
        let store = store().await;
        store.upsert(RawIoc::new("192.0.2.5", IocType::Ipv4), "feed").await.unwrap();

        let inside: ipnet::IpNet = "192.0.2.0/24".parse().unwrap();
        let q = SearchQuery::builder().ioc_type(IocType::Ipv4).cidr(inside).build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "192.0.2.5");

        let outside: ipnet::IpNet = "198.51.100.0/24".parse().unwrap();
        let q = SearchQuery::builder().ioc_type(IocType::Ipv4).cidr(outside).build();
        assert!(store.search(&q).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn search_regex_match() {
        let store = store().await;
        store.upsert(RawIoc::new("malware.example.com", IocType::Domain), "feed").await.unwrap();
        store.upsert(RawIoc::new("good.example.org", IocType::Domain), "feed").await.unwrap();

        let q = SearchQuery::builder()
            .value_match(ValueMatcher::Regex(r"^malware\.".into()))
            .build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "malware.example.com");
    }

    #[tokio::test]
    async fn search_fts_match_on_threat_type() {
        let store = store().await;
        let mut c2 = RawIoc::new("203.0.113.20", IocType::Ipv4);
        c2.threat_type = Some("botnet-c2".into());
        store.upsert(c2, "feed").await.unwrap();
        store.upsert(RawIoc::new("203.0.113.21", IocType::Ipv4), "feed").await.unwrap();

        // Quote the phrase so FTS5 treats the hyphen literally (not as NOT).
        let q = SearchQuery::builder().fts("\"botnet-c2\"").build();
        let res = store.search(&q).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].value, "203.0.113.20");
    }

    #[tokio::test]
    async fn apply_decay_halves_at_half_life() {
        let store = store().await;
        let model = DecayModel::default();
        let fourteen_days_ago = Utc::now() - chrono::Duration::days(14);
        let mut raw = RawIoc::new("203.0.113.30", IocType::Ipv4);
        raw.last_seen = Some(fourteen_days_ago);
        store.upsert(raw, "feed").await.unwrap();

        let n = store.apply_decay(&model).await.unwrap();
        assert_eq!(n, 1);

        let rec = store.lookup("203.0.113.30").await.unwrap().unwrap();
        assert!(
            (rec.decay_score - 0.5).abs() < 0.05,
            "expected ~0.5, got {}",
            rec.decay_score
        );
    }

    #[tokio::test]
    async fn counts_reflect_inserts() {
        let store = store().await;
        store
            .bulk_upsert(
                vec![
                    RawIoc::new("a.example.com", IocType::Domain),
                    RawIoc::new("b.example.com", IocType::Domain),
                    RawIoc::new("203.0.113.1", IocType::Ipv4),
                ],
                "feed",
            )
            .await
            .unwrap();
        assert_eq!(store.count_iocs().await.unwrap(), 3);
        let by_type = store.counts_by_type().await.unwrap();
        let domains = by_type.iter().find(|(t, _)| t == "domain").unwrap().1;
        assert_eq!(domains, 2);
    }
}
