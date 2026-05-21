-- rs-ioc-vault initial schema (design §5.2).
-- PRAGMAs (journal_mode, foreign_keys, synchronous) are applied per-connection
-- via SqliteConnectOptions, not here.

CREATE TABLE sources (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    url                 TEXT NOT NULL,
    feed_type           TEXT NOT NULL,   -- csv|json|stix|misp|taxii|html|unknown
    tlp                 TEXT DEFAULT 'clear',
    license             TEXT,
    confidence_default  INTEGER DEFAULT 50,
    enabled             INTEGER NOT NULL DEFAULT 1,
    fetch_interval_sec  INTEGER DEFAULT 3600,
    last_fetched_at     TEXT,
    etag                TEXT,
    last_modified       TEXT,
    metadata            TEXT
);

CREATE TABLE iocs (
    id              INTEGER PRIMARY KEY,
    value           TEXT NOT NULL,
    ioc_type        TEXT NOT NULL,
    value_hash      TEXT NOT NULL UNIQUE,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    confidence      INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    tlp             TEXT DEFAULT 'clear',
    threat_type     TEXT,
    malware_family  TEXT,
    decay_score     REAL NOT NULL DEFAULT 1.0,
    is_allowlisted  INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT
);

CREATE INDEX idx_iocs_type      ON iocs(ioc_type);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen DESC);
CREATE INDEX idx_iocs_threat    ON iocs(threat_type);
CREATE INDEX idx_iocs_family    ON iocs(malware_family);
CREATE INDEX idx_iocs_decay     ON iocs(decay_score DESC);

CREATE TABLE ioc_sources (
    ioc_id      INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source_id   INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    confidence  INTEGER NOT NULL,
    raw_data    TEXT,
    PRIMARY KEY (ioc_id, source_id)
);

CREATE TABLE tags (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    namespace   TEXT,
    UNIQUE (namespace, name)
);

CREATE TABLE ioc_tags (
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (ioc_id, tag_id)
);

CREATE TABLE cves (
    id              TEXT PRIMARY KEY,
    cvss_base       REAL,
    cvss_version    TEXT,
    cvss_vector     TEXT,
    epss_score      REAL,
    epss_percentile REAL,
    in_kev          INTEGER NOT NULL DEFAULT 0,
    kev_date_added  TEXT,
    description     TEXT,
    last_updated    TEXT
);

CREATE TABLE ioc_cves (
    ioc_id        INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    cve_id        TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    relationship  TEXT NOT NULL DEFAULT 'related-to',
    PRIMARY KEY (ioc_id, cve_id)
);

CREATE TABLE sightings (
    id           INTEGER PRIMARY KEY,
    ioc_id       INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    observed_at  TEXT NOT NULL,
    observer     TEXT,
    count        INTEGER NOT NULL DEFAULT 1,
    context      TEXT
);
CREATE INDEX idx_sightings_ioc  ON sightings(ioc_id);
CREATE INDEX idx_sightings_time ON sightings(observed_at);

CREATE TABLE collection_runs (
    id              INTEGER PRIMARY KEY,
    source_id       INTEGER NOT NULL REFERENCES sources(id),
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,           -- success|partial|failed|skipped
    iocs_added      INTEGER NOT NULL DEFAULT 0,
    iocs_updated    INTEGER NOT NULL DEFAULT 0,
    bytes_fetched   INTEGER,
    error_message   TEXT
);

CREATE TABLE allowlist (
    id            INTEGER PRIMARY KEY,
    pattern       TEXT NOT NULL,
    pattern_type  TEXT NOT NULL,             -- exact|regex|cidr
    ioc_type      TEXT,
    reason        TEXT,
    added_by      TEXT,
    added_at      TEXT NOT NULL
);

CREATE TABLE watchlist (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    pattern_type TEXT NOT NULL,
    webhook_url  TEXT,
    created_at   TEXT NOT NULL
);

CREATE VIRTUAL TABLE iocs_fts USING fts5(
    value, threat_type, malware_family, metadata,
    content='iocs', content_rowid='id',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER iocs_ai AFTER INSERT ON iocs BEGIN
    INSERT INTO iocs_fts(rowid, value, threat_type, malware_family, metadata)
    VALUES (new.id, new.value, new.threat_type, new.malware_family, new.metadata);
END;
CREATE TRIGGER iocs_ad AFTER DELETE ON iocs BEGIN
    INSERT INTO iocs_fts(iocs_fts, rowid, value, threat_type, malware_family, metadata)
    VALUES ('delete', old.id, old.value, old.threat_type, old.malware_family, old.metadata);
END;
CREATE TRIGGER iocs_au AFTER UPDATE ON iocs BEGIN
    INSERT INTO iocs_fts(iocs_fts, rowid, value, threat_type, malware_family, metadata)
    VALUES ('delete', old.id, old.value, old.threat_type, old.malware_family, old.metadata);
    INSERT INTO iocs_fts(rowid, value, threat_type, malware_family, metadata)
    VALUES (new.id, new.value, new.threat_type, new.malware_family, new.metadata);
END;
