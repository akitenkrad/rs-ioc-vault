//! `ioc-vault` command-line interface.

mod config;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use rs_ioc_vault::{
    DecayModel, ExportFormat, IocType, OrderBy, SearchQuery, Tlp, UpdateOptions, ValueMatcher,
};
use rs_ioc_vault::IocVault;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "ioc-vault", version, about = "OSINT IoC store")]
struct Cli {
    /// Database path (default: ~/.ioc-vault/vault.db).
    #[arg(long, global = true)]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize the database (open + migrate).
    Init,
    /// Manage sources.
    Source {
        #[command(subcommand)]
        action: SourceAction,
    },
    /// Update one or all sources.
    Update(UpdateArgs),
    /// Look up an indicator by value.
    Lookup {
        value: String,
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
    /// Search indicators with composable filters.
    Search(Box<SearchArgs>),
    /// Export indicators to CSV / JSONL / STIX 2.1 / MISP.
    Export(Box<ExportArgs>),
    /// Recompute time-decay scores for all indicators.
    Decay,
    /// Show store statistics.
    Stats,
}

#[derive(Subcommand)]
enum SourceAction {
    /// List configured sources.
    List,
    /// Add (or update) a source.
    Add {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long = "feed-type")]
        feed_type: String,
        #[arg(long, default_value_t = 50)]
        confidence: u8,
    },
    /// Enable a source.
    Enable { name: String },
    /// Disable a source.
    Disable { name: String },
}

#[derive(Args)]
struct UpdateArgs {
    /// Update every registered source.
    #[arg(long)]
    all: bool,
    /// Update a single source by name.
    #[arg(long)]
    source: Option<String>,
    /// Window: `7d` (days) or an ISO date `YYYY-MM-DD`.
    #[arg(long)]
    since: Option<String>,
}

#[derive(Args)]
struct SearchArgs {
    #[command(flatten)]
    filters: FilterArgs,
    /// Output format.
    #[arg(long, default_value = "table")]
    format: OutputFormat,
}

#[derive(Args)]
struct ExportArgs {
    #[command(flatten)]
    filters: FilterArgs,
    /// Export format: csv | jsonl | stix | misp.
    #[arg(long)]
    format: ExportFormatArg,
    /// Output file path (default: stdout).
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Filter flags shared by `search` and `export`.
#[derive(Args)]
struct FilterArgs {
    /// Indicator type filter (repeatable; also accepts a comma list).
    #[arg(long = "type", value_delimiter = ',')]
    types: Vec<String>,
    /// Source name filter (repeatable / comma list).
    #[arg(long = "source", value_delimiter = ',')]
    sources: Vec<String>,
    /// Threat type filter (repeatable / comma list).
    #[arg(long = "threat-type", value_delimiter = ',')]
    threat_types: Vec<String>,
    /// Malware family filter (repeatable / comma list).
    #[arg(long = "malware-family", value_delimiter = ',')]
    malware_families: Vec<String>,
    /// Tag filter (repeatable / comma list).
    #[arg(long = "tag", value_delimiter = ',')]
    tags: Vec<String>,
    /// CVE id filter (repeatable / comma list).
    #[arg(long = "cve", value_delimiter = ',')]
    cves: Vec<String>,
    /// Last-seen window: `Nd` (days) or `YYYY-MM-DD`.
    #[arg(long)]
    since: Option<String>,
    /// Minimum aggregated confidence (0-100).
    #[arg(long = "min-confidence")]
    min_confidence: Option<u8>,
    /// Minimum decay score (0.0-1.0).
    #[arg(long = "min-decay")]
    min_decay: Option<f32>,
    /// CIDR membership match (post-filtered in Rust).
    #[arg(long)]
    cidr: Option<String>,
    /// Regex value match (post-filtered in Rust).
    #[arg(long)]
    regex: Option<String>,
    /// Substring value match.
    #[arg(long)]
    contains: Option<String>,
    /// Prefix value match.
    #[arg(long)]
    prefix: Option<String>,
    /// Exact value match (normalized when a single --type is given).
    #[arg(long)]
    exact: Option<String>,
    /// Full-text search query (FTS5).
    #[arg(long)]
    fts: Option<String>,
    /// Maximum results.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Result ordering.
    #[arg(long, default_value = "last-seen-desc")]
    order: OrderArg,
}

#[derive(Clone, Copy)]
enum OrderArg {
    LastSeenDesc,
    LastSeenAsc,
    FirstSeenDesc,
    ConfidenceDesc,
    DecayDesc,
}

impl FromStr for OrderArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "last-seen-desc" => Ok(OrderArg::LastSeenDesc),
            "last-seen-asc" => Ok(OrderArg::LastSeenAsc),
            "first-seen-desc" => Ok(OrderArg::FirstSeenDesc),
            "confidence-desc" => Ok(OrderArg::ConfidenceDesc),
            "decay-desc" => Ok(OrderArg::DecayDesc),
            other => Err(format!("unknown order: {other}")),
        }
    }
}

impl From<OrderArg> for OrderBy {
    fn from(o: OrderArg) -> Self {
        match o {
            OrderArg::LastSeenDesc => OrderBy::LastSeenDesc,
            OrderArg::LastSeenAsc => OrderBy::LastSeenAsc,
            OrderArg::FirstSeenDesc => OrderBy::FirstSeenDesc,
            OrderArg::ConfidenceDesc => OrderBy::ConfidenceDesc,
            OrderArg::DecayDesc => OrderBy::DecayScoreDesc,
        }
    }
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Table,
    Json,
    Jsonl,
}

impl FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "jsonl" => Ok(OutputFormat::Jsonl),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

/// Clap-parseable wrapper around [`ExportFormat`].
#[derive(Clone, Copy)]
struct ExportFormatArg(ExportFormat);

impl FromStr for ExportFormatArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ExportFormat::from_str(s)
            .map(ExportFormatArg)
            .map_err(|e| e.to_string())
    }
}

fn default_db_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    let dir = PathBuf::from(home).join(".ioc-vault");
    std::fs::create_dir_all(&dir).context("failed to create ~/.ioc-vault")?;
    Ok(dir.join("vault.db"))
}

/// Parse `--since`: accepts `Nd` (days) or an ISO date `YYYY-MM-DD`.
fn parse_since(s: &str) -> anyhow::Result<UpdateOptions> {
    use chrono::{NaiveDate, TimeZone, Utc};
    if let Some(days) = s.strip_suffix('d') {
        let n: i64 = days.parse().context("invalid day count in --since")?;
        return Ok(UpdateOptions::since_days(n));
    }
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .context("--since must be `Nd` or `YYYY-MM-DD`")?;
    let dt = Utc
        .from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap());
    Ok(UpdateOptions { since: Some(dt) })
}

/// Translate parsed CLI filter args into a [`SearchQuery`].
fn build_search_query(args: &FilterArgs) -> anyhow::Result<SearchQuery> {
    let mut b = SearchQuery::builder();

    for t in &args.types {
        let t = IocType::from_str(t).with_context(|| format!("invalid --type: {t}"))?;
        b = b.ioc_type(t);
    }
    for s in &args.sources {
        b = b.source(s.clone());
    }
    for v in &args.threat_types {
        b = b.threat_type(v.clone());
    }
    for v in &args.malware_families {
        b = b.malware_family(v.clone());
    }
    for v in &args.tags {
        b = b.tag(v.clone());
    }
    for v in &args.cves {
        b = b.cve_id(v.clone());
    }
    if let Some(s) = &args.since
        && let Some(t) = parse_since(s)?.since
    {
        b = b.last_seen_after(t);
    }
    if let Some(c) = args.min_confidence {
        b = b.min_confidence(c);
    }
    if let Some(d) = args.min_decay {
        b = b.min_decay_score(d);
    }
    if let Some(q) = &args.fts {
        b = b.fts(q.clone());
    }

    // Value matcher: pick the first one provided (most specific wins).
    if let Some(net) = &args.cidr {
        let net: ipnet::IpNet = net.parse().context("invalid --cidr")?;
        b = b.value_match(ValueMatcher::Cidr(net));
    } else if let Some(re) = &args.regex {
        b = b.value_match(ValueMatcher::Regex(re.clone()));
    } else if let Some(v) = &args.exact {
        b = b.value_match(ValueMatcher::Exact(v.clone()));
    } else if let Some(v) = &args.prefix {
        b = b.value_match(ValueMatcher::Prefix(v.clone()));
    } else if let Some(v) = &args.contains {
        b = b.value_match(ValueMatcher::Contains(v.clone()));
    }

    Ok(b.order_by(args.order.into()).limit(args.limit).build())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let db = match &cli.db {
        Some(p) => p.clone(),
        None => default_db_path()?,
    };

    let cfg = config::Config::load(&config::default_config_path()?)?;

    let vault = IocVault::builder()
        .database(&db)
        .threatfox_auth_key(cfg.threatfox_auth_key())
        .with_default_collectors()
        .build()
        .await?;

    match cli.command {
        Command::Init => {
            println!("initialized: {}", db.display());
        }
        Command::Source { action } => match action {
            SourceAction::List => {
                let sources = vault.store().list_sources().await?;
                if sources.is_empty() {
                    println!("(no sources configured)");
                }
                for s in sources {
                    println!(
                        "{:<14} {:<6} enabled={} conf={:<3} {}",
                        s.name,
                        s.feed_type,
                        s.enabled,
                        s.confidence_default,
                        s.url
                    );
                }
            }
            SourceAction::Add {
                name,
                url,
                feed_type,
                confidence,
            } => {
                vault
                    .store()
                    .register_source(&name, &url, &feed_type, confidence, Tlp::Clear)
                    .await?;
                println!("added source: {name}");
            }
            SourceAction::Enable { name } => {
                vault.store().set_source_enabled(&name, true).await?;
                println!("enabled: {name}");
            }
            SourceAction::Disable { name } => {
                vault.store().set_source_enabled(&name, false).await?;
                println!("disabled: {name}");
            }
        },
        Command::Update(args) => {
            let opts = match args.since.as_deref() {
                Some(s) => parse_since(s)?,
                None => UpdateOptions::default(),
            };
            if args.all || args.source.is_none() {
                let report = vault.update_all(&opts).await?;
                println!("{:<14} {:>7} {:>8} {:>8}", "source", "added", "updated", "skipped");
                for r in report.per_source {
                    println!(
                        "{:<14} {:>7} {:>8} {:>8}",
                        r.source, r.added, r.updated, r.skipped
                    );
                }
            } else if let Some(name) = args.source {
                let r = vault.update_source(&name, &opts).await?;
                println!(
                    "{}: added={} updated={} skipped={}",
                    r.source, r.added, r.updated, r.skipped
                );
            }
        }
        Command::Lookup { value, format } => {
            let rec = vault.lookup(&value).await?;
            match (rec, format) {
                (None, OutputFormat::Json) => println!("null"),
                (None, OutputFormat::Jsonl) => {}
                (None, OutputFormat::Table) => println!("not found: {value}"),
                (Some(rec), OutputFormat::Json) => {
                    println!("{}", serde_json::to_string_pretty(&rec)?);
                }
                (Some(rec), OutputFormat::Jsonl) => {
                    println!("{}", serde_json::to_string(&rec)?);
                }
                (Some(rec), OutputFormat::Table) => {
                    println!("value:       {}", rec.value);
                    println!("type:        {}", rec.ioc_type);
                    println!("confidence:  {}", rec.confidence);
                    println!("first_seen:  {}", rec.first_seen);
                    println!("last_seen:   {}", rec.last_seen);
                    if let Some(t) = &rec.threat_type {
                        println!("threat:      {t}");
                    }
                    if let Some(m) = &rec.malware_family {
                        println!("malware:     {m}");
                    }
                    if !rec.tags.is_empty() {
                        println!("tags:        {}", rec.tags.join(", "));
                    }
                    let names: Vec<&str> =
                        rec.sources.iter().map(|s| s.source_name.as_str()).collect();
                    println!("sources:     {}", names.join(", "));
                }
            }
        }
        Command::Search(args) => {
            let q = build_search_query(&args.filters)?;
            let results = vault.search(&q).await?;
            match args.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
                OutputFormat::Jsonl => {
                    for rec in &results {
                        println!("{}", serde_json::to_string(rec)?);
                    }
                }
                OutputFormat::Table => {
                    if results.is_empty() {
                        println!("(no matches)");
                    } else {
                        println!(
                            "{:<40} {:<14} {:>4} {:<25} {:>7}",
                            "value", "type", "conf", "last_seen", "sources"
                        );
                        for rec in &results {
                            println!(
                                "{:<40} {:<14} {:>4} {:<25} {:>7}",
                                rec.value,
                                rec.ioc_type.to_string(),
                                rec.confidence,
                                rec.last_seen.to_rfc3339(),
                                rec.sources.len()
                            );
                        }
                    }
                }
            }
        }
        Command::Export(args) => {
            let q = build_search_query(&args.filters)?;
            let format = args.format.0;
            let count = match &args.out {
                Some(path) => {
                    let file = std::fs::File::create(path)
                        .with_context(|| format!("failed to create {}", path.display()))?;
                    let writer = std::io::BufWriter::new(file);
                    vault.export(format, &q, writer).await?
                }
                None => {
                    let stdout = std::io::stdout();
                    let writer = std::io::BufWriter::new(stdout.lock());
                    vault.export(format, &q, writer).await?
                }
            };
            let fmt_name = match format {
                ExportFormat::Csv => "csv",
                ExportFormat::Jsonl => "jsonl",
                ExportFormat::Stix => "stix",
                ExportFormat::Misp => "misp",
            };
            eprintln!("exported {count} records ({fmt_name})");
        }
        Command::Decay => {
            let n = vault.apply_decay(&DecayModel::default()).await?;
            println!("decayed {n} records");
        }
        Command::Stats => {
            let total = vault.store().count_iocs().await?;
            println!("total iocs: {total}");
            for (t, n) in vault.store().counts_by_type().await? {
                println!("  {t:<14} {n}");
            }
        }
    }

    Ok(())
}
