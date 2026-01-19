use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Cursor,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use clap::Parser;
use reqwest::Client;
use semver::{Op, Version, VersionReq};
use time_to_fix_cve::database::{Database, DownstreamVersionInfo};
use zip::ZipArchive;

fn ensure_parent_dir(path: &str) -> Result<()> {
    let p = Path::new(path);
    let Some(parent) = p.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)?;
    Ok(())
}

struct Logger {
    file: Option<std::io::BufWriter<std::fs::File>>,
}

impl Logger {
    fn new(path: Option<&str>) -> Result<Self> {
        let file = if let Some(p) = path {
            ensure_parent_dir(p)?;
            Some(std::io::BufWriter::new(std::fs::File::create(p)?))
        } else {
            None
        };
        Ok(Self { file })
    }

    fn println(&mut self, msg: impl AsRef<str>) -> Result<()> {
        let msg = msg.as_ref();
        eprintln!("{msg}");
        if let Some(w) = self.file.as_mut() {
            use std::io::Write;
            writeln!(w, "{msg}")?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(w) = self.file.as_mut() {
            use std::io::Write;
            w.flush()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SkipReason {
    Withdrawn,
    NoFixedVersions,
    NoFixTimes,
    NoSummaryT0,
    NoVulnVersions,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::Withdrawn => "withdrawn",
            SkipReason::NoFixedVersions => "no_fixed_versions",
            SkipReason::NoFixTimes => "no_fix_times",
            SkipReason::NoSummaryT0 => "no_summary_t0",
            SkipReason::NoVulnVersions => "no_vuln_versions",
        }
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "rustsec_rqx2_strict_lags.csv")]
    output: String,

    #[arg(long, default_value = "rustsec_rqx2_strict_summary.csv")]
    summary_output: String,

    #[arg(long, value_delimiter = ',', num_args = 0..)]
    only: Vec<String>,

    #[arg(long, default_value_t = false)]
    propagation: bool,

    #[arg(long, default_value = "rustsec_rqx2_propagation_summary.txt")]
    propagation_summary_output: String,

    #[arg(long, default_value = "rustsec_rqx2_propagation_svgs")]
    propagation_output_dir: String,

    #[arg(long)]
    propagation_max_hops: Option<usize>,

    #[arg(long, default_value_t = 60)]
    propagation_bins: usize,

    #[arg(long, default_value_t = false)]
    constraint: bool,

    #[arg(long, default_value = "rustsec_rqx2_constraint_breakdown.csv")]
    constraint_breakdown_output: String,

    #[arg(long, default_value = "rustsec_rqx2_constraint_summary.txt")]
    constraint_summary_output: String,

    #[arg(long, default_value = "rustsec_rqx2_constraint_svgs")]
    constraint_output_dir: String,

    #[arg(long, default_value_t = 40)]
    constraint_bins: usize,

    #[arg(long, default_value_t = 0)]
    constraint_min_age_days: i64,

    #[arg(long)]
    propagation_events_output: Option<String>,

    #[arg(long, default_value_t = 0)]
    propagation_events_limit: usize,

    #[arg(long, default_value_t = 5)]
    propagation_verify_samples: usize,

    #[arg(long, default_value_t = 50)]
    downstream_cache_crates: usize,

    #[arg(long)]
    max_advisories: Option<usize>,

    #[arg(long)]
    log_output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure_parent_dir(&args.output)?;
    ensure_parent_dir(&args.summary_output)?;
    if args.propagation {
        ensure_parent_dir(&args.propagation_summary_output)?;
    }
    if let Some(p) = args.propagation_events_output.as_deref() {
        ensure_parent_dir(p)?;
    }
    if args.constraint {
        ensure_parent_dir(&args.constraint_breakdown_output)?;
        ensure_parent_dir(&args.constraint_summary_output)?;
    }
    let mut logger = Logger::new(args.log_output.as_deref())?;

    logger.println("connecting to postgres...")?;
    let db = Database::connect_from_env().await?;
    let client = Client::builder()
        .user_agent("time-to-fix-cve/0.1")
        .build()?;

    logger.println("downloading rustsec advisory-db...")?;
    let mut advisories = fetch_rustsec_advisories(&client).await?;
    if !args.only.is_empty() {
        let allow: HashSet<String> = args
            .only
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        advisories.retain(|a| allow.contains(&a.cve_id) || allow.contains(&a.rustsec_id));
    }
    let total_advisories = advisories.len();
    logger.println(format!("rustsec advisories loaded: {total_advisories}"))?;

    let file = std::fs::File::create(&args.output)?;
    let mut w = csv::Writer::from_writer(file);

    let summary_file = std::fs::File::create(&args.summary_output)?;
    let mut sw = csv::Writer::from_writer(summary_file);

    let mut propagation_events_written = 0usize;
    let mut propagation_events_writer = if let Some(path) = &args.propagation_events_output {
        let file = std::fs::File::create(path)?;
        let mut w = csv::Writer::from_writer(file);
        w.write_record([
            "root_rustsec_id",
            "root_cve_id",
            "root_target_crate",
            "hop",
            "upstream_crate",
            "upstream_fix_version",
            "upstream_fix_time",
            "downstream_crate",
            "downstream_version",
            "downstream_time",
            "lag_days",
            "dep_req",
        ])?;
        Some(w)
    } else {
        None
    };
    let mut propagation_verify_samples: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        String,
    )> = Vec::new();

    let mut constraint_breakdown_writer = if args.constraint {
        let file = std::fs::File::create(&args.constraint_breakdown_output)?;
        let mut w = csv::Writer::from_writer(file);
        w.write_record([
            "rustsec_id",
            "cve_id",
            "severity",
            "target_crate",
            "fix_time",
            "downstream_crates_with_history",
            "affected_edges",
            "locked_out_edges",
            "break_rate_percent",
            "affected_req_exact_pin",
            "affected_req_has_upper_bound",
            "affected_req_caret_0x",
            "affected_req_other",
            "unknown_req_unparseable",
        ])?;
        Some(w)
    } else {
        None
    };
    let mut constraint_break_rate_per_adv_percent: Vec<i64> = Vec::new();
    let mut constraint_totals = ConstraintTotals::default();

    w.write_record([
        "rustsec_id",
        "cve_id",
        "severity",
        "target_crate",
        "fixed_version",
        "fix_time",
        "downstream_crate",
        "downstream_version",
        "downstream_time",
        "lag_days",
        "original_req",
        "fixed_req",
    ])?;

    sw.write_record([
        "rustsec_id",
        "cve_id",
        "severity",
        "target_crate",
        "fixed_version",
        "fix_time",
        "downstream_fixed_cnt",
        "lag_days_min",
        "lag_days_p50",
        "lag_days_avg",
        "lag_days_max",
    ])?;

    let mut processed = 0usize;
    let mut written_rows = 0usize;
    let mut skipped = 0usize;
    let mut skipped_by_reason: HashMap<SkipReason, usize> = HashMap::new();
    let mut propagation_fallback_latest_seed = 0usize;
    let mut crates_io_time_fallback_hits = 0usize;
    let mut crates_io_time_fallback_misses = 0usize;
    let mut crates_io_time_cache: HashMap<(String, String), Option<DateTime<Utc>>> = HashMap::new();
    let mut crate_versions_cache: HashMap<String, Vec<String>> = HashMap::new();
    let start = Instant::now();
    let mut last_progress = Instant::now();
    let now = Utc::now();

    let mut cache = DownstreamCache::new(args.downstream_cache_crates);
    let mut propagation_lags_by_hop: HashMap<usize, Vec<i64>> = HashMap::new();

    for adv in advisories {
        if let Some(limit) = args.max_advisories
            && processed >= limit
        {
            break;
        }

        processed += 1;
        if processed == 1 || last_progress.elapsed() >= Duration::from_secs(5) {
            logger.println(format!(
                "progress: {processed}/{total_advisories} advisories, written_rows={written_rows}, skipped={skipped}, elapsed={:.1}s",
                start.elapsed().as_secs_f64()
            ))?;
            last_progress = Instant::now();
        }

        if adv.withdrawn {
            record_skip(
                &mut logger,
                &mut skipped,
                &mut skipped_by_reason,
                &adv,
                SkipReason::Withdrawn,
                "advisory withdrawn".to_string(),
            )?;
            continue;
        }

        let pkg = normalize_crate_name(&adv.package);
        if pkg != adv.package {
            logger.println(format!(
                "package alias: rustsec_pkg={} db_pkg={}",
                adv.package, pkg
            ))?;
        }

        let fixed_versions = extract_all_fixed_versions(&adv.patched);
        let mut root_seed: Option<Carrier> = None;
        if fixed_versions.is_empty() && args.propagation {
            let patched_sample = adv
                .patched
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("|");
            let unaffected_sample = adv
                .unaffected
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("|");
            let all_versions =
                query_all_version_numbers_cached(&db, &mut crate_versions_cache, pkg).await?;
            let mut best: Option<Version> = None;
            for v_str in &all_versions {
                if let Ok(v) = Version::parse(v_str) {
                    match &best {
                        None => best = Some(v),
                        Some(b) => {
                            if v > *b {
                                best = Some(v);
                            }
                        }
                    }
                }
            }
            let Some(latest_version) = best else {
                record_skip(
                    &mut logger,
                    &mut skipped,
                    &mut skipped_by_reason,
                    &adv,
                    SkipReason::NoFixedVersions,
                    format!(
                        "fallback_latest_seed_failed: all_versions_count={} patched_versions_count={} unaffected_versions_count={} patched_sample={} unaffected_sample={}",
                        all_versions.len(),
                        adv.patched.len(),
                        adv.unaffected.len(),
                        patched_sample,
                        unaffected_sample
                    ),
                )?;
                continue;
            };
            let latest_version_str = latest_version.to_string();
            let resolved_str = resolve_equivalent_version_string(&all_versions, &latest_version)
                .unwrap_or_else(|| latest_version_str.clone());
            let latest_time = match db.query_version_time(pkg, &latest_version_str).await? {
                Some(t) => t,
                None => match db.query_version_time(pkg, &resolved_str).await? {
                    Some(t) => t,
                    None => {
                        let fetched = crates_io_query_version_time(
                            &client,
                            &mut crates_io_time_cache,
                            pkg,
                            &resolved_str,
                        )
                        .await?;
                        match fetched {
                            Some(t) => {
                                crates_io_time_fallback_hits += 1;
                                t
                            }
                            None => {
                                crates_io_time_fallback_misses += 1;
                                record_skip(
                                    &mut logger,
                                    &mut skipped,
                                    &mut skipped_by_reason,
                                    &adv,
                                    SkipReason::NoFixTimes,
                                    format!(
                                        "fallback_latest_seed_failed: latest_version={} resolved_version={} all_versions_count={} patched_versions_count={} unaffected_versions_count={} patched_sample={} unaffected_sample={}",
                                        latest_version_str,
                                        resolved_str,
                                        all_versions.len(),
                                        adv.patched.len(),
                                        adv.unaffected.len(),
                                        patched_sample,
                                        unaffected_sample
                                    ),
                                )?;
                                continue;
                            }
                        }
                    }
                },
            };
            propagation_fallback_latest_seed += 1;
            logger.println(format!(
                "propagation fallback: rustsec_id={} cve_id={} pkg={} reason=no_patched_using_latest_version latest_version={} latest_time={} patched_versions_count={} unaffected_versions_count={} patched_sample={} unaffected_sample={}",
                adv.rustsec_id,
                adv.cve_id,
                pkg,
                latest_version,
                latest_time,
                adv.patched.len(),
                adv.unaffected.len(),
                patched_sample,
                unaffected_sample
            ))?;
            root_seed = Some(Carrier {
                crate_name: pkg.to_string(),
                fix_version: latest_version,
                fix_time: latest_time,
                hop: 0,
            });
        }

        if fixed_versions.is_empty() && root_seed.is_none() {
            record_skip(
                &mut logger,
                &mut skipped,
                &mut skipped_by_reason,
                &adv,
                SkipReason::NoFixedVersions,
                format!(
                    "patched_versions_count={} unaffected_versions_count={} patched_sample={} unaffected_sample={}",
                    adv.patched.len(),
                    adv.unaffected.len(),
                    adv.patched
                        .iter()
                        .take(5)
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("|"),
                    adv.unaffected
                        .iter()
                        .take(5)
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            )?;
            continue;
        }

        // Query times for all fixed versions
        let mut fix_times = HashMap::new();
        if !fixed_versions.is_empty() {
            let all_versions =
                query_all_version_numbers_cached(&db, &mut crate_versions_cache, pkg).await?;
            for fv in &fixed_versions {
                let fv_str = fv.to_string();
                if let Some(t) = db.query_version_time(pkg, &fv_str).await? {
                    fix_times.insert(fv.clone(), t);
                    continue;
                }
                let resolved_str = resolve_equivalent_version_string(&all_versions, fv)
                    .unwrap_or_else(|| fv_str.clone());
                if let Some(t) = db.query_version_time(pkg, &resolved_str).await? {
                    fix_times.insert(fv.clone(), t);
                    continue;
                }
                let fetched = crates_io_query_version_time(
                    &client,
                    &mut crates_io_time_cache,
                    pkg,
                    &resolved_str,
                )
                .await?;
                match fetched {
                    Some(t) => {
                        crates_io_time_fallback_hits += 1;
                        fix_times.insert(fv.clone(), t);
                    }
                    None => {
                        crates_io_time_fallback_misses += 1;
                    }
                }
            }

            if fix_times.is_empty() {
                let mut used_ge_min = false;
                if adv.patched.iter().any(|s| VersionReq::parse(s).is_ok()) {
                    let published = parse_published_versions(&all_versions);
                    for req_str in &adv.patched {
                        let Ok(req) = VersionReq::parse(req_str) else {
                            continue;
                        };
                        let mut picked: Option<(&Version, &String)> = published
                            .iter()
                            .find(|(v, _)| req.matches(v))
                            .map(|x| (&x.0, &x.1));

                        if picked.is_none()
                            && !req_str.contains('<')
                            && let Some(min_v) = estimate_min_version(req_str)
                        {
                            picked = published
                                .iter()
                                .find(|(v, _)| *v >= min_v)
                                .map(|x| (&x.0, &x.1));
                            if picked.is_some() {
                                used_ge_min = true;
                            }
                        }

                        let Some((v, v_str)) = picked else {
                            continue;
                        };
                        if fix_times.contains_key(v) {
                            continue;
                        }
                        if let Some(t) = db.query_version_time(pkg, v_str).await? {
                            fix_times.insert(v.clone(), t);
                            continue;
                        }
                        let fetched = crates_io_query_version_time(
                            &client,
                            &mut crates_io_time_cache,
                            pkg,
                            v_str,
                        )
                        .await?;
                        match fetched {
                            Some(t) => {
                                crates_io_time_fallback_hits += 1;
                                fix_times.insert(v.clone(), t);
                            }
                            None => {
                                crates_io_time_fallback_misses += 1;
                            }
                        }
                    }

                    if !fix_times.is_empty() {
                        let mut xs: Vec<_> = fix_times.keys().cloned().collect();
                        xs.sort();
                        let reason = if used_ge_min {
                            "patched_req_first_published_or_ge_min"
                        } else {
                            "patched_req_first_published"
                        };
                        logger.println(format!(
                            "fixed_version fallback: rustsec_id={} cve_id={} pkg={} reason={} fixed_versions_sample={}",
                            adv.rustsec_id,
                            adv.cve_id,
                            pkg,
                            reason,
                            xs.iter()
                                .take(5)
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>()
                                .join("|")
                        ))?;
                    }
                }

                if fix_times.is_empty() {
                    record_skip(
                        &mut logger,
                        &mut skipped,
                        &mut skipped_by_reason,
                        &adv,
                        SkipReason::NoFixTimes,
                        format!(
                            "fixed_versions_count={} fixed_versions_sample={} db_versions_count={}",
                            fixed_versions.len(),
                            fixed_versions
                                .iter()
                                .take(5)
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>()
                                .join("|"),
                            all_versions.len()
                        ),
                    )?;
                    continue;
                }
            }
        }

        let mut effective_fixed_versions: Vec<Version> = fix_times.keys().cloned().collect();
        effective_fixed_versions.sort();
        let min_fixed_version = effective_fixed_versions.first().cloned();
        let min_fixed_version_str = min_fixed_version.as_ref().map(|v| v.to_string());

        // If the smallest version has no time (unlikely if fix_times is not empty, but possible if partial failure),
        // we try to find the earliest time among available ones for summary.
        let mut rows: Vec<StrictLagRow> = Vec::new();
        if !fix_times.is_empty() {
            let summary_t0 = min_fixed_version
                .as_ref()
                .and_then(|v| fix_times.get(v).cloned())
                .or_else(|| fix_times.values().min().cloned());

            let Some(summary_t0) = summary_t0 else {
                record_skip(
                    &mut logger,
                    &mut skipped,
                    &mut skipped_by_reason,
                    &adv,
                    SkipReason::NoSummaryT0,
                    format!(
                        "fixed_versions_count={} fix_times_count={}",
                        fixed_versions.len(),
                        fix_times.len()
                    ),
                )?;
                continue;
            };

            let all_versions =
                query_all_version_numbers_cached(&db, &mut crate_versions_cache, pkg).await?;
            let vuln_versions =
                identify_vuln_versions(&all_versions, &adv.patched, &adv.unaffected);

            if vuln_versions.is_empty() {
                record_skip(
                    &mut logger,
                    &mut skipped,
                    &mut skipped_by_reason,
                    &adv,
                    SkipReason::NoVulnVersions,
                    format!(
                        "all_versions_count={} patched_versions_count={} unaffected_versions_count={}",
                        all_versions.len(),
                        adv.patched.len(),
                        adv.unaffected.len()
                    ),
                )?;
                continue;
            }

            let downstream = cache.get_or_fetch(&db, pkg).await?;
            rows = compute_strict_lags_for_target(&fix_times, &vuln_versions, downstream);

            if args.constraint {
                if args.constraint_min_age_days > 0
                    && (now - summary_t0).num_days() < args.constraint_min_age_days
                {
                    continue;
                }
                let fixed_set: Vec<Version> = fix_times.keys().cloned().collect();
                let c = compute_constraint_breakdown(
                    summary_t0,
                    &vuln_versions,
                    &fixed_set,
                    downstream,
                );
                constraint_totals.add(&c);

                if let Some(w) = constraint_breakdown_writer.as_mut() {
                    w.write_record([
                        adv.rustsec_id.clone(),
                        adv.cve_id.clone(),
                        adv.severity.clone(),
                        pkg.to_string(),
                        summary_t0.to_string(),
                        c.downstream_crates_with_history.to_string(),
                        c.affected_edges.to_string(),
                        c.locked_out_edges.to_string(),
                        c.break_rate_percent.to_string(),
                        c.affected_req_exact_pin.to_string(),
                        c.affected_req_has_upper_bound.to_string(),
                        c.affected_req_caret_0x.to_string(),
                        c.affected_req_other.to_string(),
                        c.unknown_req_unparseable.to_string(),
                    ])?;
                }

                if c.affected_edges > 0 {
                    constraint_break_rate_per_adv_percent.push(c.break_rate_percent as i64);
                }
            }

            let stats = compute_lag_stats(rows.iter().map(|r| r.lag_days));
            if let Some(stats) = stats {
                sw.write_record([
                    adv.rustsec_id.clone(),
                    adv.cve_id.clone(),
                    adv.severity.clone(),
                    pkg.to_string(),
                    min_fixed_version_str
                        .clone()
                        .unwrap_or_else(|| "".to_string()),
                    summary_t0.to_string(),
                    stats.count.to_string(),
                    stats.min.to_string(),
                    format_float(stats.p50),
                    format_float(stats.avg),
                    stats.max.to_string(),
                ])?;
            }
        }

        if args.propagation {
            let mut best_seen: HashMap<String, (usize, chrono::DateTime<chrono::Utc>)> =
                HashMap::new();
            let mut queue: VecDeque<Carrier> = VecDeque::new();
            let mut last_adv_progress = Instant::now();
            let mut propagated_events = 0usize;

            if let Some(seed) = root_seed {
                let downstream = cache.get_or_fetch(&db, &seed.crate_name).await?;
                let events = compute_adoption_events_for_target(
                    &seed.fix_version,
                    seed.fix_time,
                    downstream,
                );
                for ev in events {
                    let recomputed = (ev.downstream_time - seed.fix_time).num_days();
                    if recomputed != ev.lag_days {
                        return Err(anyhow!(
                            "lag_days mismatch hop=1: {} {} -> {} {} csv={} recomputed={}",
                            adv.package,
                            seed.fix_time,
                            ev.downstream_crate,
                            ev.downstream_time,
                            ev.lag_days,
                            recomputed
                        ));
                    }
                    propagated_events += 1;
                    propagation_lags_by_hop
                        .entry(1)
                        .or_default()
                        .push(ev.lag_days);
                    if let Some(w) = propagation_events_writer.as_mut() {
                        let can_write = args.propagation_events_limit == 0
                            || propagation_events_written < args.propagation_events_limit;
                        if can_write {
                            w.write_record([
                                adv.rustsec_id.clone(),
                                adv.cve_id.clone(),
                                pkg.to_string(),
                                "1".to_string(),
                                pkg.to_string(),
                                seed.fix_version.to_string(),
                                seed.fix_time.to_string(),
                                ev.downstream_crate.clone(),
                                ev.downstream_version.to_string(),
                                ev.downstream_time.to_string(),
                                ev.lag_days.to_string(),
                                ev.dep_req.clone(),
                            ])?;
                            propagation_events_written += 1;
                        }
                    }
                    if args.propagation_verify_samples > 0
                        && propagation_verify_samples.len() < args.propagation_verify_samples
                    {
                        propagation_verify_samples.push((
                            pkg.to_string(),
                            ev.downstream_crate.clone(),
                            ev.downstream_version.to_string(),
                            ev.downstream_time,
                            ev.dep_req.clone(),
                        ));
                    }
                    let can_expand = match args.propagation_max_hops {
                        None => true,
                        Some(max_hops) => 1 < max_hops,
                    };
                    if can_expand {
                        let key = ev.downstream_crate.clone();
                        best_seen.insert(key.clone(), (1, ev.downstream_time));
                        queue.push_back(Carrier {
                            crate_name: key,
                            fix_version: ev.downstream_version,
                            fix_time: ev.downstream_time,
                            hop: 1,
                        });
                    }
                }
            } else {
                for r in &rows {
                    let recomputed = (r.downstream_time - r.matched_fix_time).num_days();
                    if recomputed != r.lag_days {
                        return Err(anyhow!(
                            "lag_days mismatch hop=1: {} {} -> {} {} csv={} recomputed={}",
                            adv.package,
                            r.matched_fix_time,
                            r.downstream_crate,
                            r.downstream_time,
                            r.lag_days,
                            recomputed
                        ));
                    }

                    propagation_lags_by_hop
                        .entry(1)
                        .or_default()
                        .push(r.lag_days);
                    if let Some(w) = propagation_events_writer.as_mut() {
                        let can_write = args.propagation_events_limit == 0
                            || propagation_events_written < args.propagation_events_limit;
                        if can_write {
                            w.write_record([
                                adv.rustsec_id.clone(),
                                adv.cve_id.clone(),
                                pkg.to_string(),
                                "1".to_string(),
                                pkg.to_string(),
                                r.matched_fix_version.clone(),
                                r.matched_fix_time.to_string(),
                                r.downstream_crate.clone(),
                                r.downstream_version.clone(),
                                r.downstream_time.to_string(),
                                r.lag_days.to_string(),
                                r.fixed_req.clone(),
                            ])?;
                            propagation_events_written += 1;
                        }
                    }
                    if args.propagation_verify_samples > 0
                        && propagation_verify_samples.len() < args.propagation_verify_samples
                    {
                        propagation_verify_samples.push((
                            pkg.to_string(),
                            r.downstream_crate.clone(),
                            r.downstream_version.clone(),
                            r.downstream_time,
                            r.fixed_req.clone(),
                        ));
                    }

                    let can_expand = match args.propagation_max_hops {
                        None => true,
                        Some(max_hops) => 1 < max_hops,
                    };
                    if can_expand && let Ok(v) = Version::parse(&r.downstream_version) {
                        let key = r.downstream_crate.clone();
                        best_seen.insert(key.clone(), (1, r.downstream_time));
                        queue.push_back(Carrier {
                            crate_name: key,
                            fix_version: v,
                            fix_time: r.downstream_time,
                            hop: 1,
                        });
                    }
                }
            }

            while let Some(carrier) = queue.pop_front() {
                if let Some(max_hops) = args.propagation_max_hops
                    && carrier.hop >= max_hops
                {
                    continue;
                }

                let next_hop = carrier.hop + 1;
                if let Some(max_hops) = args.propagation_max_hops
                    && next_hop > max_hops
                {
                    continue;
                }

                if last_adv_progress.elapsed() >= Duration::from_secs(5) {
                    logger.println(format!(
                        "propagation: adv={}/{} pkg={} queue={} seen={} events={} elapsed={:.1}s",
                        processed,
                        total_advisories,
                        pkg,
                        queue.len(),
                        best_seen.len(),
                        propagated_events,
                        start.elapsed().as_secs_f64()
                    ))?;
                    last_adv_progress = Instant::now();
                }

                let downstream = cache.get_or_fetch(&db, &carrier.crate_name).await?;
                let events = compute_adoption_events_for_target(
                    &carrier.fix_version,
                    carrier.fix_time,
                    downstream,
                );
                for ev in events {
                    let recomputed = (ev.downstream_time - carrier.fix_time).num_days();
                    if recomputed != ev.lag_days {
                        return Err(anyhow!(
                            "lag_days mismatch hop={}: {} {} -> {} {} csv={} recomputed={}",
                            next_hop,
                            carrier.crate_name,
                            carrier.fix_time,
                            ev.downstream_crate,
                            ev.downstream_time,
                            ev.lag_days,
                            recomputed
                        ));
                    }

                    propagated_events += 1;
                    propagation_lags_by_hop
                        .entry(next_hop)
                        .or_default()
                        .push(ev.lag_days);

                    if let Some(w) = propagation_events_writer.as_mut() {
                        let can_write = args.propagation_events_limit == 0
                            || propagation_events_written < args.propagation_events_limit;
                        if can_write {
                            w.write_record([
                                adv.rustsec_id.clone(),
                                adv.cve_id.clone(),
                                pkg.to_string(),
                                next_hop.to_string(),
                                carrier.crate_name.clone(),
                                carrier.fix_version.to_string(),
                                carrier.fix_time.to_string(),
                                ev.downstream_crate.clone(),
                                ev.downstream_version.to_string(),
                                ev.downstream_time.to_string(),
                                ev.lag_days.to_string(),
                                ev.dep_req.clone(),
                            ])?;
                            propagation_events_written += 1;
                        }
                    }
                    if args.propagation_verify_samples > 0
                        && propagation_verify_samples.len() < args.propagation_verify_samples
                    {
                        propagation_verify_samples.push((
                            carrier.crate_name.clone(),
                            ev.downstream_crate.clone(),
                            ev.downstream_version.to_string(),
                            ev.downstream_time,
                            ev.dep_req.clone(),
                        ));
                    }

                    let can_expand = match args.propagation_max_hops {
                        None => true,
                        Some(max_hops) => next_hop < max_hops,
                    };
                    if !can_expand {
                        continue;
                    }

                    let should_push = match best_seen.get(&ev.downstream_crate) {
                        None => true,
                        Some((seen_hop, seen_time)) => {
                            next_hop < *seen_hop
                                || (next_hop == *seen_hop && ev.downstream_time < *seen_time)
                        }
                    };
                    if should_push {
                        let key = ev.downstream_crate.clone();
                        best_seen.insert(key.clone(), (next_hop, ev.downstream_time));
                        queue.push_back(Carrier {
                            crate_name: key,
                            fix_version: ev.downstream_version,
                            fix_time: ev.downstream_time,
                            hop: next_hop,
                        });
                    }
                }
            }
        }

        for row in rows {
            w.write_record([
                adv.rustsec_id.clone(),
                adv.cve_id.clone(),
                adv.severity.clone(),
                pkg.to_string(),
                row.matched_fix_version.clone(),
                row.matched_fix_time.to_string(),
                row.downstream_crate,
                row.downstream_version,
                row.downstream_time.to_string(),
                row.lag_days.to_string(),
                row.original_req,
                row.fixed_req,
            ])?;
            written_rows += 1;
        }
    }

    w.flush()?;
    sw.flush()?;
    if let Some(w) = propagation_events_writer.as_mut() {
        w.flush()?;
    }
    if let Some(w) = constraint_breakdown_writer.as_mut() {
        w.flush()?;
    }
    logger.flush()?;

    if args.propagation {
        use std::io::Write;

        let mut hops: Vec<_> = propagation_lags_by_hop.into_iter().collect();
        hops.sort_by_key(|(h, _)| *h);

        let mut f = std::fs::File::create(&args.propagation_summary_output)?;
        let max_hop = hops.iter().map(|(h, _)| *h).max().unwrap_or(0);
        writeln!(f, "patch propagation analysis (hops=1..{})", max_hop)?;
        if let Some(max_hops) = args.propagation_max_hops {
            writeln!(f, "max_hops_limit = {}", max_hops)?;
        }
        writeln!(f)?;

        let mut all_lags: Vec<i64> = Vec::new();
        for (_, lags) in &hops {
            all_lags.extend_from_slice(lags);
        }
        if let Some(stats) = compute_lag_stats(all_lags.iter().copied()) {
            writeln!(f, "all hops")?;
            writeln!(f, "  count = {}", stats.count)?;
            writeln!(f, "  min   = {} days", stats.min)?;
            writeln!(f, "  p50   = {:.4} days", stats.p50)?;
            writeln!(f, "  avg   = {:.4} days", stats.avg)?;
            writeln!(f, "  max   = {} days", stats.max)?;
            writeln!(f)?;
        }

        for (hop, lags) in &hops {
            if lags.is_empty() {
                continue;
            }
            if let Some(stats) = compute_lag_stats(lags.iter().copied()) {
                writeln!(f, "hop {}", hop)?;
                writeln!(f, "  count = {}", stats.count)?;
                writeln!(f, "  min   = {} days", stats.min)?;
                writeln!(f, "  p50   = {:.4} days", stats.p50)?;
                writeln!(f, "  avg   = {:.4} days", stats.avg)?;
                writeln!(f, "  max   = {} days", stats.max)?;
                writeln!(f)?;
            }
        }

        let out_dir = Path::new(&args.propagation_output_dir);
        std::fs::create_dir_all(out_dir)?;
        if let Ok(rd) = std::fs::read_dir(out_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_file()
                    && let Some(name) = p.file_name().and_then(|s| s.to_str())
                    && name.starts_with("propagation_lag_hist_")
                    && name.ends_with(".svg")
                {
                    let _ = std::fs::remove_file(p);
                }
            }
        }

        if !all_lags.is_empty() {
            let x_max = all_lags.iter().copied().max().unwrap_or(1).max(1);
            let svg_path = out_dir.join("propagation_lag_hist_all.svg");
            write_hist_svg(
                &svg_path,
                &all_lags,
                args.propagation_bins,
                x_max,
                true,
                &format!(
                    "propagation lag_days histogram (all hops, n={})",
                    all_lags.len()
                ),
                &format!(
                    "bins={}, x_max={}, y_scale=log10",
                    args.propagation_bins, x_max
                ),
            )?;
        }

        for (hop, lags) in &hops {
            if lags.is_empty() {
                continue;
            }
            let x_max = lags.iter().copied().max().unwrap_or(1).max(1);
            let svg_path = out_dir.join(format!("propagation_lag_hist_hop_{}.svg", hop));
            write_hist_svg(
                &svg_path,
                lags,
                args.propagation_bins,
                x_max,
                true,
                &format!(
                    "propagation lag_days histogram (hop={}, n={})",
                    hop,
                    lags.len()
                ),
                &format!(
                    "bins={}, x_max={}, y_scale=log10",
                    args.propagation_bins, x_max
                ),
            )?;
        }
    }

    if args.constraint {
        use std::io::Write;

        let mut f = std::fs::File::create(&args.constraint_summary_output)?;
        writeln!(
            f,
            "constraint break analysis (edge=downstream crate at fix_time)"
        )?;
        if args.constraint_min_age_days > 0 {
            writeln!(f, "min_age_days = {}", args.constraint_min_age_days)?;
        }
        writeln!(f)?;
        writeln!(f, "totals")?;
        writeln!(
            f,
            "  downstream_crates_with_history = {}",
            constraint_totals.downstream_crates_with_history
        )?;
        writeln!(
            f,
            "  affected_edges                = {}",
            constraint_totals.affected_edges
        )?;
        writeln!(
            f,
            "  locked_out_edges              = {}",
            constraint_totals.locked_out_edges
        )?;
        writeln!(
            f,
            "  break_rate_percent            = {}",
            constraint_totals.break_rate_percent()
        )?;
        writeln!(
            f,
            "  unknown_req_unparseable       = {}",
            constraint_totals.unknown_req_unparseable
        )?;
        writeln!(f)?;
        writeln!(f, "affected edges dep_req shape (at fix_time)")?;
        writeln!(
            f,
            "  exact-pin (=...)              = {}",
            constraint_totals.affected_req_exact_pin
        )?;
        writeln!(
            f,
            "  has upper bound (< or <=)     = {}",
            constraint_totals.affected_req_has_upper_bound
        )?;
        writeln!(
            f,
            "  caret 0.x (^0.)               = {}",
            constraint_totals.affected_req_caret_0x
        )?;
        writeln!(
            f,
            "  other                         = {}",
            constraint_totals.affected_req_other
        )?;

        let out_dir = Path::new(&args.constraint_output_dir);
        std::fs::create_dir_all(out_dir)?;

        if !constraint_break_rate_per_adv_percent.is_empty() {
            let x_max = 100i64;
            let svg_path = out_dir.join("constraint_break_rate_hist_advisory.svg");
            write_hist_svg(
                &svg_path,
                &constraint_break_rate_per_adv_percent,
                args.constraint_bins,
                x_max,
                false,
                &format!(
                    "constraint break_rate histogram (per advisory, n={})",
                    constraint_break_rate_per_adv_percent.len()
                ),
                &format!(
                    "bins={}, x_max={}, y_scale=linear",
                    args.constraint_bins, x_max
                ),
            )?;
        }

        let svg_path = out_dir.join("constraint_req_shape_bar.svg");
        write_category_bar_svg(
            &svg_path,
            &[
                ("exact-pin (=...)", constraint_totals.affected_req_exact_pin),
                (
                    "upper bound (<,<=)",
                    constraint_totals.affected_req_has_upper_bound,
                ),
                ("caret 0.x (^0.)", constraint_totals.affected_req_caret_0x),
                ("other", constraint_totals.affected_req_other),
            ],
            "affected edges dep_req shape",
            &format!(
                "affected_edges={}, locked_out_edges={}, break_rate_percent={}",
                constraint_totals.affected_edges,
                constraint_totals.locked_out_edges,
                constraint_totals.break_rate_percent()
            ),
        )?;
    }

    if args.propagation
        && args.propagation_verify_samples > 0
        && !propagation_verify_samples.is_empty()
    {
        for (up, down, ver, t, req) in &propagation_verify_samples {
            let rows = db.query_all_downstream_details(up).await?;
            let ok = rows.iter().any(|r| {
                r.crate_name == *down
                    && r.version == *ver
                    && r.created_at == *t
                    && r.dep_req == *req
            });
            if !ok {
                return Err(anyhow!(
                    "propagation edge verify failed: upstream={} downstream={} version={} time={} dep_req={}",
                    up,
                    down,
                    ver,
                    t,
                    req
                ));
            }
        }
        logger.println(format!(
            "verified propagation edges: {} samples",
            propagation_verify_samples.len()
        ))?;
    }

    logger.println(format!(
        "processed advisories: {processed}, written rows: {written_rows}, skipped advisories: {skipped}"
    ))?;
    if propagation_fallback_latest_seed > 0 {
        logger.println(format!(
            "propagation fallback advisories (no patched using latest version): {}",
            propagation_fallback_latest_seed
        ))?;
    }
    if crates_io_time_fallback_hits > 0 || crates_io_time_fallback_misses > 0 {
        logger.println(format!(
            "crates.io version-time fallback: hits={} misses={}",
            crates_io_time_fallback_hits, crates_io_time_fallback_misses
        ))?;
    }
    if skipped > 0 {
        logger.println("skipped advisories breakdown:")?;
        let order = [
            SkipReason::Withdrawn,
            SkipReason::NoFixedVersions,
            SkipReason::NoFixTimes,
            SkipReason::NoSummaryT0,
            SkipReason::NoVulnVersions,
        ];
        for reason in order {
            if let Some(n) = skipped_by_reason.get(&reason) {
                logger.println(format!("  {}: {}", reason.as_str(), n))?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct ConstraintBreakdown {
    downstream_crates_with_history: usize,
    affected_edges: usize,
    locked_out_edges: usize,
    break_rate_percent: usize,
    affected_req_exact_pin: usize,
    affected_req_has_upper_bound: usize,
    affected_req_caret_0x: usize,
    affected_req_other: usize,
    unknown_req_unparseable: usize,
}

#[derive(Default)]
struct ConstraintTotals {
    downstream_crates_with_history: usize,
    affected_edges: usize,
    locked_out_edges: usize,
    affected_req_exact_pin: usize,
    affected_req_has_upper_bound: usize,
    affected_req_caret_0x: usize,
    affected_req_other: usize,
    unknown_req_unparseable: usize,
}

impl ConstraintTotals {
    fn add(&mut self, c: &ConstraintBreakdown) {
        self.downstream_crates_with_history += c.downstream_crates_with_history;
        self.affected_edges += c.affected_edges;
        self.locked_out_edges += c.locked_out_edges;
        self.affected_req_exact_pin += c.affected_req_exact_pin;
        self.affected_req_has_upper_bound += c.affected_req_has_upper_bound;
        self.affected_req_caret_0x += c.affected_req_caret_0x;
        self.affected_req_other += c.affected_req_other;
        self.unknown_req_unparseable += c.unknown_req_unparseable;
    }

    fn break_rate_percent(&self) -> usize {
        if self.affected_edges == 0 {
            return 0;
        }
        (self.locked_out_edges * 100) / self.affected_edges
    }
}

fn compute_constraint_breakdown(
    fix_time: chrono::DateTime<chrono::Utc>,
    vuln_versions: &[Version],
    fixed_versions: &[Version],
    downstream: &[DownstreamVersionInfo],
) -> ConstraintBreakdown {
    fn classify_req_shape(s: &str) -> ReqShape {
        let t = s.trim();
        if t.starts_with('=') {
            return ReqShape::ExactPin;
        }
        if t.starts_with("^0.") {
            return ReqShape::Caret0x;
        }
        if t.contains('<') {
            return ReqShape::HasUpperBound;
        }
        ReqShape::Other
    }

    #[derive(Clone, Copy)]
    enum ReqShape {
        ExactPin,
        HasUpperBound,
        Caret0x,
        Other,
    }

    let mut c = ConstraintBreakdown::default();

    let mut current: Option<&str> = None;
    let mut last_before: Option<&DownstreamVersionInfo> = None;

    let process = |row: Option<&DownstreamVersionInfo>, c: &mut ConstraintBreakdown| {
        let Some(row) = row else {
            return;
        };
        c.downstream_crates_with_history += 1;

        let Ok(req) = VersionReq::parse(&row.dep_req) else {
            c.unknown_req_unparseable += 1;
            return;
        };

        let affected = vuln_versions.iter().any(|v| req.matches(v));
        if !affected {
            return;
        }
        c.affected_edges += 1;

        match classify_req_shape(&row.dep_req) {
            ReqShape::ExactPin => c.affected_req_exact_pin += 1,
            ReqShape::HasUpperBound => c.affected_req_has_upper_bound += 1,
            ReqShape::Caret0x => c.affected_req_caret_0x += 1,
            ReqShape::Other => c.affected_req_other += 1,
        }

        let compatible = fixed_versions.iter().any(|v| req.matches(v));
        if !compatible {
            c.locked_out_edges += 1;
        }
    };

    for row in downstream {
        match current {
            None => {
                current = Some(row.crate_name.as_str());
                if row.created_at < fix_time {
                    last_before = Some(row);
                }
            }
            Some(name) if name == row.crate_name.as_str() => {
                if row.created_at < fix_time {
                    last_before = Some(row);
                }
            }
            Some(_) => {
                process(last_before.take(), &mut c);
                current = Some(row.crate_name.as_str());
                if row.created_at < fix_time {
                    last_before = Some(row);
                }
            }
        }
    }
    process(last_before.take(), &mut c);

    if c.affected_edges > 0 {
        c.break_rate_percent = (c.locked_out_edges * 100) / c.affected_edges;
    }
    c
}

fn write_category_bar_svg(
    path: &Path,
    categories: &[(&str, usize)],
    title: &str,
    subtitle: &str,
) -> Result<()> {
    let w = 960.0;
    let h = 520.0;
    let margin = 70.0;
    let plot_w = w - margin * 2.0;
    let plot_h = h - margin * 2.0;

    let axis = "#222222";
    let grid = "#E6E6E6";
    let fill = "#4C78A8";
    let font = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";

    let max_v = categories.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1) as f64;
    let bar_w = plot_w / categories.len().max(1) as f64;

    let x0 = margin;
    let y0 = margin;
    let x1 = w - margin;
    let y1 = h - margin;

    let y_ticks = nice_ticks(max_v, 6);

    let mut parts = Vec::new();
    parts.push(format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w_i}" height="{h_i}" viewBox="0 0 {w_i} {h_i}">"#,
        w_i = w as i64,
        h_i = h as i64
    ));
    parts.push(format!(
        r#"<rect x="0" y="0" width="{w_i}" height="{h_i}" fill="white"/>"#,
        w_i = w as i64,
        h_i = h as i64
    ));

    for t in y_ticks {
        let y = y1 - (t / max_v) * plot_h;
        parts.push(format!(
            r#"<line x1="{x0:.2}" y1="{y:.2}" x2="{x1:.2}" y2="{y:.2}" stroke="{grid}" stroke-width="1"/>"#
        ));
        parts.push(format!(
            r#"<text x="{x:.2}" y="{ytext:.2}" text-anchor="end" font-family="{font}" font-size="12" fill="{axis}">{label}</text>"#,
            x = x0 - 10.0,
            ytext = y + 4.0,
            label = svg_escape(&format!("{t:.0}"))
        ));
    }

    parts.push(format!(
        r#"<line x1="{x0:.2}" y1="{y1:.2}" x2="{x1:.2}" y2="{y1:.2}" stroke="{axis}" stroke-width="1.5"/>"#
    ));
    parts.push(format!(
        r#"<line x1="{x0:.2}" y1="{y0:.2}" x2="{x0:.2}" y2="{y1:.2}" stroke="{axis}" stroke-width="1.5"/>"#
    ));

    for (i, (name, v)) in categories.iter().enumerate() {
        let v = *v as f64;
        let bh = (v / max_v) * plot_h;
        let x = x0 + i as f64 * bar_w;
        let y = y1 - bh;
        parts.push(format!(
            r#"<rect x="{x:.2}" y="{y:.2}" width="{bw:.2}" height="{bh:.2}" fill="{fill}"/>"#,
            bw = (bar_w - 8.0).max(0.0)
        ));
        parts.push(format!(
            r#"<text x="{x:.2}" y="{y:.2}" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{label}</text>"#,
            x = x + bar_w / 2.0 - 4.0,
            y = y1 + 22.0,
            label = svg_escape(name)
        ));
    }

    parts.push(format!(
        r#"<text x="{x:.2}" y="28" text-anchor="middle" font-family="{font}" font-size="18" fill="{axis}">{t}</text>"#,
        x = w / 2.0,
        t = svg_escape(title)
    ));
    parts.push(format!(
        r#"<text x="{x:.2}" y="48" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{t}</text>"#,
        x = w / 2.0,
        t = svg_escape(subtitle)
    ));
    parts.push(format!(
        r#"<text x="18" y="{y:.2}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}" transform="rotate(-90 18 {y:.2})">count</text>"#,
        y = h / 2.0
    ));
    parts.push("</svg>\n".to_string());

    std::fs::write(path, parts.join("\n"))?;
    Ok(())
}

fn normalize_crate_name(name: &str) -> &str {
    match name {
        "rustdecimal" | "rust_demical" => "rust_decimal",
        _ => name,
    }
}

#[derive(serde::Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersion,
}

#[derive(serde::Deserialize)]
struct CratesIoVersion {
    created_at: String,
}

async fn crates_io_query_version_time(
    client: &Client,
    cache: &mut HashMap<(String, String), Option<DateTime<Utc>>>,
    crate_name: &str,
    version: &str,
) -> Result<Option<DateTime<Utc>>> {
    let key = (crate_name.to_string(), version.to_string());
    if let Some(v) = cache.get(&key) {
        return Ok(*v);
    }

    let url = format!("https://crates.io/api/v1/crates/{}/{}", crate_name, version);
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        cache.insert(key, None);
        return Ok(None);
    }

    let body: CratesIoVersionResponse = resp.json().await?;
    let parsed = chrono::DateTime::parse_from_rfc3339(&body.version.created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .ok();
    cache.insert(key, parsed);
    Ok(parsed)
}

async fn query_all_version_numbers_cached(
    db: &Database,
    cache: &mut HashMap<String, Vec<String>>,
    crate_name: &str,
) -> Result<Vec<String>> {
    if let Some(v) = cache.get(crate_name) {
        return Ok(v.clone());
    }
    let rows = db.query_all_version_numbers(crate_name).await?;
    cache.insert(crate_name.to_string(), rows.clone());
    Ok(rows)
}

fn resolve_equivalent_version_string(all_versions: &[String], wanted: &Version) -> Option<String> {
    let mut best: Option<String> = None;
    for s in all_versions {
        if let Ok(v) = Version::parse(s)
            && v.major == wanted.major
            && v.minor == wanted.minor
            && v.patch == wanted.patch
            && v.pre == wanted.pre
        {
            match &best {
                None => best = Some(s.clone()),
                Some(b) => {
                    if s > b {
                        best = Some(s.clone());
                    }
                }
            }
        }
    }
    best
}

fn parse_published_versions(all_versions: &[String]) -> Vec<(Version, String)> {
    let mut out: Vec<(Version, String)> = all_versions
        .iter()
        .filter_map(|s| Version::parse(s).ok().map(|v| (v, s.clone())))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out
}

fn record_skip(
    logger: &mut Logger,
    skipped: &mut usize,
    skipped_by_reason: &mut HashMap<SkipReason, usize>,
    adv: &Advisory,
    reason: SkipReason,
    detail: String,
) -> Result<()> {
    *skipped += 1;
    *skipped_by_reason.entry(reason).or_insert(0) += 1;
    logger.println(format!(
        "skip: rustsec_id={} cve_id={} pkg={} reason={} detail={}",
        adv.rustsec_id,
        adv.cve_id,
        adv.package,
        reason.as_str(),
        detail
    ))?;
    Ok(())
}

struct LagStats {
    count: usize,
    min: i64,
    max: i64,
    avg: f64,
    p50: f64,
}

fn compute_lag_stats<I>(lags: I) -> Option<LagStats>
where
    I: IntoIterator<Item = i64>,
{
    let mut xs: Vec<i64> = lags.into_iter().collect();
    if xs.is_empty() {
        return None;
    }
    xs.sort_unstable();
    let count = xs.len();
    let min = *xs.first().unwrap();
    let max = *xs.last().unwrap();
    let sum: i128 = xs.iter().map(|&x| x as i128).sum();
    let avg = sum as f64 / count as f64;
    let p50 = if count % 2 == 1 {
        xs[count / 2] as f64
    } else {
        (xs[count / 2 - 1] as f64 + xs[count / 2] as f64) / 2.0
    };
    Some(LagStats {
        count,
        min,
        max,
        avg,
        p50,
    })
}

fn format_float(v: f64) -> String {
    if v.is_finite() {
        format!("{v:.4}")
    } else {
        v.to_string()
    }
}

fn svg_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn nice_ticks(max_value: f64, tick_count: usize) -> Vec<f64> {
    if !max_value.is_finite() || max_value <= 0.0 {
        return vec![0.0];
    }
    let tick_count = tick_count.max(2);
    let raw_step = max_value / (tick_count as f64 - 1.0);
    let exp = raw_step.log10().floor();
    let base = 10f64.powf(exp);
    let frac = raw_step / base;
    let step = if frac <= 1.0 {
        1.0 * base
    } else if frac <= 2.0 {
        2.0 * base
    } else if frac <= 5.0 {
        5.0 * base
    } else {
        10.0 * base
    };
    let top = (max_value / step).ceil() * step;
    let mut ticks = Vec::new();
    let mut v = 0.0;
    while v <= top + 1e-9 {
        ticks.push(v);
        v += step;
    }
    ticks
}

fn histogram_counts(values: &[i64], bins: usize, x_max: i64) -> Vec<usize> {
    let bins = bins.max(1);
    let x_max = x_max.max(1) as f64;
    let w = x_max / bins as f64;
    let mut counts = vec![0usize; bins];
    for &v in values {
        if v < 0 {
            continue;
        }
        let vf = v as f64;
        let mut idx = (vf / w).floor() as isize;
        if idx < 0 {
            idx = 0;
        }
        if idx as usize >= bins {
            idx = bins as isize - 1;
        }
        counts[idx as usize] += 1;
    }
    counts
}

fn write_hist_svg(
    path: &Path,
    values: &[i64],
    bins: usize,
    x_max: i64,
    log_y: bool,
    title: &str,
    subtitle: &str,
) -> Result<()> {
    let bins = bins.max(1);
    let x_max = x_max.max(1);
    let counts = histogram_counts(values, bins, x_max);

    let y_values: Vec<f64> = if log_y {
        counts
            .iter()
            .map(|&c| if c > 0 { (c as f64).log10() } else { 0.0 })
            .collect()
    } else {
        counts.iter().map(|&c| c as f64).collect()
    };

    let y_max = y_values.iter().copied().fold(0.0, f64::max).max(1.0);

    let w = 960.0;
    let h = 540.0;
    let ml = 70.0;
    let mr = 20.0;
    let mt = 20.0;
    let mb = 60.0;
    let plot_w = w - ml - mr;
    let plot_h = h - mt - mb;
    let x0 = ml;
    let y0 = mt;
    let x1 = x0 + plot_w;
    let y1 = y0 + plot_h;
    let bar_w = plot_w / bins as f64;

    let axis = "#222222";
    let grid = "#E6E6E6";
    let fill = "#4C78A8";
    let font = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";

    let y_ticks = nice_ticks(y_max, 6);
    let x_ticks = nice_ticks(x_max as f64, 7);

    let mut parts = Vec::new();
    parts.push(format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w_i}" height="{h_i}" viewBox="0 0 {w_i} {h_i}">"#,
        w_i = w as i64,
        h_i = h as i64
    ));
    parts.push(format!(
        r#"<rect x="0" y="0" width="{w_i}" height="{h_i}" fill="white"/>"#,
        w_i = w as i64,
        h_i = h as i64
    ));

    for t in y_ticks {
        let y = y1 - (t / y_max) * plot_h;
        parts.push(format!(
            r#"<line x1="{x0:.2}" y1="{y:.2}" x2="{x1:.2}" y2="{y:.2}" stroke="{grid}" stroke-width="1"/>"#
        ));
        let label_val = if log_y {
            format!("{:.1}", t)
        } else {
            format!("{:.0}", t)
        };
        parts.push(format!(
            r#"<text x="{x:.2}" y="{ytext:.2}" text-anchor="end" font-family="{font}" font-size="12" fill="{axis}">{label}</text>"#,
            x = x0 - 10.0,
            ytext = y + 4.0,
            label = svg_escape(&label_val)
        ));
    }

    for t in x_ticks {
        let x = x0 + (t / x_max as f64) * plot_w;
        parts.push(format!(
            r#"<line x1="{x:.2}" y1="{y0:.2}" x2="{x:.2}" y2="{y1:.2}" stroke="{grid}" stroke-width="1"/>"#
        ));
        parts.push(format!(
            r#"<text x="{x:.2}" y="{ytext:.2}" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{label}</text>"#,
            ytext = y1 + 20.0,
            label = svg_escape(&format!("{:.0}", t))
        ));
    }

    parts.push(format!(
        r#"<line x1="{x0:.2}" y1="{y1:.2}" x2="{x1:.2}" y2="{y1:.2}" stroke="{axis}" stroke-width="1.5"/>"#
    ));
    parts.push(format!(
        r#"<line x1="{x0:.2}" y1="{y0:.2}" x2="{x0:.2}" y2="{y1:.2}" stroke="{axis}" stroke-width="1.5"/>"#
    ));

    for (i, &v) in y_values.iter().enumerate() {
        let bh = (v / y_max) * plot_h;
        let x = x0 + i as f64 * bar_w;
        let y = y1 - bh;
        parts.push(format!(
            r#"<rect x="{x:.2}" y="{y:.2}" width="{bw:.2}" height="{bh:.2}" fill="{fill}"/>"#,
            bw = (bar_w - 1.0).max(0.0)
        ));
    }

    parts.push(format!(
        r#"<text x="{x:.2}" y="28" text-anchor="middle" font-family="{font}" font-size="18" fill="{axis}">{t}</text>"#,
        x = w / 2.0,
        t = svg_escape(title)
    ));
    parts.push(format!(
        r#"<text x="{x:.2}" y="48" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{t}</text>"#,
        x = w / 2.0,
        t = svg_escape(subtitle)
    ));
    parts.push(format!(
        r#"<text x="{x:.2}" y="{y:.2}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}">lag_days</text>"#,
        x = w / 2.0,
        y = h - 20.0
    ));

    let y_label = if log_y { "count (log10)" } else { "count" };
    parts.push(format!(
        r#"<text x="18" y="{y:.2}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}" transform="rotate(-90 18 {y:.2})">{lbl}</text>"#,
        y = h / 2.0,
        lbl = y_label
    ));
    parts.push("</svg>\n".to_string());

    std::fs::write(path, parts.join("\n"))?;
    Ok(())
}

struct StrictLagRow {
    downstream_crate: String,
    downstream_version: String,
    downstream_time: chrono::DateTime<chrono::Utc>,
    lag_days: i64,
    original_req: String,
    fixed_req: String,
    matched_fix_version: String,
    matched_fix_time: chrono::DateTime<chrono::Utc>,
}

struct Carrier {
    crate_name: String,
    fix_version: Version,
    fix_time: chrono::DateTime<chrono::Utc>,
    hop: usize,
}

struct AdoptionEvent {
    downstream_crate: String,
    downstream_version: Version,
    downstream_time: chrono::DateTime<chrono::Utc>,
    lag_days: i64,
    dep_req: String,
}

fn compute_strict_lags_for_target(
    fix_times: &HashMap<Version, chrono::DateTime<chrono::Utc>>,
    vuln_versions: &[Version],
    downstream: &[DownstreamVersionInfo],
) -> Vec<StrictLagRow> {
    let mut by_crate: HashMap<&str, Vec<&DownstreamVersionInfo>> = HashMap::new();
    for row in downstream {
        by_crate
            .entry(row.crate_name.as_str())
            .or_default()
            .push(row);
    }

    let mut outputs = Vec::new();
    let mut skipped_negative = 0usize;
    for (downstream_crate, mut history) in by_crate {
        history.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.version.cmp(&b.version))
        });

        let mut ever_affected = false;
        let mut last_vuln_req: Option<String> = None;

        for item in history {
            let req = match VersionReq::parse(&item.dep_req) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let is_vuln = vuln_versions.iter().any(|v| req.matches(v));

            if is_vuln {
                ever_affected = true;
                last_vuln_req = Some(item.dep_req.clone());
                continue;
            }

            if ever_affected {
                let mut best_match: Option<(&Version, &chrono::DateTime<chrono::Utc>)> = None;

                for (fv, ftime) in fix_times {
                    if *ftime > item.created_at {
                        continue;
                    }
                    let mut is_match = req.matches(fv);
                    if !is_match
                        && let Some(min_v) = estimate_min_version(&item.dep_req)
                        && min_v >= *fv
                    {
                        is_match = true;
                    }

                    if is_match {
                        match best_match {
                            None => best_match = Some((fv, ftime)),
                            Some((_, best_time)) => {
                                if ftime < best_time {
                                    best_match = Some((fv, ftime));
                                }
                            }
                        }
                    }
                }

                if let Some((matched_ver, matched_time)) = best_match
                    && let Some(original_req) = last_vuln_req.take()
                {
                    let lag_days = (item.created_at - *matched_time).num_days();
                    if lag_days < 0 {
                        skipped_negative += 1;
                        continue;
                    }

                    outputs.push(StrictLagRow {
                        downstream_crate: downstream_crate.to_string(),
                        downstream_version: item.version.clone(),
                        downstream_time: item.created_at,
                        lag_days,
                        original_req,
                        fixed_req: item.dep_req.clone(),
                        matched_fix_version: matched_ver.to_string(),
                        matched_fix_time: *matched_time,
                    });
                    break;
                }
            }
        }
    }

    if skipped_negative > 0 {
        eprintln!(
            "warning: skipped negative strict lags: {}",
            skipped_negative
        );
    }
    outputs.sort_by(|a, b| a.downstream_crate.cmp(&b.downstream_crate));
    outputs
}

fn compute_adoption_events_for_target(
    fix_version: &Version,
    fix_time: chrono::DateTime<chrono::Utc>,
    downstream: &[DownstreamVersionInfo],
) -> Vec<AdoptionEvent> {
    fn min_allowed(dep_req: &str) -> Option<Version> {
        estimate_min_version(dep_req)
    }

    fn is_ever_affected(dep_req: &str, fix_version: &Version) -> bool {
        let Some(min_v) = min_allowed(dep_req) else {
            return false;
        };
        min_v < *fix_version
    }

    fn is_explicitly_fixed(dep_req: &str, fix_version: &Version) -> bool {
        let Some(min_v) = min_allowed(dep_req) else {
            return false;
        };
        min_v >= *fix_version
    }

    let mut by_crate: HashMap<&str, Vec<&DownstreamVersionInfo>> = HashMap::new();
    for row in downstream {
        by_crate
            .entry(row.crate_name.as_str())
            .or_default()
            .push(row);
    }

    let mut outputs = Vec::new();
    for (downstream_crate, mut history) in by_crate {
        history.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.version.cmp(&b.version))
        });

        let mut last_before: Option<&DownstreamVersionInfo> = None;
        for item in &history {
            if item.created_at < fix_time {
                last_before = Some(*item);
            } else {
                break;
            }
        }
        let Some(last_before) = last_before else {
            continue;
        };
        if !is_ever_affected(&last_before.dep_req, fix_version) {
            continue;
        }

        for item in history {
            if item.created_at < fix_time {
                continue;
            }

            if is_explicitly_fixed(&item.dep_req, fix_version) {
                let Ok(v) = Version::parse(&item.version) else {
                    break;
                };
                let lag_days = (item.created_at - fix_time).num_days();
                outputs.push(AdoptionEvent {
                    downstream_crate: downstream_crate.to_string(),
                    downstream_version: v,
                    downstream_time: item.created_at,
                    lag_days,
                    dep_req: item.dep_req.clone(),
                });
                break;
            }
        }
    }

    outputs
}

fn estimate_min_version(req_str: &str) -> Option<Version> {
    let s = req_str.trim();
    let s = s.split(',').next().unwrap_or(s).trim();
    let s = s.trim_start_matches(|c| {
        c == '^' || c == '~' || c == '=' || c == '>' || c == '<' || c == ' '
    });

    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }

    let s2 = format!("{}.0", s);
    if let Ok(v) = Version::parse(&s2) {
        return Some(v);
    }

    let s3 = format!("{}.0.0", s);
    if let Ok(v) = Version::parse(&s3) {
        return Some(v);
    }

    None
}

struct Advisory {
    rustsec_id: String,
    cve_id: String,
    severity: String,
    package: String,
    withdrawn: bool,
    patched: Vec<String>,
    unaffected: Vec<String>,
}

async fn fetch_rustsec_advisories(client: &Client) -> Result<Vec<Advisory>> {
    let url = "https://github.com/RustSec/advisory-db/archive/refs/heads/main.zip";
    let bytes = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let cursor = Cursor::new(bytes);
    let mut zip = ZipArchive::new(cursor)?;
    let mut out = Vec::new();

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        if !file.name().ends_with(".md") {
            continue;
        }
        if !file.name().contains("/crates/") {
            continue;
        }
        let mut s = String::new();
        std::io::Read::read_to_string(&mut file, &mut s)?;
        let Some(toml_str) = extract_toml_front_matter(&s) else {
            continue;
        };
        let val: toml::Value = toml::from_str(toml_str)?;
        let adv = parse_advisory(&val)?;
        out.push(adv);
    }

    out.sort_by(|a, b| a.rustsec_id.cmp(&b.rustsec_id));
    Ok(out)
}

fn extract_toml_front_matter(md: &str) -> Option<&str> {
    let start = md.find("```toml")?;
    let rest = &md[start + "```toml".len()..];
    let rest = rest.strip_prefix('\n').unwrap_or(rest);
    let end = rest.find("\n```")?;
    Some(&rest[..end])
}

fn parse_advisory(val: &toml::Value) -> Result<Advisory> {
    let advisory = val
        .get("advisory")
        .and_then(|v| v.as_table())
        .ok_or_else(|| anyhow!("missing [advisory]"))?;

    let rustsec_id = advisory
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing advisory.id"))?
        .to_string();

    let package = advisory
        .get("package")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing advisory.package"))?
        .to_string();

    let withdrawn = advisory.get("withdrawn").is_some();

    let cve_id = advisory
        .get("aliases")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .find(|s| s.starts_with("CVE-"))
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| rustsec_id.clone());

    let severity = extract_severity(advisory);

    let patched = val
        .get("versions")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("patched"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let unaffected = val
        .get("versions")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("unaffected"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(Advisory {
        rustsec_id,
        cve_id,
        severity,
        package,
        withdrawn,
        patched,
        unaffected,
    })
}

fn normalize_severity(s: &str) -> String {
    let u = s.trim().to_ascii_uppercase();
    match u.as_str() {
        "INFORMATIONAL" | "INFO" => "INFO".to_string(),
        "LOW" => "LOW".to_string(),
        "MEDIUM" | "MODERATE" => "MEDIUM".to_string(),
        "HIGH" => "HIGH".to_string(),
        "CRITICAL" => "CRITICAL".to_string(),
        _ => {
            if u.is_empty() {
                "UNKNOWN".to_string()
            } else {
                u
            }
        }
    }
}

fn extract_severity(advisory: &toml::value::Table) -> String {
    if let Some(s) = advisory.get("severity").and_then(|v| v.as_str()) {
        return normalize_severity(s);
    }
    if let Some(cvss) = advisory.get("cvss").and_then(|v| v.as_str())
        && let Some(score) = cvss31_base_score_from_vector(cvss)
    {
        return severity_from_cvss_score(score);
    }
    if advisory.get("informational").is_some() {
        return "INFO".to_string();
    }
    "UNKNOWN".to_string()
}

fn severity_from_cvss_score(score: f64) -> String {
    if !score.is_finite() || score <= 0.0 {
        return "INFO".to_string();
    }
    if score < 4.0 {
        "LOW".to_string()
    } else if score < 7.0 {
        "MEDIUM".to_string()
    } else if score < 9.0 {
        "HIGH".to_string()
    } else {
        "CRITICAL".to_string()
    }
}

fn cvss31_base_score_from_vector(s: &str) -> Option<f64> {
    let s = s.trim();
    let s = s
        .strip_prefix("CVSS:3.1/")
        .or_else(|| s.strip_prefix("CVSS:3.0/"))?;
    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr_u: Option<f64> = None;
    let mut pr_c: Option<f64> = None;
    let mut ui: Option<f64> = None;
    let mut scope: Option<char> = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for part in s.split('/') {
        let mut it = part.splitn(2, ':');
        let k = it.next()?.trim();
        let v = it.next()?.trim();
        match k {
            "AV" => {
                av = match v {
                    "N" => Some(0.85),
                    "A" => Some(0.62),
                    "L" => Some(0.55),
                    "P" => Some(0.20),
                    _ => None,
                };
            }
            "AC" => {
                ac = match v {
                    "L" => Some(0.77),
                    "H" => Some(0.44),
                    _ => None,
                };
            }
            "PR" => {
                pr_u = match v {
                    "N" => Some(0.85),
                    "L" => Some(0.62),
                    "H" => Some(0.27),
                    _ => None,
                };
                pr_c = match v {
                    "N" => Some(0.85),
                    "L" => Some(0.68),
                    "H" => Some(0.50),
                    _ => None,
                };
            }
            "UI" => {
                ui = match v {
                    "N" => Some(0.85),
                    "R" => Some(0.62),
                    _ => None,
                };
            }
            "S" => {
                scope = match v {
                    "U" => Some('U'),
                    "C" => Some('C'),
                    _ => None,
                };
            }
            "C" => {
                c = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            "I" => {
                i = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            "A" => {
                a = match v {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let ui = ui?;
    let scope = scope?;
    let pr = match scope {
        'U' => pr_u?,
        'C' => pr_c?,
        _ => return None,
    };
    let c = c?;
    let i = i?;
    let a = a?;

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope == 'U' {
        6.42 * iss
    } else {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    };
    let exploitability = 8.22 * av * ac * pr * ui;

    if impact <= 0.0 {
        return Some(0.0);
    }

    let raw = if scope == 'U' {
        (impact + exploitability).min(10.0)
    } else {
        (1.08 * (impact + exploitability)).min(10.0)
    };

    Some((raw * 10.0).ceil() / 10.0)
}

fn extract_all_fixed_versions(patched: &[String]) -> Vec<Version> {
    let mut candidates = Vec::new();
    for p in patched {
        if let Ok(v) = Version::parse(p) {
            candidates.push(v);
            continue;
        }
        if let Ok(req) = VersionReq::parse(p) {
            candidates.extend(extract_versions_from_req(&req));
        }
    }
    candidates.sort();
    candidates
}

fn extract_versions_from_req(req: &VersionReq) -> Vec<Version> {
    let mut out = Vec::new();
    for c in &req.comparators {
        let Some(minor) = c.minor else {
            continue;
        };
        let Some(patch) = c.patch else {
            continue;
        };
        let v = Version {
            major: c.major,
            minor,
            patch,
            pre: c.pre.clone(),
            build: semver::BuildMetadata::EMPTY,
        };
        match c.op {
            Op::Exact | Op::Greater | Op::GreaterEq | Op::Tilde | Op::Caret => out.push(v),
            _ => {}
        }
    }
    out
}

fn identify_vuln_versions(
    all_versions: &[String],
    patched: &[String],
    unaffected: &[String],
) -> Vec<Version> {
    let mut vuln = Vec::new();

    if patched.is_empty() && unaffected.is_empty() {
        for v_str in all_versions {
            if let Ok(v) = Version::parse(v_str) {
                vuln.push(v);
            }
        }
        vuln.sort();
        return vuln;
    }

    // Parse constraints
    let patched_reqs: Vec<VersionReq> = patched
        .iter()
        .filter_map(|s| VersionReq::parse(s).ok())
        .collect();
    let unaffected_reqs: Vec<VersionReq> = unaffected
        .iter()
        .filter_map(|s| VersionReq::parse(s).ok())
        .collect();

    // Check each version
    for v_str in all_versions {
        if let Ok(v) = Version::parse(v_str) {
            // Check if safe
            let is_patched = patched_reqs.iter().any(|req| req.matches(&v));
            let is_unaffected = unaffected_reqs.iter().any(|req| req.matches(&v));

            if !is_patched && !is_unaffected {
                vuln.push(v);
            }
        }
    }

    vuln.sort();
    vuln
}

struct DownstreamCache {
    max_crates: usize,
    order: std::collections::VecDeque<String>,
    map: HashMap<String, Vec<DownstreamVersionInfo>>,
}

impl DownstreamCache {
    fn new(max_crates: usize) -> Self {
        Self {
            max_crates: max_crates.max(1),
            order: std::collections::VecDeque::new(),
            map: HashMap::new(),
        }
    }

    async fn get_or_fetch(
        &mut self,
        db: &Database,
        target_crate: &str,
    ) -> Result<&Vec<DownstreamVersionInfo>> {
        if self.map.contains_key(target_crate) {
            self.touch(target_crate);
            return Ok(self.map.get(target_crate).unwrap());
        }

        let rows = db.query_all_downstream_details(target_crate).await?;
        self.insert(target_crate.to_string(), rows);
        Ok(self.map.get(target_crate).unwrap())
    }

    fn touch(&mut self, key: &str) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.to_string());
    }

    fn insert(&mut self, key: String, value: Vec<DownstreamVersionInfo>) {
        self.map.insert(key.clone(), value);
        self.touch(&key);

        while self.order.len() > self.max_crates {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }
}
