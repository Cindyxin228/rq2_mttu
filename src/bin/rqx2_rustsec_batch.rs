use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Cursor,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use clap::Parser;
use reqwest::Client;
use semver::{Op, Version, VersionReq};
use time_to_fix_cve::database::{Database, DownstreamVersionInfo};
use zip::ZipArchive;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("connecting to postgres...");
    let db = Database::connect_from_env().await?;
    let client = Client::new();

    eprintln!("downloading rustsec advisory-db...");
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
    eprintln!("rustsec advisories loaded: {total_advisories}");

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
    let start = Instant::now();
    let mut last_progress = Instant::now();

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
            eprintln!(
                "progress: {processed}/{total_advisories} advisories, written_rows={written_rows}, skipped={skipped}, elapsed={:.1}s",
                start.elapsed().as_secs_f64()
            );
            last_progress = Instant::now();
        }

        let fixed_versions = adv.fixed_versions_candidates();
        if fixed_versions.is_empty() {
            skipped += 1;
            continue;
        }

        // Query times for all fixed versions
        let mut fix_times = HashMap::new();
        for fv in &fixed_versions {
            let fv_str = fv.to_string();
            if let Some(t) = db.query_version_time(&adv.package, &fv_str).await? {
                fix_times.insert(fv.clone(), t);
            }
        }

        if fix_times.is_empty() {
            skipped += 1;
            continue;
        }

        // Use the smallest fixed version for vuln sample selection and summary reporting
        let min_fixed_version = fixed_versions.first().unwrap(); // sorted in extract_all_fixed_versions
        let min_fixed_version_str = min_fixed_version.to_string();

        // If the smallest version has no time (unlikely if fix_times is not empty, but possible if partial failure),
        // we try to find the earliest time among available ones for summary.
        let summary_t0 = fix_times.get(min_fixed_version).cloned().or_else(|| {
            // fallback: min time
            fix_times.values().min().cloned()
        });

        let Some(summary_t0) = summary_t0 else {
            skipped += 1;
            continue;
        };

        let all_versions = db.query_all_version_numbers(&adv.package).await?;
        let vuln_versions = identify_vuln_versions(&all_versions, &adv.patched, &adv.unaffected);

        if vuln_versions.is_empty() {
            skipped += 1;
            continue;
        }

        let downstream = cache.get_or_fetch(&db, &adv.package).await?;

        let rows = compute_strict_lags_for_target(&fix_times, &vuln_versions, downstream);

        let stats = compute_lag_stats(rows.iter().map(|r| r.lag_days));
        if let Some(stats) = stats {
            sw.write_record([
                adv.rustsec_id.clone(),
                adv.cve_id.clone(),
                adv.severity.clone(),
                adv.package.clone(),
                min_fixed_version_str.clone(),
                summary_t0.to_string(),
                stats.count.to_string(),
                stats.min.to_string(),
                format_float(stats.p50),
                format_float(stats.avg),
                stats.max.to_string(),
            ])?;
        }

        if args.propagation {
            let mut best_seen: HashMap<String, (usize, chrono::DateTime<chrono::Utc>)> =
                HashMap::new();
            let mut queue: VecDeque<Carrier> = VecDeque::new();
            let mut last_adv_progress = Instant::now();
            let mut propagated_events = 0usize;

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
                            adv.package.clone(),
                            "1".to_string(),
                            adv.package.clone(),
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
                        adv.package.clone(),
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
                    eprintln!(
                        "propagation: adv={}/{} pkg={} queue={} seen={} events={} elapsed={:.1}s",
                        processed,
                        total_advisories,
                        adv.package,
                        queue.len(),
                        best_seen.len(),
                        propagated_events,
                        start.elapsed().as_secs_f64()
                    );
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
                                adv.package.clone(),
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
                adv.package.clone(),
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
                &format!(
                    "propagation lag_days histogram (all hops, n={})",
                    all_lags.len()
                ),
                &format!("bins={}, x_max={}", args.propagation_bins, x_max),
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
                &format!(
                    "propagation lag_days histogram (hop={}, n={})",
                    hop,
                    lags.len()
                ),
                &format!("bins={}, x_max={}", args.propagation_bins, x_max),
            )?;
        }
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
        eprintln!(
            "verified propagation edges: {} samples",
            propagation_verify_samples.len()
        );
    }

    eprintln!(
        "processed advisories: {processed}, written rows: {written_rows}, skipped advisories: {skipped}"
    );
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
    title: &str,
    subtitle: &str,
) -> Result<()> {
    let bins = bins.max(1);
    let x_max = x_max.max(1);
    let counts = histogram_counts(values, bins, x_max);
    let y_max = counts.iter().copied().max().unwrap_or(0).max(1) as f64;

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
        parts.push(format!(
            r#"<text x="{x:.2}" y="{ytext:.2}" text-anchor="end" font-family="{font}" font-size="12" fill="{axis}">{label}</text>"#,
            x = x0 - 10.0,
            ytext = y + 4.0,
            label = svg_escape(&format!("{t:.0}"))
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

    for (i, &c) in counts.iter().enumerate() {
        let bh = (c as f64 / y_max) * plot_h;
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
    parts.push(format!(
        r#"<text x="18" y="{y:.2}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}" transform="rotate(-90 18 {y:.2})">count</text>"#,
        y = h / 2.0
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

impl Advisory {
    fn fixed_versions_candidates(&self) -> Vec<Version> {
        if self.withdrawn {
            return vec![];
        }
        extract_all_fixed_versions(&self.patched)
    }
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
