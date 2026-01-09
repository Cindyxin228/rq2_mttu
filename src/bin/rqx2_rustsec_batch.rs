use std::{collections::HashMap, io::Cursor};

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

    #[arg(long, default_value_t = 50)]
    downstream_cache_crates: usize,

    #[arg(long)]
    max_advisories: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let db = Database::connect_from_env().await?;
    let client = Client::new();

    let advisories = fetch_rustsec_advisories(&client).await?;

    let file = std::fs::File::create(&args.output)?;
    let mut w = csv::Writer::from_writer(file);

    let summary_file = std::fs::File::create(&args.summary_output)?;
    let mut sw = csv::Writer::from_writer(summary_file);
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

    let mut cache = DownstreamCache::new(args.downstream_cache_crates);

    for adv in advisories {
        if let Some(limit) = args.max_advisories
            && processed >= limit
        {
            break;
        }

        processed += 1;

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

        let downstream = cache.get_or_fetch(&db, &adv.package).await?.clone();

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

        for row in rows {
            w.write_record([
                adv.rustsec_id.clone(),
                adv.cve_id.clone(),
                adv.severity.clone(),
                adv.package.clone(),
                row.matched_fix_version.clone(),
                row.matched_fix_time.clone(),
                row.downstream_crate,
                row.downstream_version,
                row.downstream_time,
                row.lag_days.to_string(),
                row.original_req,
                row.fixed_req,
            ])?;
            written_rows += 1;
        }
    }

    w.flush()?;
    sw.flush()?;
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

struct StrictLagRow {
    downstream_crate: String,
    downstream_version: String,
    downstream_time: String,
    lag_days: i64,
    original_req: String,
    fixed_req: String,
    matched_fix_version: String,
    matched_fix_time: String,
}

fn compute_strict_lags_for_target(
    fix_times: &HashMap<Version, chrono::DateTime<chrono::Utc>>,
    vuln_versions: &[Version],
    downstream: Vec<DownstreamVersionInfo>,
) -> Vec<StrictLagRow> {
    let mut by_crate: HashMap<String, Vec<DownstreamVersionInfo>> = HashMap::new();
    for row in downstream {
        by_crate
            .entry(row.crate_name.clone())
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
                     let mut is_match = req.matches(fv);
                     if !is_match {
                        if let Some(min_v) = estimate_min_version(&item.dep_req) {
                            if min_v >= *fv {
                                is_match = true;
                            }
                        }
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

                 if let Some((matched_ver, matched_time)) = best_match {
                     if let Some(original_req) = last_vuln_req.take() {
                        let lag_days = (item.created_at - *matched_time).num_days();

                        outputs.push(StrictLagRow {
                            downstream_crate: downstream_crate.clone(),
                            downstream_version: item.version,
                            downstream_time: item.created_at.to_string(),
                            lag_days,
                            original_req,
                            fixed_req: item.dep_req,
                            matched_fix_version: matched_ver.to_string(),
                            matched_fix_time: matched_time.to_string(),
                        });
                        break;
                    }
                 }
            }
        }
    }

    outputs.sort_by(|a, b| a.downstream_crate.cmp(&b.downstream_crate));
    outputs
}

fn estimate_min_version(req_str: &str) -> Option<Version> {
    let s = req_str.trim();
    let s = s.split(',').next().unwrap_or(s).trim();
    let s = s.trim_start_matches(|c| c == '^' || c == '~' || c == '=' || c == '>' || c == '<' || c == ' ');
    
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
    if let Some(cvss) = advisory.get("cvss").and_then(|v| v.as_str()) {
        if let Some(score) = cvss31_base_score_from_vector(cvss) {
            return severity_from_cvss_score(score);
        }
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
    let s = s.strip_prefix("CVSS:3.1/").or_else(|| s.strip_prefix("CVSS:3.0/"))?;
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
