use std::{collections::HashMap, fs::File};

use anyhow::{Result, anyhow};
use clap::Parser;
use semver::{Version, VersionReq};
use time_to_fix_cve::database;
use time_to_fix_cve::database::Database;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    cve_id: String,

    #[arg(long)]
    target_crate: String,

    #[arg(long)]
    fixed_version: String,

    #[arg(long)]
    vuln_version_sample: String,
}

struct OutputRow {
    crate_name: String,
    fix_version: String,
    fix_time: String,
    lag_days: i64,
    original_req: String,
    fixed_req: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let fixed_version = Version::parse(&args.fixed_version)
        .map_err(|e| anyhow!("invalid --fixed-version {}: {e}", args.fixed_version))?;
    let vuln_sample = Version::parse(&args.vuln_version_sample).map_err(|e| {
        anyhow!(
            "invalid --vuln-version-sample {}: {e}",
            args.vuln_version_sample
        )
    })?;

    let db = Database::connect_from_env().await?;
    let t0 = db
        .query_version_time(&args.target_crate, &args.fixed_version)
        .await?
        .ok_or_else(|| {
            anyhow!(
                "cannot find published time for {} {}",
                args.target_crate,
                args.fixed_version
            )
        })?;

    let downstream = db.query_all_downstream_details(&args.target_crate).await?;
    let mut by_crate: HashMap<String, Vec<database::DownstreamVersionInfo>> = HashMap::new();
    for row in downstream {
        by_crate
            .entry(row.crate_name.clone())
            .or_default()
            .push(row);
    }

    let mut outputs = Vec::new();

    for (crate_name, mut history) in by_crate {
        history.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.version.cmp(&b.version))
        });

        let mut ever_affected = false;
        let mut last_vuln_req: Option<String> = None;
        let mut found_fix: Option<OutputRow> = None;

        for item in history {
            let req = match VersionReq::parse(&item.dep_req) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "skip {} {}: cannot parse req {} ({e})",
                        crate_name, item.version, item.dep_req
                    );
                    continue;
                }
            };

            let allows_vuln = req.matches(&vuln_sample);
            if allows_vuln {
                ever_affected = true;
                last_vuln_req = Some(item.dep_req.clone());
                continue;
            }

            if ever_affected
                && req.matches(&fixed_version)
                && let Some(original_req) = last_vuln_req.take()
            {
                let lag_days = (item.created_at - t0).num_days();
                found_fix = Some(OutputRow {
                    crate_name: crate_name.clone(),
                    fix_version: args.fixed_version.clone(),
                    fix_time: t0.to_string(),
                    lag_days,
                    original_req,
                    fixed_req: item.dep_req.clone(),
                });
                break;
            }
        }

        match found_fix {
            Some(r) => outputs.push(r),
            None => {
                if ever_affected {
                    eprintln!("crate {crate_name} was affected but never explicitly fixed");
                }
            }
        }
    }

    outputs.sort_by(|a, b| a.crate_name.cmp(&b.crate_name));

    let out_path = format!("rqx2_strict_lag_{}.csv", args.cve_id);
    let file = File::create(&out_path)?;
    let mut w = csv::Writer::from_writer(file);
    w.write_record([
        "crate",
        "fix_version",
        "fix_time",
        "lag_days",
        "original_req",
        "fixed_req",
    ])?;
    for row in outputs {
        w.write_record([
            row.crate_name,
            row.fix_version,
            row.fix_time,
            row.lag_days.to_string(),
            row.original_req,
            row.fixed_req,
        ])?;
    }
    w.flush()?;

    println!("wrote {out_path}");
    Ok(())
}
