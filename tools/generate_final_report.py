import os
from pathlib import Path

def read_file(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None

def main():
    report = []
    report.append("# Final Analysis Report")
    
    report.append("\n## 1. Strict Lag Analysis (Direct Dependencies)")
    if Path("rustsec_rqx2_strict_lags.csv").exists():
        report.append("- **Data Source**: `rustsec_rqx2_strict_lags.csv` (Found)")
    else:
        report.append("- **Data Source**: `rustsec_rqx2_strict_lags.csv` (Missing)")

    sev_dir = Path("lag_days_by_severity_svgs")
    if sev_dir.exists():
        svgs = list(sev_dir.glob("*.svg"))
        report.append(f"- **Visualizations**: Found {len(svgs)} severity histograms in `{sev_dir}`")
    else:
        sev_dir_alt = Path("lag_days_by_severity_svgs_all")
        if sev_dir_alt.exists():
             svgs = list(sev_dir_alt.glob("*.svg"))
             report.append(f"- **Visualizations**: Found {len(svgs)} severity histograms in `{sev_dir_alt}`")
        else:
            report.append(f"- **Visualizations**: Severity histograms missing")

    report.append("\n## 2. Propagation Analysis (Transitive Impact)")
    prop_summary = read_file("rustsec_rqx2_propagation_summary.txt")
    if prop_summary:
        report.append("### Key Metrics")
        report.append("```text")
        report.append(prop_summary)
        report.append("```")
    else:
        report.append("- **Summary**: Not found (`rustsec_rqx2_propagation_summary.txt`)")

    prop_svg_dir = Path("rustsec_rqx2_propagation_svgs")
    if prop_svg_dir.exists():
        svgs = list(prop_svg_dir.glob("*.svg"))
        report.append(f"- **Visualizations**: Found {len(svgs)} propagation histograms in `{prop_svg_dir}`")
        report.append("  - **Note**: These graphs use a **log10 scale** for the y-axis to better display long-tail distribution (as requested).")
    else:
        report.append(f"- **Visualizations**: Missing (`{prop_svg_dir}`)")

    report.append("\n## 3. Constraint Analysis (Blockage)")
    cons_summary = read_file("rustsec_rqx2_constraint_summary.txt")
    if cons_summary:
        report.append("### Key Metrics")
        report.append("```text")
        report.append(cons_summary)
        report.append("```")
    else:
        report.append("- **Summary**: Not found (`rustsec_rqx2_constraint_summary.txt`)")
        
    cons_svg_dir = Path("rustsec_rqx2_constraint_svgs")
    if cons_svg_dir.exists():
        svgs = list(cons_svg_dir.glob("*.svg"))
        report.append(f"- **Visualizations**: Found {len(svgs)} constraint graphs in `{cons_svg_dir}`")
    
    report.append("\n## 4. File Manifest")
    report.append("| File/Directory | Description | Status |")
    report.append("|---|---|---|")
    
    files = [
        ("rustsec_rqx2_strict_lags.csv", "Raw data for direct dependency lags"),
        ("rustsec_rqx2_propagation_summary.txt", "Summary stats for propagation hops"),
        ("rustsec_rqx2_constraint_summary.txt", "Summary stats for constraint breaks"),
        ("rustsec_rqx2_propagation_svgs/", "Histograms of propagation delays (Log Scale)"),
        ("rustsec_rqx2_constraint_svgs/", "Visualizations of constraint types and break rates"),
        ("lag_days_by_severity_svgs/", "Strict lag histograms by severity"),
    ]
    
    for path, desc in files:
        status = "✅ Found" if Path(path).exists() else "❌ Missing"
        report.append(f"| `{path}` | {desc} | {status} |")

    Path("FINAL_REPORT.md").write_text("\n".join(report))
    print("Report generated: FINAL_REPORT.md")

if __name__ == "__main__":
    main()
