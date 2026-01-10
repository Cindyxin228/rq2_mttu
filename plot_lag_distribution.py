#!/usr/bin/env python3
import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PlotSpec:
    width: int
    height: int
    margin_left: int
    margin_right: int
    margin_top: int
    margin_bottom: int


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot lag_days distribution as an SVG histogram.")
    p.add_argument(
        "--input",
        default="rustsec_rqx2_strict_lags.csv",
        help="Input CSV (default: rustsec_rqx2_strict_lags.csv)",
    )
    p.add_argument(
        "--output",
        default="lag_days_hist.svg",
        help="Output SVG path (default: lag_days_hist.svg)",
    )
    p.add_argument(
        "--by-severity",
        action="store_true",
        help="Generate one SVG per RustSec severity value",
    )
    p.add_argument(
        "--output-dir",
        default=".",
        help="Output directory when using --by-severity (default: .)",
    )
    p.add_argument(
        "--bins",
        type=int,
        default=60,
        help="Histogram bin count (default: 60)",
    )
    p.add_argument(
        "--max-days",
        type=int,
        default=-1,
        help="Cap x-axis max day (default: use data max)",
    )
    p.add_argument(
        "--log-y",
        action="store_true",
        help="Use log10 scale for y values",
    )
    p.add_argument(
        "--filter",
        default="",
        help="Regex filter applied to rustsec_id/cve_id/target_crate/downstream_crate (optional)",
    )
    return p.parse_args()


def read_lags(path: Path) -> list[int]:
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        out: list[int] = []
        for row in r:
            v = row.get("lag_days", "").strip()
            if not v:
                continue
            out.append(int(v))
    return out


def read_lags_filtered(path: Path, pattern: str) -> list[int]:
    if not pattern:
        return read_lags(path)
    import re

    rx = re.compile(pattern)
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        out: list[int] = []
        for row in r:
            hay = " ".join(
                [
                    row.get("rustsec_id", ""),
                    row.get("cve_id", ""),
                    row.get("target_crate", ""),
                    row.get("downstream_crate", ""),
                ]
            )
            if not rx.search(hay):
                continue
            v = row.get("lag_days", "").strip()
            if not v:
                continue
            out.append(int(v))
        return out


def read_lags_by_severity_filtered(path: Path, pattern: str) -> dict[str, list[int]]:
    import re

    rx = re.compile(pattern) if pattern else None
    out: dict[str, list[int]] = {}
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            hay = " ".join(
                [
                    row.get("rustsec_id", ""),
                    row.get("cve_id", ""),
                    row.get("severity", ""),
                    row.get("target_crate", ""),
                    row.get("downstream_crate", ""),
                ]
            )
            if rx and not rx.search(hay):
                continue

            v = row.get("lag_days", "").strip()
            if not v:
                continue

            sev = (row.get("severity", "") or "UNKNOWN").strip().upper() or "UNKNOWN"
            out.setdefault(sev, []).append(int(v))
    return out


def clean_output_dir_for_severity(out_dir: Path) -> None:
    if not out_dir.exists():
        return
    for p in out_dir.glob("lag_days_hist_*.svg"):
        if p.is_file():
            p.unlink()


def histogram(values: list[int], bins: int, x_max: int) -> tuple[list[int], list[tuple[float, float]]]:
    if bins <= 0:
        raise ValueError("--bins must be positive")
    if x_max <= 0:
        raise ValueError("x_max must be positive")
    counts = [0 for _ in range(bins)]
    edges: list[tuple[float, float]] = []
    step = x_max / bins
    for i in range(bins):
        lo = i * step
        hi = (i + 1) * step
        edges.append((lo, hi))
    for v in values:
        if v < 0:
            continue
        if v >= x_max:
            idx = bins - 1
        else:
            idx = int(v / step)
            if idx >= bins:
                idx = bins - 1
        counts[idx] += 1
    return counts, edges


def svg_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def nice_ticks(max_value: float, tick_count: int) -> list[float]:
    if max_value <= 0:
        return [0.0]
    tick_count = max(2, tick_count)
    raw_step = max_value / (tick_count - 1)
    exp = math.floor(math.log10(raw_step))
    base = 10 ** exp
    frac = raw_step / base
    if frac <= 1:
        step = 1 * base
    elif frac <= 2:
        step = 2 * base
    elif frac <= 5:
        step = 5 * base
    else:
        step = 10 * base
    top = math.ceil(max_value / step) * step
    ticks = []
    v = 0.0
    while v <= top + 1e-9:
        ticks.append(v)
        v += step
    return ticks


def write_svg(
    output: Path,
    values: list[int],
    counts: list[int],
    edges: list[tuple[float, float]],
    x_max: int,
    log_y: bool,
    title: str,
    subtitle: str,
) -> None:
    spec = PlotSpec(
        width=960,
        height=540,
        margin_left=70,
        margin_right=20,
        margin_top=20,
        margin_bottom=60,
    )

    w = spec.width
    h = spec.height
    plot_w = w - spec.margin_left - spec.margin_right
    plot_h = h - spec.margin_top - spec.margin_bottom
    x0 = spec.margin_left
    y0 = spec.margin_top
    x1 = x0 + plot_w
    y1 = y0 + plot_h

    if log_y:
        y_values = [math.log10(c) if c > 0 else 0.0 for c in counts]
        y_label = "count (log10)"
    else:
        y_values = [float(c) for c in counts]
        y_label = "count"

    y_max = max(y_values) if y_values else 0.0
    y_max = max(y_max, 1.0)

    y_ticks = nice_ticks(y_max, 6)
    x_ticks = nice_ticks(float(x_max), 7)

    bar_w = plot_w / max(1, len(counts))
    fill = "#4C78A8"
    axis = "#222222"
    grid = "#E6E6E6"
    font = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">')
    parts.append(f'<rect x="0" y="0" width="{w}" height="{h}" fill="white"/>')

    for t in y_ticks:
        y = y1 - (t / y_max) * plot_h
        parts.append(f'<line x1="{x0}" y1="{y:.2f}" x2="{x1}" y2="{y:.2f}" stroke="{grid}" stroke-width="1"/>')
        label = f"{t:.0f}" if not log_y else f"{t:.1f}"
        parts.append(
            f'<text x="{x0 - 10}" y="{y + 4:.2f}" text-anchor="end" font-family="{font}" font-size="12" fill="{axis}">{svg_escape(label)}</text>'
        )

    for t in x_ticks:
        x = x0 + (t / x_max) * plot_w
        parts.append(f'<line x1="{x:.2f}" y1="{y0}" x2="{x:.2f}" y2="{y1}" stroke="{grid}" stroke-width="1"/>')
        parts.append(
            f'<text x="{x:.2f}" y="{y1 + 20}" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{svg_escape(str(int(t)))}</text>'
        )

    parts.append(f'<line x1="{x0}" y1="{y1}" x2="{x1}" y2="{y1}" stroke="{axis}" stroke-width="1.5"/>')
    parts.append(f'<line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y1}" stroke="{axis}" stroke-width="1.5"/>')

    for i, yv in enumerate(y_values):
        bh = (yv / y_max) * plot_h
        x = x0 + i * bar_w
        y = y1 - bh
        parts.append(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{max(0.0, bar_w - 1):.2f}" height="{bh:.2f}" fill="{fill}"/>'
        )

    parts.append(
        f'<text x="{w/2:.2f}" y="28" text-anchor="middle" font-family="{font}" font-size="18" fill="{axis}">{svg_escape(title)}</text>'
    )
    parts.append(
        f'<text x="{w/2:.2f}" y="48" text-anchor="middle" font-family="{font}" font-size="12" fill="{axis}">{svg_escape(subtitle)}</text>'
    )

    parts.append(
        f'<text x="{w/2:.2f}" y="{h - 20}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}">lag_days</text>'
    )
    parts.append(
        f'<text x="18" y="{h/2:.2f}" text-anchor="middle" font-family="{font}" font-size="14" fill="{axis}" transform="rotate(-90 18 {h/2:.2f})">{svg_escape(y_label)}</text>'
    )

    parts.append("</svg>\n")
    output.write_text("\n".join(parts), encoding="utf-8")


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"input not found: {input_path}")

    if args.by_severity:
        by_sev = read_lags_by_severity_filtered(input_path, args.filter)
        by_sev = {k: v for k, v in by_sev.items() if v}
        if not by_sev:
            raise SystemExit("no lag_days values found after filtering")

        all_values: list[int] = []
        for xs in by_sev.values():
            all_values.extend(xs)
        x_max = args.max_days if args.max_days and args.max_days > 0 else max(all_values)
        x_max = max(x_max, 1)

        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        clean_output_dir_for_severity(out_dir)

        for sev in sorted(by_sev.keys()):
            values = by_sev[sev]
            counts, edges = histogram(values, args.bins, x_max)
            output_path = out_dir / f"lag_days_hist_{sev}.svg"
            title = f"lag_days histogram (severity={sev}, n={len(values)})"
            subtitle = f"bins={len(counts)}, x_max={x_max}, y_scale={'log10' if args.log_y else 'linear'}"
            write_svg(output_path, values, counts, edges, x_max, bool(args.log_y), title, subtitle)
    else:
        values = read_lags_filtered(input_path, args.filter)
        if not values:
            raise SystemExit("no lag_days values found after filtering")

        x_max = args.max_days if args.max_days and args.max_days > 0 else max(values)
        x_max = max(x_max, 1)

        counts, edges = histogram(values, args.bins, x_max)
        output_path = Path(args.output)
        title = f"lag_days histogram (n={len(values)})"
        subtitle = f"bins={len(counts)}, x_max={x_max}, y_scale={'log10' if args.log_y else 'linear'}"
        write_svg(output_path, values, counts, edges, x_max, bool(args.log_y), title, subtitle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
