#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass(frozen=True)
class SummaryRow:
    rustsec_id: str
    cve_id: str
    target_crate: str
    fixed_version: str
    fix_time: str
    downstream_fixed_cnt: int
    lag_days_min: int
    lag_days_p50: float
    lag_days_avg: float
    lag_days_max: int


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Render rustsec_rqx2_strict_summary.csv as a Markdown table."
    )
    p.add_argument(
        "--input",
        default="rustsec_rqx2_strict_summary.csv",
        help="Input CSV path (default: rustsec_rqx2_strict_summary.csv)",
    )
    p.add_argument(
        "--output",
        default="-",
        help="Output path, or '-' for stdout (default: -)",
    )
    p.add_argument(
        "--top",
        type=int,
        default=30,
        help="Number of rows to output after sorting/filtering (default: 30)",
    )
    p.add_argument(
        "--sort-by",
        default="lag_days_p50",
        choices=[
            "downstream_fixed_cnt",
            "lag_days_min",
            "lag_days_p50",
            "lag_days_avg",
            "lag_days_max",
            "fix_time",
            "rustsec_id",
            "cve_id",
            "target_crate",
        ],
        help="Sort key (default: lag_days_p50)",
    )
    p.add_argument(
        "--desc",
        action="store_true",
        help="Sort descending (default: ascending)",
    )
    p.add_argument(
        "--filter",
        default="",
        help="Regex filter applied to rustsec_id/cve_id/target_crate (optional)",
    )
    p.add_argument(
        "--columns",
        default="rustsec_id,cve_id,target_crate,fixed_version,downstream_fixed_cnt,lag_days_min,lag_days_p50,lag_days_avg,lag_days_max",
        help="Comma-separated columns to include",
    )
    return p.parse_args()


def to_int(field: str, value: str) -> int:
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"invalid int for {field}: {value!r}") from e


def to_float(field: str, value: str) -> float:
    try:
        return float(value)
    except Exception as e:
        raise ValueError(f"invalid float for {field}: {value!r}") from e


def read_summary_rows(path: Path) -> list[SummaryRow]:
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        out: list[SummaryRow] = []
        for row in r:
            out.append(
                SummaryRow(
                    rustsec_id=row["rustsec_id"],
                    cve_id=row["cve_id"],
                    target_crate=row["target_crate"],
                    fixed_version=row["fixed_version"],
                    fix_time=row["fix_time"],
                    downstream_fixed_cnt=to_int(
                        "downstream_fixed_cnt", row["downstream_fixed_cnt"]
                    ),
                    lag_days_min=to_int("lag_days_min", row["lag_days_min"]),
                    lag_days_p50=to_float("lag_days_p50", row["lag_days_p50"]),
                    lag_days_avg=to_float("lag_days_avg", row["lag_days_avg"]),
                    lag_days_max=to_int("lag_days_max", row["lag_days_max"]),
                )
            )
        return out


def filter_rows(rows: Iterable[SummaryRow], pattern: str) -> list[SummaryRow]:
    if not pattern:
        return list(rows)
    rx = re.compile(pattern)
    out = []
    for r in rows:
        hay = f"{r.rustsec_id} {r.cve_id} {r.target_crate}"
        if rx.search(hay):
            out.append(r)
    return out


def sort_key(row: SummaryRow, key: str):
    return getattr(row, key)


def format_cell(col: str, row: SummaryRow) -> str:
    v = getattr(row, col)
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def render_markdown_table(rows: list[SummaryRow], columns: list[str]) -> str:
    header = "| " + " | ".join(columns) + " |"
    sep = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = ["| " + " | ".join(format_cell(c, r) for c in columns) + " |" for r in rows]
    return "\n".join([header, sep, *body]) + "\n"


def open_output(path: str):
    if path == "-" or path == "":
        return sys.stdout
    return open(path, "w", encoding="utf-8", newline="")


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"input not found: {input_path}", file=sys.stderr)
        return 2

    rows = read_summary_rows(input_path)
    rows = filter_rows(rows, args.filter)
    rows.sort(key=lambda r: sort_key(r, args.sort_by), reverse=bool(args.desc))

    if args.top is not None and args.top >= 0:
        rows = rows[: args.top]

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    fields = set(SummaryRow.__dataclass_fields__.keys())
    unknown = [c for c in columns if c not in fields]
    if unknown:
        print(f"unknown columns: {', '.join(unknown)}", file=sys.stderr)
        return 2

    out_text = render_markdown_table(rows, columns)
    with open_output(args.output) as f:
        f.write(out_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
