"""
CloudShield IQ — Dataset Profiler
==================================
Profiles a CSV dataset and produces:
  1. A machine-readable JSON profile  → datasets/profiles/<name>_profile.json
  2. A human-readable Markdown report → datasets/profiles/<name>_profile.md

Usage:
    python ml/scripts/profile_dataset.py datasets/synthetic/cloud_security_events.csv
    python ml/scripts/profile_dataset.py path/to/any.csv --output-dir datasets/profiles

The profiler computes:
  - Dataset shape and memory usage
  - Per-column: dtype, null count/%, unique count, top values
  - Numeric columns: min, max, mean, median, std, 25th/75th percentile
  - Categorical columns: value_counts (top 15)
  - Class balance for columns named *label*, *anomaly*, *target*, *class*
  - Timestamp columns: date range, hourly distribution sketch

Design note:
    This script uses only pandas and numpy (already in pyproject.toml).
    No additional profiling libraries (ydata-profiling etc.) are required,
    keeping the dependency surface minimal and the script self-contained.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Profiling logic
# ---------------------------------------------------------------------------


def _profile_numeric(series: pd.Series) -> dict[str, Any]:
    clean = series.dropna()
    if clean.empty:
        return {"min": None, "max": None, "mean": None, "median": None,
                "std": None, "p25": None, "p75": None}
    described = clean.describe(percentiles=[0.25, 0.5, 0.75])
    d = described.to_dict()
    return {
        "min": round(float(d.get("min", float("nan"))), 4),
        "max": round(float(d.get("max", float("nan"))), 4),
        "mean": round(float(d.get("mean", float("nan"))), 4),
        "median": round(float(d.get("50%", float("nan"))), 4),
        "std": round(float(d.get("std", float("nan"))), 4),
        "p25": round(float(d.get("25%", float("nan"))), 4),
        "p75": round(float(d.get("75%", float("nan"))), 4),
    }


def _profile_categorical(series: pd.Series, top_n: int = 15) -> dict[str, Any]:
    vc = series.value_counts(dropna=False)
    total = len(series)
    top = {
        str(k): {"count": int(v), "pct": round(v / total * 100, 2)}
        for k, v in vc.head(top_n).items()
    }
    return {"top_values": top}


def _profile_timestamp(series: pd.Series) -> dict[str, Any]:
    try:
        parsed = pd.to_datetime(series, utc=True, errors="coerce")
        valid = parsed.dropna()
        if valid.empty:
            return {"parseable": False}
        return {
            "parseable": True,
            "min": str(valid.min()),
            "max": str(valid.max()),
            "range_days": (valid.max() - valid.min()).days,
            "null_count": int(parsed.isna().sum()),
        }
    except Exception as exc:
        return {"parseable": False, "error": str(exc)}


def _is_timestamp_col(col: str, series: pd.Series) -> bool:
    col_lower = col.lower()
    if any(kw in col_lower for kw in ("time", "date", "ts", "created", "updated")):
        sample = series.dropna().head(5)
        try:
            pd.to_datetime(sample, utc=True, errors="raise")
            return True
        except Exception:
            return False
    return False


def profile_dataframe(df: pd.DataFrame, dataset_name: str) -> dict[str, Any]:
    """
    Compute a full profile of a DataFrame.

    Returns a dict that is JSON-serialisable.
    """
    n_rows, n_cols = df.shape
    mem_mb = round(df.memory_usage(deep=True).sum() / 1024 / 1024, 3)
    null_total = int(df.isna().sum().sum())
    null_pct = round(null_total / (n_rows * n_cols) * 100, 2)
    duplicate_rows = int(df.duplicated().sum())

    columns: dict[str, Any] = {}
    label_columns: list[str] = []

    for col in df.columns:
        series = df[col]
        col_null_count = int(series.isna().sum())
        col_null_pct = round(col_null_count / n_rows * 100, 2)
        col_unique = int(series.nunique(dropna=True))

        col_profile: dict[str, Any] = {
            "dtype": str(series.dtype),
            "null_count": col_null_count,
            "null_pct": col_null_pct,
            "unique_count": col_unique,
        }

        # Detect label-like columns for class balance section
        col_lower = col.lower()
        if any(kw in col_lower for kw in ("label", "anomaly", "target", "class", "attack")):
            label_columns.append(col)

        if _is_timestamp_col(col, series):
            col_profile["kind"] = "timestamp"
            col_profile["timestamp_stats"] = _profile_timestamp(series)

        elif pd.api.types.is_numeric_dtype(series):
            col_profile["kind"] = "numeric"
            col_profile["numeric_stats"] = _profile_numeric(series)

            # If low cardinality numeric (≤20 unique), also show value counts
            if col_unique <= 20:
                col_profile["categorical_stats"] = _profile_categorical(series)

        elif pd.api.types.is_bool_dtype(series):
            col_profile["kind"] = "boolean"
            vc = series.value_counts(dropna=False)
            col_profile["value_counts"] = {str(k): int(v) for k, v in vc.items()}

        else:
            col_profile["kind"] = "categorical"
            col_profile["categorical_stats"] = _profile_categorical(series)

        columns[col] = col_profile

    # Class balance summary for label columns
    class_balance: dict[str, Any] = {}
    for lc in label_columns:
        vc = df[lc].value_counts(dropna=False)
        class_balance[lc] = {
            str(k): {"count": int(v), "pct": round(v / n_rows * 100, 2)}
            for k, v in vc.items()
        }

    return {
        "dataset_name": dataset_name,
        "profiled_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "shape": {"rows": n_rows, "columns": n_cols},
        "memory_mb": mem_mb,
        "null_summary": {
            "total_nulls": null_total,
            "null_pct": null_pct,
        },
        "duplicate_rows": duplicate_rows,
        "columns": columns,
        "class_balance": class_balance,
    }


# ---------------------------------------------------------------------------
# Markdown report renderer
# ---------------------------------------------------------------------------


def _render_markdown(profile: dict[str, Any]) -> str:
    lines: list[str] = []
    name = profile["dataset_name"]
    shape = profile["shape"]
    ts = profile["profiled_at"]

    lines += [
        f"# Dataset Profile — {name}",
        "",
        f"**Profiled at:** {ts}  ",
        f"**Shape:** {shape['rows']:,} rows × {shape['columns']} columns  ",
        f"**Memory:** {profile['memory_mb']} MB  ",
        f"**Total nulls:** {profile['null_summary']['total_nulls']:,} ({profile['null_summary']['null_pct']}%)  ",
        f"**Duplicate rows:** {profile['duplicate_rows']:,}  ",
        "",
        "---",
        "",
        "## Column Summary",
        "",
        "| Column | Kind | Dtype | Nulls | Nulls % | Unique |",
        "|---|---|---|---|---|---|",
    ]

    for col, cp in profile["columns"].items():
        lines.append(
            f"| `{col}` | {cp['kind']} | {cp['dtype']} | {cp['null_count']} "
            f"| {cp['null_pct']}% | {cp['unique_count']} |"
        )

    lines += ["", "---", "", "## Per-Column Details", ""]

    for col, cp in profile["columns"].items():
        lines += [f"### `{col}`", ""]
        lines.append(f"- **Kind:** {cp['kind']}")
        lines.append(f"- **Dtype:** `{cp['dtype']}`")
        lines.append(f"- **Null count:** {cp['null_count']} ({cp['null_pct']}%)")
        lines.append(f"- **Unique values:** {cp['unique_count']}")
        lines.append("")

        kind = cp["kind"]

        if kind == "numeric" and "numeric_stats" in cp:
            ns = cp["numeric_stats"]
            lines += [
                "**Numeric statistics:**",
                "",
                f"| Stat | Value |",
                f"|---|---|",
                f"| Min | {ns['min']} |",
                f"| Max | {ns['max']} |",
                f"| Mean | {ns['mean']} |",
                f"| Median | {ns['median']} |",
                f"| Std Dev | {ns['std']} |",
                f"| 25th pct | {ns['p25']} |",
                f"| 75th pct | {ns['p75']} |",
                "",
            ]

        if kind == "timestamp" and "timestamp_stats" in cp:
            ts_stat = cp["timestamp_stats"]
            if ts_stat.get("parseable"):
                lines += [
                    "**Timestamp statistics:**",
                    "",
                    f"| Stat | Value |",
                    f"|---|---|",
                    f"| Min | {ts_stat['min']} |",
                    f"| Max | {ts_stat['max']} |",
                    f"| Range (days) | {ts_stat['range_days']} |",
                    "",
                ]

        if "categorical_stats" in cp:
            cs = cp["categorical_stats"]
            lines += [
                "**Top values:**",
                "",
                "| Value | Count | % |",
                "|---|---|---|",
            ]
            for val, info in cs["top_values"].items():
                lines.append(f"| `{val}` | {info['count']} | {info['pct']}% |")
            lines.append("")

        if kind == "boolean" and "value_counts" in cp:
            lines += [
                "**Value counts:**",
                "",
                "| Value | Count |",
                "|---|---|",
            ]
            for val, cnt in cp["value_counts"].items():
                lines.append(f"| `{val}` | {cnt} |")
            lines.append("")

    # Class balance
    if profile["class_balance"]:
        lines += ["---", "", "## Class Balance", ""]
        for lc, balance in profile["class_balance"].items():
            lines += [f"### `{lc}`", "", "| Class | Count | % |", "|---|---|---|"]
            for cls_val, info in balance.items():
                lines.append(f"| `{cls_val}` | {info['count']} | {info['pct']}% |")
            lines.append("")

            # Imbalance warning
            pcts = [info["pct"] for info in balance.values()]
            if pcts and min(pcts) < 10.0:
                lines += [
                    "> [!WARNING]",
                    f"> Significant class imbalance detected in `{lc}`. "
                    "Minority class < 10%. Consider SMOTE, cost-sensitive learning, "
                    "or stratified sampling for ML training.",
                    "",
                ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile a CSV dataset and write JSON + Markdown reports."
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to the CSV file to profile.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for output files. Defaults to datasets/profiles/",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Dataset name override. Defaults to the CSV filename stem.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    input_csv = args.input_csv.resolve()

    if not input_csv.exists():
        print(f"ERROR: File not found: {input_csv}", file=sys.stderr)
        sys.exit(1)

    dataset_name = args.name or input_csv.stem

    # Resolve output directory relative to project root
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent

    if args.output_dir is None:
        output_dir = project_root / "datasets" / "profiles"
    else:
        output_dir = args.output_dir.resolve()

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading {input_csv.name}...")
    df = pd.read_csv(input_csv, low_memory=False)
    print(f"Loaded: {df.shape[0]:,} rows × {df.shape[1]} columns")

    print("Profiling...")
    profile = profile_dataframe(df, dataset_name)

    # Write JSON profile
    json_path = output_dir / f"{dataset_name}_profile.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)
    print(f"JSON profile   -> {json_path}")

    # Write Markdown profile
    md_path = output_dir / f"{dataset_name}_profile.md"
    md_content = _render_markdown(profile)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"Markdown report -> {md_path}")

    # Summary to stdout
    print("\n" + "=" * 60)
    print(f"PROFILE SUMMARY: {dataset_name}")
    print("=" * 60)
    print(f"Rows        : {profile['shape']['rows']:,}")
    print(f"Columns     : {profile['shape']['columns']}")
    print(f"Memory      : {profile['memory_mb']} MB")
    print(f"Total nulls : {profile['null_summary']['total_nulls']:,} ({profile['null_summary']['null_pct']}%)")
    print(f"Duplicates  : {profile['duplicate_rows']:,}")
    if profile["class_balance"]:
        print("\nClass balance:")
        for lc, bal in profile["class_balance"].items():
            dist = ", ".join(f"{k}={v['pct']}%" for k, v in bal.items())
            print(f"  {lc}: {dist}")
    print("=" * 60)


if __name__ == "__main__":
    main()
