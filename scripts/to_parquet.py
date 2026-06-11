#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
to_parquet.py — Optional: convert the JSONL/CSV dataset configs to Parquet.

HuggingFace serves datasets most efficiently as Parquet. The dataset ships as
JSONL/CSV (human-readable, diff-friendly, git-friendly); run this to additionally
materialize Parquet copies next to each source file.

    python scripts/to_parquet.py --dataset dataset

Requires: pandas, pyarrow.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset")
    args = ap.parse_args()

    try:
        import pandas as pd
    except ImportError:
        sys.exit("pandas + pyarrow required: pip install pandas pyarrow")

    jsonl = glob.glob(os.path.join(args.dataset, "**", "*.jsonl"), recursive=True)
    csvs = glob.glob(os.path.join(args.dataset, "**", "*.csv"), recursive=True)
    if not jsonl and not csvs:
        sys.exit(f"no .jsonl/.csv found under {args.dataset}")

    for path in jsonl:
        df = pd.read_json(path, lines=True)
        out = path[:-len(".jsonl")] + ".parquet"
        df.to_parquet(out, index=False)
        print(f"  {len(df):>6} rows -> {os.path.relpath(out)}")
    for path in csvs:
        df = pd.read_csv(path)
        out = path[:-len(".csv")] + ".parquet"
        df.to_parquet(out, index=False)
        print(f"  {len(df):>6} rows -> {os.path.relpath(out)}")
    print("done.")


if __name__ == "__main__":
    main()
