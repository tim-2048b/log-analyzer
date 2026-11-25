"""Command-line interface for troubleshooting PML or any CSV log file."""

from __future__ import annotations

import argparse
import codecs

from .loader import load
from .pml_analyzer import PMLAnalyzer, print_rows

def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="analyze_pml", description="Troubleshoot PML or any CSV log file")
    p.add_argument("file", help=".pml or .csv file")
    p.add_argument("--csv", metavar="OUT", help="export (filtered) rows to CSV")
    p.add_argument("--process", help="filter by process name")
    p.add_argument("--search", help="grep text across all columns")
    p.add_argument("--delimiter", help="Delimiter for log file, default ',' for most of the text log file", default=",")
    p.add_argument("--report", action="store_true", help="full troubleshooting report")
    p.add_argument("--errors", action="store_true", help="list failing rows")
    p.add_argument("--slowest", type=int, metavar="N", help="N slowest events")
    p.add_argument("--columns", action="store_true", help="profile each column (great for unknown CSVs)")
    p.add_argument("--gaps", type=float, metavar="SECS", help="find stalls longer than SECS")
    p.add_argument("--compare", metavar="OTHER", help="diff against another capture")
    p.add_argument("--compare-column", default="path")
    a = p.parse_args(argv)

    # Delimiter need to be noticed if it need escape or not
    an = load(a.file, delimiter = codecs.decode(a.delimiter, "unicode_escape"))
    rows = an.rows

    if a.process:
        rows = an.filter(process_name=a.process, rows=rows)
        print(f"Found {len(rows)} rows for {a.process}")
    if a.search:
        rows = an.search(a.search, rows=rows)
        print(f"Found {len(rows)} rows matching '{a.search}'")

    acted = False
    if a.columns:
        an.print_columns()
        acted = True
    if a.report:
        an.report()
        acted = True
    if a.errors:
        print_rows(an.errors(rows), 50)
        acted = True
    if a.slowest:
        for r in an.slowest(a.slowest, rows):
            print(f"{r['duration']:.4f}s | {r.get('process_name')} | {r.get('operation')} | {str(r.get('path'))[:70]}")
        acted = True
    if a.gaps:
        for g in an.find_gaps(a.gaps, rows)[:20]:
            print(g)
        acted = True
    if a.compare:
        other = load(a.compare)
        for k, v in an.compare(other, a.compare_column).items():
            print(f"\n{k}:\n  {v}")
        acted = True
    if a.csv:
        an.export_to_csv(a.csv, rows)
        acted = True
    if not acted:
        if isinstance(an, PMLAnalyzer):
            an.print_summary()
        else:
            an.report()
