"""
LogAnalyzer: the generic troubleshooting methods.

Operates on `self.rows`, a list of plain dicts with canonical keys
(time, _ts, process_name, pid, operation, path, result, result_code, level,
detail, duration). 
Subclasses (CSVAnalyzer, PMLAnalyzer) only differ in how they
fill `self.rows`; every method here is source-agnostic.
Source adapters are responsible for populating that schema.
"""

from __future__ import annotations

import csv
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from .utils import parse_number, parse_time

# Statuses that are normal noise in Procmon traces (not real problems)
BENIGN_STATUSES = {
    0, 259, 0x80000005, 0x80000006, 0x8000001A, 0xC0000011, 0xC0000275,
    0xC0000035,
}

SUCCESS_WORDS = {
    "success", 
    "ok", 
    "0", 
    "pass", 
    "passed", 
    "true", 
    "200", 
    "info",
    "information", 
    "debug", 
    "trace", 
    "notice", 
    ""
}
ERROR_WORDS = {"error", "err", "fatal", "critical", "crit", "fail", "failed",
               "failure", "exception", "severe", "alert", "emerg", "false"}
WARN_WORDS = {
    "warn", 
    "warning"
}

class LogAnalyzer:
    """Troubleshooting methods for any tabular log. Subclasses fill self.rows."""

    def __init__(self, rows: list[dict] | None = None):
        """Initialize an analyzer from optional normalized rows."""
        self.rows: list[dict] = rows or []
        self.common_alias = True # Default open coomon alias detection for column name - `Time Created` for `Timestamp` field for example
    
    # ---- basic access -----------------------------------------------------

    def __len__(self) -> int:
        """Return the number of loaded rows."""
        return len(self.rows)

    @property
    def columns(self) -> list[str]:
        """Return column names in first-seen order from the first 500 rows."""
        seen: dict[str, None] = {}
        for r in self.rows[:500]:
            for k in r:
                seen.setdefault(k)
        return list(seen)

    def to_dataframe(self):
        """Convert all rows to a pandas ``DataFrame``.

        Returns:
            A new ``pandas.DataFrame`` containing every row and discovered key.

        """
        import pandas as pd
        return pd.DataFrame(self.rows)

    def _rows(self, rows=None):
        """Return caller-supplied rows or the analyzer's complete row list."""
        return self.rows if rows is None else rows

    # ---- failure classification ------------------------------------------

    @staticmethod
    def is_failure(row: dict) -> bool:
        """Classify a row as a failure from status code, result, or level."""
        code = row.get("result_code")
        if isinstance(code, int):
            return code not in BENIGN_STATUSES
        res = str(row.get("result", "")).strip().lower()
        lvl = str(row.get("level", "")).strip().lower()
        if lvl in ERROR_WORDS:
            return True
        if res:
            if res in ERROR_WORDS:
                return True
            if res.isdigit():
                n = int(res)
                return n >= 400 if n >= 100 else False   # HTTP-ish codes
            return res not in SUCCESS_WORDS and not _looks_benign(res)
        return False

    @staticmethod
    def is_warning(row: dict) -> bool:
        return str(row.get("level", "")).strip().lower() in WARN_WORDS

    # ---- filtering / searching -------------------------------------------

    def filter(self, predicate: Callable[[dict], bool] | None = None, rows=None, **equals):
        """Filter rows using a predicate and case-insensitive field matches.

        Args:
            predicate: Optional callable that receives a row and returns truthy
                when the row should be retained.
            rows: Optional input collection; defaults to ``self.rows``.
            **equals: Canonical or source column names mapped to substring
                values. Despite the name, matching is case-insensitive and
                substring-based rather than exact.

        Returns:
            A new list containing rows that satisfy every supplied condition.
        """
        out = self._rows(rows)
        if predicate:
            out = [r for r in out if predicate(r)]
        for col, needle in equals.items():
            n = str(needle).lower()
            out = [r for r in out if n in str(r.get(col, "")).lower()]
        return out

    def search(self, text: str, columns: list[str] | None = None,
               regex: bool = False, rows=None):
        """Search text across all or selected columns.

        Args:
            text: Literal substring or regular expression.
            columns: Optional allow-list of columns to inspect.
            regex: Compile ``text`` as a case-insensitive regular expression.
            rows: Optional input collection; defaults to all rows.

        Returns:
            Matching rows, with each row included at most once.

        Raises:
            re.error: If ``regex`` is true and the pattern is invalid.
        """
        pat = re.compile(text, re.I) if regex else None
        needle = text.lower()
        out = []
        for r in self._rows(rows):
            for k, v in r.items():
                if columns and k not in columns:
                    continue
                s = str(v)
                if (pat.search(s) if pat else needle in s.lower()):
                    out.append(r)
                    break
        return out

    def context(self, index: int, before: int = 5, after: int = 5):
        """Rows surrounding a given index (what happened right before the failure?)."""
        return self.rows[max(0, index - before): index + after + 1]

    # ---- counting / profiling --------------------------------------------

    def top_n(self, column: str, n: int = 10, rows=None):
        """Most common values of a column."""
        return Counter(str(r.get(column, "")) for r in self._rows(rows)).most_common(n)

    def count_by(self, *columns: str, rows=None, n: int | None = None):
        """Count rows grouped by one or more columns."""
        c = Counter(tuple(str(r.get(col, "")) for col in columns) for r in self._rows(rows))
        return c.most_common(n)

    def column_profile(self, rows=None) -> dict:
        """Per-column profile: fill rate, unique count, numeric stats, top values.
        First thing to run on an unfamiliar CSV."""
        rows = self._rows(rows)
        profile = {}
        for col in self.columns:
            if col.startswith("_"):
                continue
            vals = [r.get(col) for r in rows]
            non_null = [v for v in vals if v not in (None, "")]
            nums = [x for x in (parse_number(v) for v in non_null) if x is not None]
            entry = {
                "non_empty": len(non_null),
                "empty": len(vals) - len(non_null),
                "unique": len(set(map(str, non_null))),
                "top": Counter(map(str, non_null)).most_common(3),
            }
            if non_null and len(nums) >= 0.9 * len(non_null):
                entry.update(type="numeric", min=min(nums), max=max(nums),
                             mean=round(statistics.fmean(nums), 4),
                             median=statistics.median(nums))
            elif non_null and sum(parse_time(v) is not None for v in non_null[:50]) >= 0.9 * min(50, len(non_null)):
                entry["type"] = "datetime"
            else:
                entry["type"] = "text"
            profile[col] = entry
        return profile

    def find_duplicates(self, columns: list[str], min_count: int = 2, rows=None):
        """Rows sharing the same values in the given columns (repeated identical events)."""
        c = Counter(tuple(str(r.get(col, "")) for col in columns) for r in self._rows(rows))
        return [(k, v) for k, v in c.most_common() if v >= min_count]

    def numeric_outliers(self, column: str, sigma: float = 3.0, rows=None):
        """Return Rows whose numeric value is > `sigma` std-devs from the mean (spikes)."""
        rows = self._rows(rows)
        pairs = [(r, parse_number(r.get(column))) for r in rows]
        pairs = [(r, v) for r, v in pairs if v is not None]
        if len(pairs) < 3:
            return []
        vals = [v for _, v in pairs]
        mean, sd = statistics.fmean(vals), statistics.pstdev(vals)
        if sd == 0:
            return []
        return sorted(((r, v) for r, v in pairs if abs(v - mean) / sd > sigma),
                      key=lambda x: -abs(x[1] - mean))

    # ---- failures --------------------------------------------------------

    def errors(self, rows=None):
        """All failing rows (non-benign NTSTATUS, error levels/results)."""
        return [r for r in self._rows(rows) if self.is_failure(r)]

    def warnings(self, rows=None):
        return [r for r in self._rows(rows) if self.is_warning(r)]

    def error_summary(self, n: int = 10, rows=None) -> dict:
        """Where do failures concentrate? By result, process, operation and path."""
        errs = self.errors(rows)
        return {
            "total_errors": len(errs),
            "error_rate_pct": round(100 * len(errs) / max(1, len(self._rows(rows))), 2),
            "by_result": self.top_n("result", n, errs),
            "by_process": self.top_n("process_name", n, errs),
            "by_operation": self.top_n("operation", n, errs),
            "by_path": self.top_n("path", n, errs),
        }

    def access_denied(self, rows=None):
        """Permission problems (ACCESS DENIED / 403 / 'denied' / 'unauthorized')."""
        pat = re.compile(r"access.?denied|permission|unauthori[sz]ed|forbidden|\b403\b|\b401\b", re.I)
        return [r for r in self._rows(rows)
                if pat.search(str(r.get("result", "")) + " " + str(r.get("detail", "")))]

    def not_found(self, rows=None):
        """Missing file/key/resource (NAME NOT FOUND, PATH NOT FOUND, 404, 'not found')."""
        pat = re.compile(r"not.?found|no such|does not exist|\b404\b", re.I)
        return [r for r in self._rows(rows)
                if pat.search(str(r.get("result", "")) + " " + str(r.get("detail", "")))]

    def sharing_violations(self, rows=None):
        """File lock / sharing conflicts (AV scans, backup agents, stuck handles)."""
        pat = re.compile(r"sharing.?violation|locked|in use|lock.?conflict|busy", re.I)
        return [r for r in self._rows(rows)
                if pat.search(str(r.get("result", "")) + " " + str(r.get("detail", "")))]

    def repeated_failures(self, min_count: int = 20, rows=None):
        """Retry storms: same process+operation+path+result failing over and over.
        Classic cause of slowness / high CPU."""
        errs = self.errors(rows)
        c = Counter((r.get("process_name"), r.get("operation"), r.get("path"), r.get("result"))
                    for r in errs)
        return [(k, v) for k, v in c.most_common() if v >= min_count]

    def error_keywords(self, rows=None, n: int = 15):
        """Most common error words in detail/message text - quick root-cause hints."""
        words = Counter()
        pat = re.compile(r"[A-Za-z_]{4,}")
        for r in self.errors(rows):
            words.update(w.lower() for w in pat.findall(str(r.get("detail", ""))))
        return words.most_common(n)

    # ---- performance -----------------------------------------------------

    def slowest(self, n: int = 20, rows=None):
        """Slowest events by duration (seconds)."""
        rows = [r for r in self._rows(rows) if isinstance(r.get("duration"), (int, float))]
        return sorted(rows, key=lambda r: r["duration"], reverse=True)[:n]

    def duration_by(self, column: str = "process_name", n: int = 10, rows=None):
        """Total / average / max duration grouped by a column - who is eating time?"""
        agg = defaultdict(list)
        for r in self._rows(rows):
            d = r.get("duration")
            if isinstance(d, (int, float)):
                agg[str(r.get(column, ""))].append(d)
        out = [{column: k, "count": len(v), "total_s": round(sum(v), 6),
                "avg_s": round(sum(v) / len(v), 6), "max_s": round(max(v), 6)}
               for k, v in agg.items()]
        return sorted(out, key=lambda x: -x["total_s"])[:n]

    def hot_paths(self, n: int = 10, rows=None):
        """Most frequently touched paths/targets (thrashing, polling loops)."""
        return self.top_n("path", n, rows)

    def process_activity(self, n: int = 15, rows=None):
        """Per-process event count, error count, error %, and total time."""
        stats = defaultdict(lambda: {"events": 0, "errors": 0, "duration_s": 0.0})
        for r in self._rows(rows):
            s = stats[str(r.get("process_name", ""))]
            s["events"] += 1
            s["errors"] += self.is_failure(r)
            if isinstance(r.get("duration"), (int, float)):
                s["duration_s"] += r["duration"]
        out = [{"process_name": k, **v, "error_pct": round(100 * v["errors"] / v["events"], 1),
                "duration_s": round(v["duration_s"], 6)} for k, v in stats.items()]
        return sorted(out, key=lambda x: -x["events"])[:n]

    # ---- time based ------------------------------------------------------

    def time_range(self, rows=None):
        """(first, last, span) timestamps of the data."""
        ts = [r["_ts"] for r in self._rows(rows) if r.get("_ts")]
        if not ts:
            return None
        return min(ts), max(ts), max(ts) - min(ts)

    def timeline(self, bucket_seconds: int = 60, rows=None) -> list[tuple[datetime, int]]:
        """Event counts per time bucket."""
        buckets = Counter()
        for r in self._rows(rows):
            ts = r.get("_ts")
            if ts:
                epoch = ts.replace(tzinfo=None).timestamp()
                buckets[int(epoch // bucket_seconds) * bucket_seconds] += 1
        return [(datetime.fromtimestamp(k), v) for k, v in sorted(buckets.items())]

    def find_bursts(self, bucket_seconds: int = 1, sigma: float = 3.0, rows=None):
        """Time buckets with abnormally high activity (spikes worth investigating)."""
        tl = self.timeline(bucket_seconds, rows)
        if len(tl) < 3:
            return []
        counts = [c for _, c in tl]
        mean, sd = statistics.fmean(counts), statistics.pstdev(counts)
        thr = mean + sigma * sd
        return [(t, c) for t, c in tl if c > thr and sd > 0]

    def find_gaps(self, min_gap_seconds: float = 5.0, rows=None):
        """Find long time gaps between consecutive log events.

        Events with timestamps are ordered chronologically and the elapsed
        time between each pair of consecutive events is calculated. Gaps
        greater than or equal to ``min_gap_seconds`` are returned from
        longest to shortest.

        Args:
            min_gap_seconds:
                Minimum elapsed time, in seconds, required for a gap to be
                included.
            rows:
                Optional collection of log rows to analyze. If omitted,
                ``self.rows`` is used.

        Returns:
            A list of dictionaries describing each detected gap. Each item
            contains the start and end timestamps, gap duration in seconds,
            and the process names before and after the gap.
        """
        rows = [r for r in self._rows(rows) if r.get("_ts")]
        rows.sort(key=lambda r: r["_ts"])
        gaps = []
        for a, b in zip(rows, rows[1:]):
            delta = (b["_ts"] - a["_ts"]).total_seconds()
            if delta >= min_gap_seconds:
                gaps.append({"from": a["_ts"], "to": b["_ts"], "gap_s": round(delta, 3),
                             "before": a.get("process_name"), "after": b.get("process_name")})
        return sorted(gaps, key=lambda g: -g["gap_s"])

    def first_error(self, rows=None):
        """Earliest failing row - often closest to the root cause."""
        errs = [r for r in self.errors(rows) if r.get("_ts")]
        return min(errs, key=lambda r: r["_ts"]) if errs else (self.errors(rows) or [None])[0]

    def events_around(self, ts: datetime, seconds: float = 2.0, rows=None):
        """Everything within +/- N seconds of a timestamp."""
        d = timedelta(seconds=seconds)
        return [r for r in self._rows(rows) if r.get("_ts") and abs(r["_ts"] - ts) <= d]

    # ---- comparison ------------------------------------------------------

    def compare(self, other: "LogAnalyzer", column: str = "path", n: int = 20):
        """Diff two captures (good vs bad, before vs after): values new in / gone from
        the other capture, and the biggest count changes."""
        a = Counter(str(r.get(column, "")) for r in self.rows)
        b = Counter(str(r.get(column, "")) for r in other.rows)
        return {
            "only_in_self": [(k, a[k]) for k in sorted(set(a) - set(b), key=lambda k: -a[k])[:n]],
            "only_in_other": [(k, b[k]) for k in sorted(set(b) - set(a), key=lambda k: -b[k])[:n]],
            "biggest_changes": sorted(((k, a[k], b[k], b[k] - a[k]) for k in set(a) & set(b)),
                                      key=lambda x: -abs(x[3]))[:n],
            "error_rate_self_pct": round(100 * len(self.errors()) / max(1, len(self.rows)), 2),
            "error_rate_other_pct": round(100 * len(other.errors()) / max(1, len(other.rows)), 2),
        }

    # ---- export ----------------------------------------------------------

    def export_to_csv(self, output_path: str, rows=None, columns: list[str] | None = None):
        """Export rows (default: all) to CSV. Internal '_' fields are skipped."""
        rows = self._rows(rows)
        if not rows:
            print("No rows to export")
            return
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        columns = columns or [c for c in self.columns if not c.startswith("_")]
        try:
            with open(out, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(columns)
                for r in rows:
                    w.writerow([r.get(c, "") if r.get(c) is not None else "" for c in columns])
            print(f"Exported {len(rows)} rows to {output_path}")
        except Exception as e:
            print(f"Error exporting to CSV: {e}")

    # ---- reporting -------------------------------------------------------

    def report(self, n: int = 10):
        """One-shot troubleshooting report: run this first."""
        rows = self.rows
        line = "=" * 70
        print(line)
        print("TROUBLESHOOTING REPORT")
        print(line)
        print(f"Rows: {len(rows)}   Columns: {', '.join(c for c in self.columns if not c.startswith('_'))}")
        tr = self.time_range()
        if tr:
            print(f"Time range: {tr[0]} -> {tr[1]}  (span {tr[2]})")

        es = self.error_summary(n)
        print(f"\n[Errors] {es['total_errors']} ({es['error_rate_pct']}%)")

        # Loop over predefined (section, section-function) tuple list. Produce report per ``section`` with ``section-function`` 
        for label, key in (
            ("result", "by_result"), 
            ("process", "by_process"),
            ("operation", "by_operation"), 
            ("path", "by_path")
        ):
            if es[key] and any(k for k, _ in es[key]):
                print(f"  Top by {label}:")
                for k, v in es[key][:5]:
                    print(f"    {v:>7}  {k[:90]}")

        for title, fn in (("Access denied", self.access_denied),
                          ("Not found", self.not_found),
                          ("Sharing violations / locks", self.sharing_violations)):
            hits = fn()
            if hits:
                print(f"\n[{title}] {len(hits)} events; top paths:")
                for k, v in self.top_n("path", 5, hits):
                    print(f"    {v:>7}  {k[:90]}")

        storms = self.repeated_failures()
        if storms:
            print("\n[Retry storms] same failing call repeated:")
            for (proc, op, path, res), cnt in storms[:5]:
                print(f"    {cnt:>7}x {proc} {op} {str(path)[:60]} -> {res}")

        slow = self.slowest(5)
        if slow:
            print("\n[Slowest events]")
            for r in slow:
                print(f"    {r['duration']:.4f}s  {r.get('process_name')}  {r.get('operation')}  {str(r.get('path'))[:60]}")

        bursts = self.find_bursts()
        if bursts:
            print("\n[Activity bursts] (1s buckets)")
            for t, c in sorted(bursts, key=lambda x: -x[1])[:5]:
                print(f"    {t}  {c} events")

        gaps = self.find_gaps()
        if gaps:
            print("\n[Gaps / possible stalls]")
            for g in gaps[:5]:
                print(f"    {g['gap_s']}s between {g['from']} and {g['to']}")

        fe = self.first_error()
        if fe:
            print(f"\n[First error] {fe.get('_ts') or ''} {fe.get('process_name')} "
                  f"{fe.get('operation')} {str(fe.get('path'))[:70]} -> {fe.get('result')}")
        print(line)

    def print_columns(self):
        """Pretty-print the column profile."""
        for col, p in self.column_profile().items():
            extra = f" min={p['min']} max={p['max']} mean={p['mean']}" if p["type"] == "numeric" else ""
            print(f"{col:<25} {p['type']:<9} filled={p['non_empty']:<8} unique={p['unique']:<8}{extra}")
            print(f"{'':<25} top: {p['top']}")


def _looks_benign(res: str) -> bool:
    return res in {"buffer overflow", "no more files", "no more entries", "end of file",
                   "pending", "reparse", "name collision", "not a reparse point"}
