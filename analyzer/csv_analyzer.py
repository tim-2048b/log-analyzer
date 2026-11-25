"""CSVAnalyzer: load any CSV log/export and normalise it for LogAnalyzer."""

from __future__ import annotations

import csv
from typing import Sequence

from .log_analyzer import LogAnalyzer
from .utils import parse_number, parse_time

# Canonical column -> header aliases (lower-case) used to auto-map CSVs
COLUMN_ALIASES = {
    "time": [
       "time",
       "time of day",
        "timestamp",
        "datetime",
        "date",
        "@timestamp",
        "date/time",
        "eventtime",
        "timecreated",
        "time_created",
        "logtime"
    ],

    "process_name": [
        "process name",
        "process_name",
        "process",
        "image",
        "app",
        "application",
        "service",
        "source",
        "provider",
        "providername"
    ],

    "pid": [
        "pid",
        "process id",
        "process_id",
        "processid"
    ],

    "operation": [
        "operation",
        "event",
        "action",
        "eventname",
        "event_name",
        "op",
        "event id",
        "eventid"
    ],

    "path": [
        "path",
        "file",
        "filename",
        "target",
        "resource",
        "url",
        "uri",
        "key"
    ],

    "result": ["result",
 "status",
 "outcome",
 "status_code",
 "statuscode",
 "response"],

    "level": ["level",
 "severity",
 "loglevel",
 "log_level",
 "levelname",
 "type"],

    "detail": [
        "detail",
        "details",
        "message",
        "msg",
        "description",
        "text"
    ],

    "duration": [
        "duration",
        "elapsed",
        "latency",
        "time_ms",
        "duration_ms",
        "response_time",
        "responsetime",
        "took"
    ],

}

class CSVAnalyzer(LogAnalyzer):
    """Load any CSV and auto-map columns to canonical names (time, process_name,
    operation, path, result, level, detail, duration). Original columns are kept,
    and mapped ones are added alongside with canonical names.

    Override auto-detection with column_map={"time": "Event Time", ...}.
    """

    def __init__(self, csv_path: str, column_map: dict[str, str] | None = None,
                 delimiter: str | None = None, encoding: str = "utf-8-sig", strip_whitespace: bool = True ):
        super().__init__()
        self.csv_path = csv_path
        self.config = {
            "strip_whitespace": strip_whitespace,
           
        }
        self.column_map: dict[str, str] = {}

        # Sniff to get the delimiter, and loading the data row according to it
        with open(csv_path, "r", newline="", encoding=encoding, errors="replace") as f:
            sample = f.read(65536)
            f.seek(0)
            if delimiter is None:
                try:
                    delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
                except csv.Error:
                    delimiter = ","
            reader = csv.DictReader(f, delimiter=delimiter)
            headers = reader.fieldnames or []
            self.column_map = self._detect_columns(headers, column_map)
            for raw in reader:
                self.rows.append(self._normalise(raw))

    @staticmethod
    def _detect_columns(headers: list[str] | Sequence[str], override: dict[str, str] | None) -> dict[str, str]:
        lowered = {h.strip().lower(): h for h in headers}
        mapping = {}
        for canon, aliases in COLUMN_ALIASES.items():
            for a in aliases:
                if a in lowered:
                    mapping[canon] = lowered[a]
                    break
        if override:
            mapping.update(override)
        return mapping

    def _normalise(self, raw: dict) -> dict:
        row = dict(raw)
        for canon, src in self.column_map.items():
            if canon not in row:
                row[canon] = raw.get(src)
        row["_ts"] = parse_time(row.get("time"))
        d = parse_number(row.get("duration"))
        if d is not None:
            row["duration"] = d
        return row

