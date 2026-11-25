"""
PMLAnalyzer: Process Monitor (.pml) events normalised for LogAnalyzer.

`procmon_parser` is imported lazily inside __init__ so that importing this
module (or analyze_pml.py) never requires procmon-parser unless a .pml file is
actually opened. CSV-only users therefore don't need it installed.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta

from .log_analyzer import LogAnalyzer
from .utils import parse_time

# Common NTSTATUS codes seen in Procmon (decimal -> name)
NTSTATUS_NAMES = {
    0: "SUCCESS",
    259: "PENDING",
    0x80000005: "BUFFER OVERFLOW",
    0x80000006: "NO MORE FILES",
    0x8000001A: "NO MORE ENTRIES",
    0xC000000D: "INVALID PARAMETER",
    0xC0000011: "END OF FILE",
    0xC0000022: "ACCESS DENIED",
    0xC0000033: "OBJECT NAME INVALID",
    0xC0000034: "NAME NOT FOUND",
    0xC0000035: "NAME COLLISION",
    0xC000003A: "PATH NOT FOUND",
    0xC0000043: "SHARING VIOLATION",
    0xC00000BA: "FILE IS A DIRECTORY",
    0xC00000BE: "BAD NETWORK PATH",
    0xC0000120: "CANCELLED",
    0xC0000275: "NOT A REPARSE POINT",
}

def _name(value) -> str:
    """Readable name for enums / ints / strings."""
    if value is None:
        return ""
    n = getattr(value, "name", None)
    return str(n) if n else str(value)


def status_name(code) -> str:
    """Map an NTSTATUS int to a readable name, else hex."""
    if isinstance(code, int):
        return NTSTATUS_NAMES.get(code, f"0x{code:08X}")
    return str(code)


class PMLAnalyzer(LogAnalyzer):
    """Analyze Process Monitor events from PML files.

    self.events -> raw procmon-parser events (unchanged)
    self.rows   -> normalised dicts, used by all the troubleshooting methods
    """

    FILE_OPS = {"CreateFile", "ReadFile", "WriteFile", "DeleteFile", "QueryOpen",
                "SetFileInformation", "CloseFile", "QueryDirectory", "CreateFileMapping"}

    def __init__(self, pml_path: str):
        super().__init__()
        from procmon_parser import ProcmonLogsReader  # imported lazily: CSV use needs no procmon

        self.pml_path = pml_path
        self.events = []
        with open(pml_path, "rb") as f:
            reader = ProcmonLogsReader(f)
            for _ in range(len(reader)):
                self.events.append(next(reader))
        self.rows = [self._to_row(e) for e in self.events]

    # ---- normalisation ----------------------------------------------------

    @staticmethod
    def _op_name(e) -> str:
        op = e.operation
        n = getattr(op, "name", None)
        if n:
            return str(n)
        if isinstance(op, str) and not op.isdigit():
            return op
        # Numeric operation: try procmon-parser's enums for this event class
        try:
            from procmon_parser import consts
            cls_name = _name(getattr(e, "event_class", "")).lower()
            for enum_name in ("FilesystemOperation", "RegistryOperation", "ProcessOperation",
                              "NetworkOperation", "ProfilingOperation"):
                enum = getattr(consts, enum_name, None)
                if enum and cls_name.startswith(enum_name[:4].lower().replace("file", "file")):
                    return enum(int(op)).name
            for enum_name in ("FilesystemOperation", "RegistryOperation", "ProcessOperation",
                              "NetworkOperation", "ProfilingOperation"):
                enum = getattr(consts, enum_name, None)
                try:
                    if enum:
                        return enum(int(op)).name
                except Exception:
                    continue
        except Exception:
            pass
        return str(op)

    @staticmethod
    def _event_time(e):
        t = getattr(e, "time", None) or getattr(e, "date", None)
        if isinstance(t, datetime):
            return t
        ft = getattr(e, "date_filetime", None)
        if isinstance(ft, int) and ft > 0:
            return datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
        return parse_time(t)

    def _to_row(self, e) -> dict:
        proc = getattr(e, "process", None)
        code = e.result if isinstance(e.result, int) else None
        dur = getattr(e, "duration", None)
        details = getattr(e, "details", None) or getattr(e, "detail", None)
        ts = self._event_time(e)
        return {
            "time": ts.isoformat() if ts else "",
            "_ts": ts,
            "process_name": getattr(proc, "process_name", ""),
            "pid": getattr(proc, "pid", ""),
            "tid": getattr(e, "tid", ""),
            "operation": self._op_name(e),
            "event_class": _name(getattr(e, "event_class", "")),
            "path": getattr(e, "path", "") or "",
            "result_code": code,
            "result": status_name(code) if code is not None else _name(e.result),
            "duration": (dur / 1e7) if isinstance(dur, (int, float)) else None,  # 100ns -> s
            "detail": str(details) if details else "",
        }

    # ---- PML-specific helpers (API kept from the original) ---------------

    def summary_stats(self) -> dict:
        """Get summary statistics."""
        processes = Counter(r["process_name"] for r in self.rows)
        operations = Counter(r["operation"] for r in self.rows)
        results = Counter(r["result"] for r in self.rows)
        return {
            "total_events": len(self.rows),
            "unique_processes": len(processes),
            "unique_operations": len(operations),
            "top_processes": processes.most_common(10),
            "top_operations": operations.most_common(10),
            "result_distribution": dict(results.most_common()),
        }

    def get_events_by_process(self, process_name: str):
        """All rows for a process (substring match)."""
        return self.filter(process_name=process_name)

    def get_file_operations(self, path_filter: str | None = None):
        """File system rows, optionally filtered by path substring."""
        ops = [r for r in self.rows
               if r["operation"] in self.FILE_OPS or r["event_class"].lower().startswith("file")]
        if path_filter:
            ops = [r for r in ops if path_filter.lower() in r["path"].lower()]
        return ops

    def get_registry_operations(self):
        """Registry rows."""
        return [r for r in self.rows
                if r["operation"].startswith("Reg") or r["event_class"].lower().startswith("reg")]

    def get_network_operations(self):
        """Network rows."""
        return [r for r in self.rows
                if r["event_class"].lower().startswith("net")
                or any(k in r["operation"] for k in ("TCP", "UDP", "Send", "Receive", "Connect"))]

    def get_process_operations(self):
        """Process/thread lifecycle rows (create/exit/load image)."""
        return [r for r in self.rows
                if r["operation"].startswith(("Process", "Thread", "Load"))
                or r["event_class"].lower().startswith("proc")]

    # ---- PML troubleshooting extras ---------------------------------------

    def loaded_modules(self, process_name: str):
        """DLLs loaded by a process (from the PML process table)."""
        seen = {}
        for e in self.events:
            p = getattr(e, "process", None)
            if p and process_name.lower() in str(getattr(p, "process_name", "")).lower():
                for m in getattr(p, "modules", []) or []:
                    seen[str(getattr(m, "path", m))] = getattr(m, "version", "")
        return seen

    def registry_misses(self, n: int = 20):
        """Registry keys that were looked up but don't exist (config lookups, COM, etc.)."""
        misses = [r for r in self.get_registry_operations() if r["result"] == "NAME NOT FOUND"]
        return self.top_n("path", n, misses)

    def dll_search_failures(self, n: int = 20):
        """Failed .dll/.exe lookups - DLL search-order issues and missing dependencies."""
        bad = [r for r in self.get_file_operations()
               if re.search(r"\.(dll|exe|sys|ocx)$", r["path"], re.I)
               and r["result"] in ("NAME NOT FOUND", "PATH NOT FOUND", "ACCESS DENIED")]
        return self.top_n("path", n, bad)

    def process_tree_roots(self):
        """Unique (process, pid) pairs seen in the capture."""
        return sorted({(r["process_name"], r["pid"]) for r in self.rows})

    def print_summary(self):
        """Print summary statistics."""
        stats = self.summary_stats()
        print("=" * 70)
        print("PML FILE ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Total Events: {stats['total_events']}")
        print(f"Unique Processes: {stats['unique_processes']}")
        print(f"Unique Operations: {stats['unique_operations']}")
        print("\nTop 10 Processes:")
        for proc, count in stats["top_processes"]:
            print(f"  {proc}: {count}")
        print("\nTop 10 Operations:")
        for op, count in stats["top_operations"]:
            print(f"  {op}: {count}")
        print("\nResult Distribution:")
        for result, count in stats["result_distribution"].items():
            print(f"  {result}: {count}")
        print("=" * 70)


def print_rows(rows, limit=20):
    for r in rows[:limit]:
        print(f"{r.get('time', '')} | {r.get('process_name', '')} | {r.get('operation', '')} | "
              f"{str(r.get('path', ''))[:70]} | {r.get('result', '')}")
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more")

