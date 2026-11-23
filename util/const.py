from typing import TypeAlias
# --------------------------------------------------------------------------
# Constants / helpers
# --------------------------------------------------------------------------

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

# Statuses that are normal noise in Procmon traces (not real problems)
BENIGN_STATUSES = {
    0, 259, 0x80000005, 0x80000006, 0x8000001A, 0xC0000011, 0xC0000275,
    0xC0000035,
}

SUCCESS_WORDS = {"success", "ok", 
                 "0", "pass", "passed", "true", "200", "info",
                 "information", "debug", "trace", "notice", ""}
ERROR_WORDS = {"error", "err", "fatal", "critical", "crit", "fail", "failed",
               "failure", "exception", "severe", "alert", "emerg", "false"}
WARN_WORDS = {"warn", "warning"}

# Canonical column -> header aliases (lower-case) used to auto-map CSVs
COLUMN_ALIASES = {
    "time": [
        "time", 
        "time of day", 
        "timestamp", 
        "datetime", "date", "@timestamp",
             "date/time", "eventtime", "timecreated", "time_created", "logtime", "Date And Time"],
    "process_name": ["process name", "process_name", "process", "image", "app",
                     "application", "service", "source", "provider", "providername"],
    "pid": ["pid", "process id", "process_id", "processid"],
    "operation": ["operation", "event", "action", "eventname", "event_name", "op",
                  "event id", "eventid"],
    "path": ["path", "file", "filename", "target", "resource", "url", "uri", "key"],
    "result": ["result", "status", "outcome", "status_code", "statuscode", "response"],
    "level": ["level", "severity", "loglevel", "log_level", "levelname", "type", "Event Level"],
    "detail": ["detail", "details", "message", "msg", "description", "text"],
    "duration": [
        "duration", 
        "elapsed", "latency", "time_ms", "duration_ms",
                 "response_time", "responsetime", "took"],
}

TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f", 
    "%Y-%m-%d %H:%M:%S", 
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S", 
    "%Y-%m-%dT%H:%M:%S.%fZ", 
    "%Y-%m-%dT%H:%M:%SZ",
    "%m/%d/%Y %H:%M:%S", 
    "%m/%d/%Y %I:%M:%S %p", 
    "%m/%d/%Y %I:%M:%S.%f %p",
    "%d/%m/%Y %H:%M:%S", 
    "%I:%M:%S.%f %p", 
    "%I:%M:%S %p", 
    "%H:%M:%S.%f",
    "%H:%M:%S", 
    "%b %d %H:%M:%S",
]

CATEGORY_PATH: dict[str, list[str]] = {
    "SharePoint-uls": ["Process", "Area", "Category" ], 
    "Winevt-csv": ["Source", "Task Category"]
}

SEVERITY_PATH: dict[str, list[str]] = {
    "SharePoint-uls": ["Level" ], 
    "Winevt-csv": ["Level"]
}


# Type Alias for constraint certain log analysis process
Num_str_value: TypeAlias = int | float | str