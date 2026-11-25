"""
Shared parsing helpers used by every analyzer (CSV and PML).

Kept as plain functions in their own module because three other modules need
them; putting them inside any one analyzer class would force the others to
import that class just to parse a timestamp.
"""

from __future__ import annotations

import re
import warnings
from datetime import datetime
#07/12/2026 15:28:12.04
TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M:%S.%f %p",
    "%d/%m/%Y %H:%M:%S", "%I:%M:%S.%f %p", "%I:%M:%S %p", "%H:%M:%S.%f",
    "%H:%M:%S", "%b %d %H:%M:%S",
]

def parse_time(value) -> datetime | None:
    """Best-effort timestamp parsing (ISO, US dates, Procmon time-of-day, epoch)."""
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    # Procmon has 7 fractional digits; datetime supports 6
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    if re.fullmatch(r"\d{10}(\.\d+)?", s):
        return datetime.fromtimestamp(float(s))
    if re.fullmatch(r"\d{13}", s):
        return datetime.fromtimestamp(int(s) / 1000)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for fmt in TIME_FORMATS:
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
    return None


def parse_number(value) -> float | None:
    """Parse '1,234', '12ms', '0.5 s', '45%' style values into floats."""
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return None
    s = str(value).strip().replace(",", "")
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(ms|s|sec|us|%|kb|mb|gb)?", s, re.I)
    if not m:
        return None
    num, unit = float(m.group(1)), (m.group(2) or "").lower()
    if unit == "ms":
        return num / 1000.0
    if unit == "us":
        return num / 1e6
    return num

