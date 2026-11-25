"""
pyanalysis: analyze Process Monitor (.pml) captures and any CSV log.

    from troubleshoot import PMLAnalyzer, CSVAnalyzer, load

`procmon_parser` is only imported when a .pml file is opened, so CSV-only use
does not require it.
"""
print(f"loaded {__package__}.{__name__}")       # current module name

from .csv_analyzer import CSVAnalyzer
from .loader import load

from .log_analyzer import LogAnalyzer
from .pml_analyzer import PMLAnalyzer, print_rows

__all__ = ["LogAnalyzer", "CSVAnalyzer", "PMLAnalyzer", "load", "print_rows"]
__doc__ = """
  General purpose logparse.
"""
