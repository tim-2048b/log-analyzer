"""load(): pick the right analyzer from a file's extension."""

from __future__ import annotations

from pathlib import Path

from .csv_analyzer import CSVAnalyzer
from .log_analyzer import LogAnalyzer
from .pml_analyzer import PMLAnalyzer


def load(path: str, **kwargs) -> LogAnalyzer:
    """ Simple routing function that load log file into Analyzer class.
       Parameter
            path: the path to the log file
       .pml -> PMLAnalyzer; 
       anything else -> CSVAnalyzer (kwargs go to CSVAnalyzer).
    """
    return PMLAnalyzer(path) if Path(path).suffix.lower() == ".pml" else CSVAnalyzer(path,**kwargs)
