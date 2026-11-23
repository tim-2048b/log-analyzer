from __future__ import annotations

import csv
from typing import Literal

import pandas as pd

from .const import Num_str_value




def load_csv_df(
    path: str,
    columns: list[str] | None = None,
    include_pattern: dict[str, Num_str_value | list[Num_str_value]] | None = None,
    exclude_pattern: dict[str, Num_str_value | list[Num_str_value]] | None = None,
    encoding: str = "utf-8",
    sep: str | None = None,
    index_col: str | int | bool = False,
    encoding_errors: str = "replace",
    max_rows = 1000,
    quoting: Literal[0,1,2,3,4] = csv.QUOTE_MINIMAL,
    strip_whitespace: bool = False,
) -> pd.DataFrame:
    """Load a delimited text file (e.g. a Windows Event Log CSV export) into a DataFrame.

    The delimiter is auto-detected from the first 64 KiB of the file unless
    ``sep`` is given. Rows can then be dropped by matching column values.

    Args:
        path: Path of the file to read.
        columns: Names that replace the header row. Must have the same length
            as the file's header, otherwise ``ValueError`` is raised. If None,
            the file's own header is used.
        exclude_pattern: Mapping of ``{column_name: value | [values]}``. Rows
            whose column value matches any listed value are dropped. Values are
            compared as strings, so ``"4625"`` matches both ``4625`` and
            ``"4625"`` in the data. Default None (no filtering).
        encoding: Text encoding of the file. Default ``utf-8-sig`` strips a BOM. 
            use ``utf-16`` for current Sharepoint uls as they contain BOM
        sep: Delimiter. If None (recommended), it is detected from the header
            line first, because header names never contain free text, then by
            ``csv.Sniffer``, then falls back to ``,``. An explicit value always
            wins, so passing ``sep=","`` on a tab-delimited log breaks parsing.
        index_col: Passed to ``pandas.read_csv``. ``False`` (default) keeps a
            default RangeIndex.
        encoding_errors: How undecodable bytes are handled (``"replace"``,
            ``"strict"`` or ``"ignore"``). Default ``"replace"``.
        max_rows: Max number of row to load; default be `1000`
        quoting: ``csv`` quoting mode. Use ``csv.QUOTE_NONE`` for logs such as
            SharePoint ULS whose messages contain stray ``"`` characters.
        strip_whitespace: Strip leading/trailing spaces from column names and
            string cells. Useful for column-padded exports such as ULS.

    Returns:
        The loaded DataFrame, filtered by ``exclude_pattern``.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ValueError: ``columns`` length differs from the header length, or a key
            in ``exclude_pattern`` is not a column of the result.

    Notes:
        Malformed lines (too many fields) are skipped with a warning.

    Example:
        >>> df = load_csv_df("events.csv", exclude_pattern={"Event ID": [4624, "4634"]})
    """
    with open(path, "r", newline="", encoding=encoding, errors=encoding_errors) as f:
        sample = f.read(65536)
    delimiter = _pick_delimiter(sample, sep)
    header = next(csv.reader(sample.splitlines(), delimiter=delimiter), [])

    if columns is not None and header and len(columns) != len(header):
        raise ValueError(
            f"columns has {len(columns)} names but the file header has {len(header)}"
        )

    df = pd.read_csv(
        path,
        header=0,
        names=columns,
        encoding=encoding,
        encoding_errors=encoding_errors,
        sep=delimiter,
        index_col=index_col,
        on_bad_lines="warn",
        quoting = quoting,
        quotechar='"', 
        nrows= max_rows
    )

    if strip_whitespace:
        df.columns = [c.strip() if isinstance(c, str) else c for c in df.columns]
        for col in df.columns:
            if pd.api.types.is_string_dtype(df[col]):
                df[col] = df[col].str.strip()

    print("[load_csv_df]:Overall dataframe info:",df.info())

    
    # Include pattern 
    for key, raw_filter_value in (include_pattern or {}).items():
        if key not in df.columns:
            raise ValueError(f"include_pattern column {key!r} not found; have {list(df.columns)}")
        values = {str(v) for v in (raw_filter_value if isinstance(raw_filter_value, list) else [raw_filter_value])}
        df = df[df[key].astype(str).isin(values)]
    
    
    for key, raw_filter_value in (exclude_pattern or {}).items():
        if key not in df.columns:
            raise ValueError(f"exclude_pattern column {key!r} not found; have {list(df.columns)}")
        values = {str(v) for v in (raw_filter_value if isinstance(raw_filter_value, list) else [raw_filter_value])}
        df = df[~df[key].astype(str).isin(values)]

    return df


_CANDIDATES = ",;\t|"


def _pick_delimiter(sample: str, sep: str | None) -> str:
    if sep:
        return sep
    # 1) Header line: column names are short and free of message text, so the
    #    candidate it contains most often is the real delimiter.
    first = next((ln for ln in sample.splitlines() if ln.strip()), "")
    counts = {d: first.count(d) for d in _CANDIDATES}
    best = max(counts.values(), default=0)
    if best > 0 and list(counts.values()).count(best) == 1:
        return next(d for d, n in counts.items() if n == best)
    # 2) Statistical guess over the whole sample.
    try:
        return csv.Sniffer().sniff(sample, delimiters=_CANDIDATES).delimiter
    except csv.Error:
        return ","
