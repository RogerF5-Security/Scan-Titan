"""Literal spreadsheet data writes, separate from trusted template formulas."""
from __future__ import annotations

from typing import Any


def write_openpyxl_data(cell: Any, value: Any) -> None:
    """Preserve data verbatim while preventing formula/error inference for text."""
    cell.value = value
    if isinstance(value, str):
        cell.data_type = "s"


def write_com_data(cell: Any, value: Any) -> None:
    """Set text format before Excel interprets a string assigned through COM."""
    if isinstance(value, str):
        cell.NumberFormat = "@"
    cell.Value = value
