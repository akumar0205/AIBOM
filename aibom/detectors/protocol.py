from __future__ import annotations

from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from aibom.analyzer import ScanContext, ScanResult


class SourceDetector(Protocol):
    source_type: str

    def scan(self, context: ScanContext) -> ScanResult: ...
