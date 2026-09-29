"""Deterministic generators for SherLog's sample evidence sets.

Each scenario writes ``<out>/<name>/evidence/`` (logs with realistic benign
activity plus the incident) and ``<out>/<name>/answer_key.json`` (what was
injected: expected findings, techniques, IOCs and timeline). The end-to-end
tests in ``tests/e2e`` run the full pipeline on each and compare.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from samples.generate import scenario_a

SCENARIOS: dict[str, Callable[[Path], Path]] = {
    "a": scenario_a.generate,
}
