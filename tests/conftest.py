"""Shared fixtures, plus the security scorecard printed at the end of every pytest run."""
from __future__ import annotations

import pytest

from src.config import load_config
from src.ingest.normalizer import EdgeTokenizer, Normalizer
from tests.redteam import SCORECARD


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def edge_tokenizer(cfg):
    return EdgeTokenizer.from_config(cfg)


@pytest.fixture(scope="session")
def normalizer(cfg, edge_tokenizer):
    return Normalizer.from_config(cfg, tokenizer=edge_tokenizer)


def pytest_terminal_summary(terminalreporter):
    if not SCORECARD:
        return
    terminalreporter.section("security scorecard")
    for section, rows in SCORECARD.items():
        terminalreporter.write_line("")
        terminalreporter.write_line(section)
        width = max(len(row[0]) for row in rows)
        for name, passed, total, note in rows:
            pct = 100.0 * passed / total if total else 100.0
            terminalreporter.write_line(f"  {name:<{width}}  {passed:>5} / {total:<5} {pct:6.1f}%  {note}".rstrip())
