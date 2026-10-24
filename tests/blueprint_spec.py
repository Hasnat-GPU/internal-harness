"""Reads the machine-checkable parts of Blueprint_Backend.html, so tests compare against the source
of truth itself: the §5.1 directory tree and the §5.2 SQLite DDL."""
from __future__ import annotations

import re
from html.parser import HTMLParser

from src.config import PROJECT_ROOT

BLUEPRINT = PROJECT_ROOT / "Blueprint_Backend.html"
_TREE_ENTRY = re.compile(r"^((?:│   |    )*)(?:├── |└── )(\S+)")


class _PreBlocks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[str] = []
        self._buffer: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "pre":
            self._buffer = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "pre" and self._buffer is not None:
            self.blocks.append("".join(self._buffer))
            self._buffer = None

    def handle_data(self, data: str) -> None:
        if self._buffer is not None:
            self._buffer.append(data)


def pre_blocks() -> list[str]:
    parser = _PreBlocks()
    parser.feed(BLUEPRINT.read_text(encoding="utf-8"))
    return parser.blocks


def directory_tree() -> tuple[list[str], list[str]]:
    """(directories, files) of the §5.1 tree as project-relative POSIX paths."""
    tree = next(block for block in pre_blocks() if block.startswith("internal-harness/"))
    dirs: list[str] = []
    files: list[str] = []
    stack: list[str] = []
    for line in tree.splitlines()[1:]:
        match = _TREE_ENTRY.match(line)
        if not match:
            continue
        depth, name = len(match.group(1)) // 4, match.group(2)
        stack = stack[:depth]
        path = "/".join([*stack, name.rstrip("/")])
        if name.endswith("/"):
            dirs.append(path)
            stack.append(name.rstrip("/"))
        else:
            files.append(path)
            if "/" in name:  # e.g. "ingest/normalizer.py" also declares the ingest/ directory
                dirs.append(path.rsplit("/", 1)[0])
    return dirs, files


def sqlite_ddl() -> str:
    """The §5.2 CREATE TABLE statements, verbatim."""
    return next(block for block in pre_blocks() if "CREATE TABLE IF NOT EXISTS episodic_events" in block)
