"""M4: Episodic SQLite & Task-Vector Bank (mod_bank).

T03 scope: the exact SQLite schema of Blueprint §5.2 and the initialiser for
``data/episodic_buffer.db``. Rule deprecation (T06), anchor promotion (T10) and task-vector
arithmetic (T12) are added by their own tasks.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from ..config import load_config, resolve_path

# Verbatim from Blueprint_Backend.html §5.2 (SQLite keeps the comments in sqlite_master).
SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS episodic_events (
    event_id TEXT PRIMARY KEY,            -- UUID v4
    created_at INTEGER NOT NULL,          -- Unix epoch milliseconds
    domain_tag TEXT NOT NULL,             -- 'prompt_refinement'|'tool_synthesis'|'memory_policy'|'subagent_routing'|'general'
    source_trust TEXT NOT NULL,           -- 'HUMAN'|'HARNESS2_VERIFIED'|'UNTRUSTED_EXTERNAL'
    outcome_status TEXT NOT NULL,         -- 'VERIFIED_SUCCESS'|'FAILURE'
    context_text TEXT NOT NULL,           -- Scrubbed input state / task context
    expected_action TEXT NOT NULL,        -- Scrubbed verified refinement or action
    context_embedding BLOB NOT NULL,      -- Float32 mean-pooled vector for conflict check
    surprise_score REAL NOT NULL,         -- Cross-entropy loss S_t at ingestion
    is_human_correction INTEGER NOT NULL, -- 1 if human override, 0 otherwise
    verified_success_count INTEGER DEFAULT 1,
    status TEXT DEFAULT 'ACTIVE',         -- 'ACTIVE'|'DEPRECATED'
    supersedes_event_id TEXT DEFAULT NULL,-- Points to older event_id if replaced
    consolidated INTEGER DEFAULT 0        -- 0 = pending sleep, 1 = merged into long_term
);

CREATE TABLE IF NOT EXISTS pending_failures (
    failure_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    domain_tag TEXT NOT NULL,
    context_text TEXT NOT NULL,
    failed_action TEXT NOT NULL,          -- Stored for contrastive unlikelihood penalty once resolved
    resolved_by_event_id TEXT DEFAULT NULL
);
"""


def init_db(db_path: str | Path | None = None) -> Path:
    """Create the episodic buffer tables if they are missing (idempotent); returns the DB path."""
    path = Path(db_path) if db_path is not None else resolve_path(load_config()["paths"]["episodic_db"])
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    return path


if __name__ == "__main__":
    print(f"initialised {init_db()}")
