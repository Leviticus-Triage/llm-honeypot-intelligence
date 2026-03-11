"""
SQLite database schema and helper functions for the Ollama Proxy cache + RL system.
"""

import sqlite3
import os
import threading
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.environ.get("CACHE_DB", "/data/ollama-proxy/cache.db")

_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA busy_timeout=5000")
    return _local.conn


@contextmanager
def get_db():
    """Context manager for database operations with auto-commit."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Initialize the database schema."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    # Create tables
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS prompt_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_hash TEXT NOT NULL UNIQUE,
            prompt_text TEXT NOT NULL,
            prompt_embedding BLOB,
            model TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt_cache_id INTEGER NOT NULL,
            response_text TEXT NOT NULL,
            engagement_score REAL NOT NULL DEFAULT 0.5,
            times_served INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_served TEXT,
            FOREIGN KEY (prompt_cache_id) REFERENCES prompt_cache(id)
        );

        CREATE TABLE IF NOT EXISTS serve_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            response_id INTEGER NOT NULL,
            served_at TEXT NOT NULL DEFAULT (datetime('now')),
            honeypot_type TEXT NOT NULL DEFAULT '',
            prompt_hash TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (response_id) REFERENCES responses(id)
        );
    """)

    # Migrations: add columns if missing (for existing databases)
    migrations = [
        ("serve_log", "src_ip", "ALTER TABLE serve_log ADD COLUMN src_ip TEXT NOT NULL DEFAULT ''"),
        ("serve_log", "cve_id", "ALTER TABLE serve_log ADD COLUMN cve_id TEXT NOT NULL DEFAULT ''"),
        ("serve_log", "cve_vendor", "ALTER TABLE serve_log ADD COLUMN cve_vendor TEXT NOT NULL DEFAULT ''"),
        ("serve_log", "cve_product", "ALTER TABLE serve_log ADD COLUMN cve_product TEXT NOT NULL DEFAULT ''"),
        ("prompt_cache", "cve_id", "ALTER TABLE prompt_cache ADD COLUMN cve_id TEXT NOT NULL DEFAULT ''"),
    ]
    for table, col, sql in migrations:
        try:
            conn.execute(f"SELECT {col} FROM {table} LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute(sql)
            conn.commit()

    # Create indexes (after migration so all columns exist)
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_prompt_hash ON prompt_cache(prompt_hash);
        CREATE INDEX IF NOT EXISTS idx_responses_prompt ON responses(prompt_cache_id);
        CREATE INDEX IF NOT EXISTS idx_responses_score ON responses(engagement_score DESC);
        CREATE INDEX IF NOT EXISTS idx_serve_log_time ON serve_log(served_at);
        CREATE INDEX IF NOT EXISTS idx_serve_log_response ON serve_log(response_id);
        CREATE INDEX IF NOT EXISTS idx_serve_log_ip ON serve_log(src_ip);
        CREATE INDEX IF NOT EXISTS idx_serve_log_cve ON serve_log(cve_id);
        CREATE INDEX IF NOT EXISTS idx_prompt_cache_cve ON prompt_cache(cve_id);
    """)
    conn.commit()
    conn.close()


def get_cache_stats() -> dict:
    """Return cache statistics."""
    with get_db() as conn:
        total_prompts = conn.execute("SELECT COUNT(*) FROM prompt_cache").fetchone()[0]
        total_responses = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        total_served = conn.execute("SELECT COUNT(*) FROM serve_log").fetchone()[0]
        avg_score = conn.execute(
            "SELECT AVG(engagement_score) FROM responses"
        ).fetchone()[0]
    return {
        "total_prompts": total_prompts,
        "total_responses": total_responses,
        "total_served": total_served,
        "avg_engagement_score": round(avg_score, 3) if avg_score else 0.0,
    }
