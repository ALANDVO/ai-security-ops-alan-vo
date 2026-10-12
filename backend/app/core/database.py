"""SQLite database initialization and connection management."""
import sqlite3
import threading
import logging
from contextlib import contextmanager
from typing import Generator, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

_local = threading.local()
_memory_conn: Optional[sqlite3.Connection] = None  # Shared for :memory: DBs


def get_db_path() -> str:
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url[len("sqlite:///"):]
    if url.startswith("sqlite:///:memory:"):
        return ":memory:"
    return "./security_ops.db"


def reset_memory_db() -> None:
    """Close and reset the shared in-memory connection (for test isolation)."""
    global _memory_conn
    if _memory_conn is not None:
        try:
            _memory_conn.close()
        except Exception:
            pass
    _memory_conn = None


def _get_connection() -> sqlite3.Connection:
    global _memory_conn
    path = get_db_path()
    if path == ":memory:":
        # Use a single shared connection for in-memory so tests and app share state
        if _memory_conn is None:
            _memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            _memory_conn.row_factory = sqlite3.Row
            _memory_conn.execute("PRAGMA foreign_keys=ON")
        return _memory_conn
    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return _local.conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    """Create schema tables if they do not exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                asset TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.75,
                score REAL NOT NULL DEFAULT 0.0,
                llm_classification TEXT,
                llm_summary TEXT,
                raw_data TEXT NOT NULL DEFAULT '{}',
                detected_at TEXT NOT NULL,
                correlated_incident TEXT
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'open',
                description TEXT NOT NULL DEFAULT '',
                threat_count INTEGER NOT NULL DEFAULT 0,
                types TEXT NOT NULL DEFAULT '[]',
                llm_analysis TEXT,
                llm_recommendation TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asset_scores (
                asset TEXT PRIMARY KEY,
                score REAL NOT NULL DEFAULT 50.0,
                risk_level TEXT NOT NULL DEFAULT 'medium',
                factors TEXT NOT NULL DEFAULT '[]',
                last_assessed TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
            CREATE INDEX IF NOT EXISTS idx_threats_asset ON threats(asset);
            CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        """)
    logger.info("Database initialized at %s", get_db_path())
