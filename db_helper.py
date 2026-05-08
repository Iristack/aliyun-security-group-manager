import logging
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Optional

logger = logging.getLogger("DBHelper")


class DBHelper:
    """Thread-safe singleton SQLite database helper with WAL mode."""

    _instance: Optional["DBHelper"] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, db_path: str = "monitor.db") -> None:
        self.db_path = db_path
        self._init_tables()

    @classmethod
    def get_instance(cls, db_path: str = "monitor.db") -> "DBHelper":
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = cls(db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (useful for testing)."""
        with cls._lock:
            cls._instance = None

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
            conn.commit()
            logger.debug("DB operation committed")
        except Exception as e:
            conn.rollback()
            logger.error("DB error, rollback: %s", e)
            raise
        finally:
            conn.close()

    def _init_tables(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    old_ip TEXT,
                    new_ip TEXT NOT NULL,
                    change_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS last_status (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    current_ip TEXT,
                    last_check_time TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip_history_time
                ON ip_history(change_time DESC)
            """)
            logger.info("Database tables initialized")

    def save_ip_change(self, old_ip: str | None, new_ip: str) -> None:
        """Record an IP change and update last status."""
        now_iso = datetime.now(UTC).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO ip_history (old_ip, new_ip, change_time) VALUES (?, ?, ?)",
                (old_ip, new_ip, now_iso),
            )
            cursor.execute(
                "INSERT OR REPLACE INTO last_status (id, current_ip, last_check_time) VALUES (1, ?, ?)",
                (new_ip, now_iso),
            )
        logger.info("DB saved IP change: %s -> %s", old_ip, new_ip)

    def get_last_ip(self) -> str | None:
        """Return the last known public IP."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_ip FROM last_status WHERE id = 1")
            row = cursor.fetchone()
            return row["current_ip"] if row else None

    def get_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent IP change history."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ip_history ORDER BY change_time DESC LIMIT ?",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
