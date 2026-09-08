from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING

from platformdirs import user_cache_path

from .models import is_json_value

if TYPE_CHECKING:
    from typing import Any

FRESH_TTL_SECONDS = 24 * 60 * 60
STALE_POSITIVE_SECONDS = 7 * 24 * 60 * 60
_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6
_SQLITE_CORRUPT = 11
_SQLITE_NOTADB = 26
_BUSY_TIMEOUT_SECONDS = 5.0
MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_CACHE_ENTRIES = 10_000
MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_WAL_BYTES = 16 * 1024 * 1024


class _CacheSchemaError(sqlite3.DatabaseError):
    pass


@dataclass(frozen=True, slots=True)
class CacheEntry:
    payload: Any
    positive: bool
    fetched_at: float
    stale: bool


def default_cache_path() -> Path:
    configured = os.environ.get("CONDA_ADVISE_CACHE_PATH")
    if configured:
        return Path(configured)
    return user_cache_path("conda-advise") / "cache.sqlite3"


class AdvisoryCache:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        deadline: float | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else default_cache_path()
        self.deadline = deadline
        self._connection = self._open()

    def __enter__(self) -> AdvisoryCache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def get(
        self,
        source: str,
        key: str,
        *,
        now: float | None = None,
        allow_stale_positive: bool = True,
    ) -> CacheEntry | None:
        timestamp = time.time() if now is None else now
        if not self._prepare_operation():
            return None
        try:
            row = self._connection.execute(
                """
                SELECT CASE WHEN length(CAST(payload AS BLOB)) <= ?
                            THEN payload END,
                       positive, fetched_at, expires_at, stale_until
                FROM cache_entries
                WHERE source = ? AND cache_key = ?
                """,
                (MAX_ENTRY_BYTES, source, key),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            if _is_corruption(error):
                self._recover_safely()
            return None
        if row is None:
            return None
        payload_json, positive, fetched_at, expires_at, stale_until = row
        try:
            if not isinstance(payload_json, str) or positive not in (0, 1):
                raise ValueError
            normalized_fetched_at = float(fetched_at)
            normalized_expires_at = float(expires_at)
            normalized_stale_until = float(stale_until)
            if not all(
                isfinite(value)
                for value in (
                    normalized_fetched_at,
                    normalized_expires_at,
                    normalized_stale_until,
                )
            ):
                raise ValueError
        except (TypeError, ValueError):
            self.delete(source, key)
            return None
        fresh = timestamp <= normalized_expires_at
        stale_positive = (
            bool(positive)
            and allow_stale_positive
            and timestamp <= normalized_stale_until
        )
        if not fresh and not stale_positive:
            self.delete(source, key)
            return None
        try:
            payload = json.loads(payload_json)
            if not is_json_value(payload):
                raise ValueError
        except (RecursionError, TypeError, ValueError, json.JSONDecodeError):
            self.delete(source, key)
            return None
        return CacheEntry(
            payload=payload,
            positive=bool(positive),
            fetched_at=normalized_fetched_at,
            stale=not fresh,
        )

    def put(
        self,
        source: str,
        key: str,
        payload: Any,
        *,
        positive: bool,
        now: float | None = None,
        ttl: float = FRESH_TTL_SECONDS,
        stale_positive_ttl: float = STALE_POSITIVE_SECONDS,
    ) -> None:
        timestamp = time.time() if now is None else now
        if len(source) > 16_384 or len(key) > 16_384:
            return
        serialized = self._serialize(payload)
        if serialized is None:
            return
        stale_until = timestamp + stale_positive_ttl if positive else timestamp + ttl
        if not self._prepare_operation():
            return
        try:
            if str(self.path) != ":memory:":
                wal = self.path.with_name(f"{self.path.name}-wal")
                try:
                    if wal.stat().st_size > MAX_WAL_BYTES:
                        self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                        if wal.stat().st_size > MAX_WAL_BYTES:
                            return
                except FileNotFoundError:
                    pass
            with self._connection:
                self._prune(self._connection, timestamp)
                self._connection.execute(
                    """
                    INSERT INTO cache_entries (
                        source, cache_key, positive, payload,
                        fetched_at, expires_at, stale_until
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source, cache_key) DO UPDATE SET
                        positive = excluded.positive,
                        payload = excluded.payload,
                        fetched_at = excluded.fetched_at,
                        expires_at = excluded.expires_at,
                        stale_until = excluded.stale_until
                    """,
                    (
                        source,
                        key,
                        int(positive),
                        serialized,
                        timestamp,
                        timestamp + ttl,
                        stale_until,
                    ),
                )
                self._prune(self._connection, timestamp)
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except (OSError, sqlite3.DatabaseError) as error:
            if isinstance(error, OSError) or not _is_corruption(error):
                return
            if not self._recover_safely():
                return
            try:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT OR REPLACE INTO cache_entries (
                            source, cache_key, positive, payload,
                            fetched_at, expires_at, stale_until
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            source,
                            key,
                            int(positive),
                            serialized,
                            timestamp,
                            timestamp + ttl,
                            stale_until,
                        ),
                    )
                    self._prune(self._connection, timestamp)
            except sqlite3.DatabaseError:
                return

    def delete(self, source: str, key: str) -> None:
        if not self._prepare_operation():
            return
        try:
            with self._connection:
                self._connection.execute(
                    "DELETE FROM cache_entries WHERE source = ? AND cache_key = ?",
                    (source, key),
                )
        except sqlite3.DatabaseError as error:
            if _is_corruption(error):
                self._recover_safely()

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(5):
            connection = sqlite3.connect(
                self.path,
                timeout=self._remaining_busy_timeout(),
            )
            try:
                self._initialize(connection)
            except sqlite3.DatabaseError as error:
                connection.close()
                if _is_corruption(error):
                    self._move_corrupt_database()
                    continue
                if _is_busy(error) and attempt < 4:
                    remaining = self._remaining_busy_timeout()
                    if remaining <= 0:
                        raise
                    time.sleep(min(0.05 * (attempt + 1), remaining))
                    continue
                raise
            return connection
        raise sqlite3.DatabaseError("could not initialize advisory cache")

    def _recover(self) -> None:
        self._connection.close()
        self._move_corrupt_database()
        self._connection = sqlite3.connect(
            self.path,
            timeout=self._remaining_busy_timeout(),
        )
        self._initialize(self._connection)

    def _recover_safely(self) -> bool:
        try:
            self._recover()
        except (OSError, sqlite3.DatabaseError):
            return False
        return True

    def _initialize(self, connection: sqlite3.Connection) -> None:
        self._set_busy_timeout(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA journal_size_limit={MAX_ENTRY_BYTES}")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cache_entries (
                source TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                positive INTEGER NOT NULL,
                payload TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                stale_until REAL NOT NULL,
                PRIMARY KEY (source, cache_key)
            )
            """
        )
        expected = (
            ("source", "TEXT", 1, 1),
            ("cache_key", "TEXT", 1, 2),
            ("positive", "INTEGER", 1, 0),
            ("payload", "TEXT", 1, 0),
            ("fetched_at", "REAL", 1, 0),
            ("expires_at", "REAL", 1, 0),
            ("stale_until", "REAL", 1, 0),
        )
        actual = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in connection.execute("PRAGMA table_info(cache_entries)")
        )
        if actual != expected:
            raise _CacheSchemaError("cache schema is incompatible")
        connection.execute("PRAGMA user_version=1")
        connection.commit()
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        if page_size * page_count > MAX_DATABASE_BYTES:
            with connection:
                self._prune(connection, time.time())
            connection.execute("VACUUM")
        connection.execute(
            f"PRAGMA max_page_count={max(1, MAX_DATABASE_BYTES // page_size)}"
        )

    def _serialize(self, payload: Any) -> str | None:
        if not self._prepare_operation() or not is_json_value(payload):
            return None
        parts: list[str] = []
        size = 0
        try:
            encoder = json.JSONEncoder(
                allow_nan=False, sort_keys=True, separators=(",", ":")
            )
            for part in encoder.iterencode(payload):
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    return None
                size += len(part.encode("utf-8"))
                if size > MAX_ENTRY_BYTES:
                    return None
                parts.append(part)
        except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError):
            return None
        return "".join(parts)

    def _prune(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "DELETE FROM cache_entries WHERE stale_until < ? "
            "OR length(CAST(payload AS BLOB)) > ?",
            (now, MAX_ENTRY_BYTES),
        )
        connection.execute(
            """
            DELETE FROM cache_entries WHERE rowid IN (
                SELECT rowid FROM (
                    SELECT rowid,
                           ROW_NUMBER() OVER recent AS entry_number,
                           SUM(length(CAST(payload AS BLOB))
                               + length(CAST(source AS BLOB))
                               + length(CAST(cache_key AS BLOB))) OVER recent AS bytes
                    FROM cache_entries
                    WINDOW recent AS (ORDER BY fetched_at DESC, rowid DESC)
                ) WHERE entry_number > ? OR bytes > ?
            )
            """,
            (MAX_CACHE_ENTRIES, MAX_CACHE_BYTES),
        )

    def _remaining_busy_timeout(self) -> float:
        if self.deadline is None:
            return _BUSY_TIMEOUT_SECONDS
        return max(0.0, min(_BUSY_TIMEOUT_SECONDS, self.deadline - time.monotonic()))

    def _set_busy_timeout(self, connection: sqlite3.Connection) -> None:
        milliseconds = max(0, int(self._remaining_busy_timeout() * 1000))
        connection.execute(f"PRAGMA busy_timeout={milliseconds}")

    def _prepare_operation(self) -> bool:
        if self.deadline is not None and self.deadline <= time.monotonic():
            return False
        self._set_busy_timeout(self._connection)
        return True

    def _move_corrupt_database(self) -> None:
        if self.path.exists():
            suffix = f".corrupt-{int(time.time())}-{os.getpid()}"
            try:
                self.path.replace(self.path.with_name(f"{self.path.name}{suffix}"))
            except FileNotFoundError:
                pass
        for suffix in ("-wal", "-shm"):
            self.path.with_name(f"{self.path.name}{suffix}").unlink(missing_ok=True)


def _is_corruption(error: sqlite3.DatabaseError) -> bool:
    if isinstance(error, _CacheSchemaError):
        return True
    error_code = getattr(error, "sqlite_errorcode", None)
    if error_code is not None and error_code & 0xFF in {
        _SQLITE_CORRUPT,
        _SQLITE_NOTADB,
    }:
        return True
    message = str(error).lower()
    return any(
        marker in message
        for marker in (
            "database disk image is malformed",
            "file is not a database",
            "no such table: cache_entries",
        )
    )


def _is_busy(error: sqlite3.DatabaseError) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    if error_code is not None and error_code & 0xFF in {
        _SQLITE_BUSY,
        _SQLITE_LOCKED,
    }:
        return True
    message = str(error).lower()
    return "database is locked" in message or "database table is locked" in message
