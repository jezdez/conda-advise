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


class _CacheSchemaError(sqlite3.DatabaseError):
    pass


@dataclass(frozen=True, slots=True)
class CacheEntry:
    payload: Any
    positive: bool
    fetched_at: float
    stale: bool


def default_cache_path() -> Path:
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
                SELECT payload, positive, fetched_at, expires_at, stale_until
                FROM cache_entries
                WHERE source = ? AND cache_key = ?
                """,
                (source, key),
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
        try:
            serialized = json.dumps(
                payload,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (OverflowError, RecursionError, TypeError, ValueError):
            return
        stale_until = timestamp + stale_positive_ttl if positive else timestamp + ttl
        if not self._prepare_operation():
            return
        try:
            with self._connection:
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
        except sqlite3.DatabaseError as error:
            if not _is_corruption(error):
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
