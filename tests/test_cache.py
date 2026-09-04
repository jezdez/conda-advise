from __future__ import annotations

import math
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

from conda_advise.cache import AdvisoryCache


def test_cache_reuses_fresh_positive_and_negative_entries(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "positive", {"value": 1}, positive=True, now=100)
        cache.put("source", "negative", {}, positive=False, now=100)

        positive = cache.get("source", "positive", now=101)
        negative = cache.get("source", "negative", now=101)

    assert positive is not None
    assert positive.payload == {"value": 1}
    assert positive.positive
    assert not positive.stale
    assert negative is not None
    assert not negative.positive


def test_cache_reuses_only_stale_positives(tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            "source",
            "positive",
            {"value": 1},
            positive=True,
            now=100,
            ttl=10,
            stale_positive_ttl=30,
        )
        cache.put("source", "negative", {}, positive=False, now=100, ttl=10)

        positive = cache.get("source", "positive", now=120)
        negative = cache.get("source", "negative", now=120)
        expired = cache.get("source", "positive", now=131)

    assert positive is not None
    assert positive.stale
    assert negative is None
    assert expired is None


def test_cache_replaces_query_result_sets(tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("osv.query", "pkg", {"vulns": [{"id": "old"}]}, positive=True)
        cache.put("osv.query", "pkg", {"vulns": []}, positive=False)

        cached = cache.get("osv.query", "pkg")

    assert cached is not None
    assert cached.payload == {"vulns": []}
    assert not cached.positive


def test_cache_enables_wal_and_busy_timeout(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path):
        with closing(sqlite3.connect(path)) as connection:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]

    assert journal_mode == "wal"
    assert busy_timeout == 5000


def test_cache_moves_a_corrupt_database_aside(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    path.write_bytes(b"not sqlite")

    with AdvisoryCache(path) as cache:
        cache.put("source", "key", {"ok": True}, positive=True)
        assert cache.get("source", "key") is not None

    assert list(tmp_path.glob("cache.sqlite3.corrupt-*"))


def test_cache_recreates_an_incompatible_schema(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE cache_entries (source TEXT)")
        connection.commit()

    with AdvisoryCache(path) as cache:
        cache.put("source", "key", {"ok": True}, positive=True)
        assert cache.get("source", "key") is not None

    assert list(tmp_path.glob("cache.sqlite3.corrupt-*"))


def test_cache_recovers_when_schema_is_corrupted_while_open(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "before", {"ok": True}, positive=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("DROP TABLE cache_entries")

        assert cache.get("source", "before") is None
        cache.put("source", "after", {"ok": True}, positive=True)
        assert cache.get("source", "after") is not None

    assert list(tmp_path.glob("cache.sqlite3.corrupt-*"))


def test_cache_recovery_failure_does_not_escape(monkeypatch, tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("DROP TABLE cache_entries")
            connection.commit()

        def fail_recovery(self) -> None:
            raise OSError("read-only cache directory")

        monkeypatch.setattr(AdvisoryCache, "_recover", fail_recovery)

        assert cache.get("source", "key") is None


def test_cache_serializes_writes_from_multiple_connections(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"

    def write_entries(worker: int) -> None:
        with AdvisoryCache(path) as cache:
            for index in range(25):
                cache.put(
                    "source",
                    f"{worker}:{index}",
                    {"worker": worker, "index": index},
                    positive=True,
                )

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(write_entries, range(4)))

    with closing(sqlite3.connect(path)) as connection:
        count = connection.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]
    assert count == 100
    assert not list(tmp_path.glob("cache.sqlite3.corrupt-*"))


def test_cache_write_contention_stops_at_the_scan_deadline(tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "existing", {"ok": True}, positive=True)
    with AdvisoryCache(path, deadline=time.monotonic() + 0.1) as cache:
        with closing(sqlite3.connect(path, timeout=0)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            blocker.execute(
                "UPDATE cache_entries SET payload = payload "
                "WHERE cache_key = 'existing'"
            )
            started = time.monotonic()
            cache.put("source", "blocked", {"ok": True}, positive=True)
            elapsed = time.monotonic() - started

    assert elapsed < 0.5
    with closing(sqlite3.connect(path)) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM cache_entries WHERE cache_key = 'blocked'"
        ).fetchone()[0]
    assert count == 0


def test_cache_rejects_nonfinite_numbers(tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("source", "nan", {"value": math.nan}, positive=True)

        assert cache.get("source", "nan") is None


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("positive", "not-an-integer"),
        ("fetched_at", "not-a-time"),
        ("expires_at", "not-a-time"),
        ("stale_until", "not-a-time"),
        ("expires_at", float("inf")),
    ],
    ids=["positive", "fetched-at", "expires-at", "stale-until", "infinite"],
)
def test_cache_discards_malformed_row_metadata(tmp_path, column, value) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "key", {"ok": True}, positive=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                f"UPDATE cache_entries SET {column} = ? WHERE cache_key = 'key'",
                (value,),
            )
            connection.commit()

        assert cache.get("source", "key") is None

        with closing(sqlite3.connect(path)) as connection:
            remaining = connection.execute(
                "SELECT COUNT(*) FROM cache_entries WHERE cache_key = 'key'"
            ).fetchone()[0]

    assert remaining == 0


@pytest.mark.parametrize("payload", ['{"score": NaN}', '{"score": 1e999}'])
def test_cache_discards_nonstandard_json_numbers(tmp_path, payload) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "key", {"ok": True}, positive=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "UPDATE cache_entries SET payload = ? WHERE cache_key = 'key'",
                (payload,),
            )
            connection.commit()

        assert cache.get("source", "key") is None
