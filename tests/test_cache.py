from __future__ import annotations

import math
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

import conda_advise.cache as cache_module
from conda_advise.cache import AdvisoryCache


@pytest.mark.parametrize("in_memory", [False, True], ids=["disk", "memory"])
def test_cache_reuses_fresh_positive_and_negative_entries(tmp_path, in_memory) -> None:
    path = ":memory:" if in_memory else tmp_path / "cache.sqlite3"
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


@pytest.mark.parametrize("recover_on", ["read", "write"])
def test_cache_recovers_when_schema_is_corrupted_while_open(
    tmp_path, recover_on
) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "before", {"ok": True}, positive=True)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("DROP TABLE cache_entries")

        if recover_on == "read":
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

    assert elapsed < 1.0
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


def test_cache_path_override_is_explicit_and_platform_independent(
    monkeypatch, tmp_path
) -> None:
    configured = tmp_path / "configured.sqlite3"
    explicit = tmp_path / "explicit.sqlite3"
    monkeypatch.setenv("CONDA_ADVISE_CACHE_PATH", str(configured))
    with AdvisoryCache() as cache:
        assert cache.path == configured
    with AdvisoryCache(explicit) as cache:
        assert cache.path == explicit


@pytest.mark.parametrize("stored", [False, True], ids=["new-response", "legacy-row"])
@pytest.mark.parametrize("text", ["a" * 101, "é" * 51], ids=["ascii", "multibyte"])
def test_cache_rejects_oversized_entries_before_json_decoding(
    monkeypatch, tmp_path, stored, text
) -> None:
    monkeypatch.setattr(cache_module, "MAX_ENTRY_BYTES", 100)
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "key", {"ok": True}, positive=True)
        if stored:
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE cache_entries SET payload = ?",
                    ('{"data":"' + text + '"}',),
                )
                connection.commit()

            def forbidden(*args, **kwargs):
                pytest.fail("oversized cache data reached JSON decoding")

            monkeypatch.setattr(cache_module.json, "loads", forbidden)
            assert cache.get("source", "key") is None
        else:
            cache.put("source", "large", {"data": text}, positive=True)
            assert cache.get("source", "large") is None
            assert cache.get("source", "key").payload == {"ok": True}


@pytest.mark.parametrize(
    "limit", ["count", "bytes"], ids=["entry-count", "storage-bytes"]
)
def test_cache_evicts_old_entries_and_reuses_disk_space(
    monkeypatch, tmp_path, limit
) -> None:
    monkeypatch.setattr(
        cache_module, "MAX_CACHE_ENTRIES", 3 if limit == "count" else 1000
    )
    monkeypatch.setattr(
        cache_module, "MAX_CACHE_BYTES", 10_000 if limit == "count" else 170
    )
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        for index in range(100):
            cache.put(
                "source",
                f"key-{index}",
                {"value": "a" * 40},
                positive=True,
                now=index + 100,
            )
        assert cache.get("source", "key-0", now=200) is None
        assert cache.get("source", "key-99", now=200) is not None
        with closing(sqlite3.connect(path)) as connection:
            count, size = connection.execute(
                "SELECT count(*), sum(length(CAST(payload AS BLOB)) "
                "+ length(source) + length(cache_key)) FROM cache_entries"
            ).fetchone()
        assert count <= cache_module.MAX_CACHE_ENTRIES
        assert size <= cache_module.MAX_CACHE_BYTES
    assert path.stat().st_size < 128 * 1024


def test_cache_prunes_expired_revisions(monkeypatch, tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        for index in range(10):
            cache.put(
                "osv.detail",
                f"id:{index}",
                {"id": "id", "modified": index},
                positive=True,
                now=index * 10,
                ttl=1,
                stale_positive_ttl=2,
            )
        count = cache._connection.execute(
            "SELECT count(*) FROM cache_entries"
        ).fetchone()[0]
        assert count == 1


@pytest.mark.parametrize("field", ["source", "key"])
def test_cache_rejects_oversized_identifiers(tmp_path, field) -> None:
    identifiers = {"source": "source", "key": "key"}
    identifiers[field] = "x" * 16_385
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("source", "key", {"value": "existing"}, positive=True)
        cache.put(**identifiers, payload={"value": "rejected"}, positive=True)

        assert cache.get("source", "key").payload == {"value": "existing"}
        count = cache._connection.execute(
            "SELECT count(*) FROM cache_entries"
        ).fetchone()[0]
        assert count == 1


def test_cache_refuses_writes_while_a_reader_prevents_wal_truncation(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(cache_module, "MAX_WAL_BYTES", 4096)
    monkeypatch.setattr(cache_module, "_BUSY_TIMEOUT_SECONDS", 0.0)
    path = tmp_path / "cache.sqlite3"
    wal = tmp_path / "cache.sqlite3-wal"
    with AdvisoryCache(path) as cache:
        cache.put("source", "existing", {"value": "before"}, positive=True)
        with closing(sqlite3.connect(path)) as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT payload FROM cache_entries").fetchall()
            with cache._connection:
                cache._connection.execute(
                    "UPDATE cache_entries SET payload = ?",
                    ('{"value":"' + "x" * 10_000 + '"}',),
                )
            size_before = wal.stat().st_size
            assert size_before > cache_module.MAX_WAL_BYTES

            cache.put("source", "blocked", {"ok": True}, positive=True)

            assert cache.get("source", "blocked") is None
            assert wal.stat().st_size == size_before

        cache.put("source", "after", {"ok": True}, positive=True)

        assert cache.get("source", "after").payload == {"ok": True}
        assert wal.stat().st_size <= cache_module.MAX_WAL_BYTES


def test_cache_shrinks_an_oversized_legacy_database(monkeypatch, tmp_path) -> None:
    path = tmp_path / "cache.sqlite3"
    with AdvisoryCache(path) as cache:
        cache.put("source", "fresh", {"ok": True}, positive=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "INSERT INTO cache_entries VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("source", "expired", 1, '"' + "x" * 200_000 + '"', 0, 1, 2),
        )
        connection.commit()
    monkeypatch.setattr(cache_module, "MAX_DATABASE_BYTES", 64 * 1024)
    assert path.stat().st_size > cache_module.MAX_DATABASE_BYTES

    with AdvisoryCache(path) as cache:
        assert cache.get("source", "expired") is None
        assert cache.get("source", "fresh").payload == {"ok": True}
        page_size = cache._connection.execute("PRAGMA page_size").fetchone()[0]
        page_limit = cache._connection.execute("PRAGMA max_page_count").fetchone()[0]
        assert page_size * page_limit <= cache_module.MAX_DATABASE_BYTES

    assert path.stat().st_size <= cache_module.MAX_DATABASE_BYTES


def test_cache_keeps_existing_entry_when_integer_serialization_fails(tmp_path) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("source", "key", {"value": "existing"}, positive=True)
        previous_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(640)
            cache.put("source", "key", {"value": 10**1000}, positive=True)
        finally:
            sys.set_int_max_str_digits(previous_limit)

        assert cache.get("source", "key").payload == {"value": "existing"}


def test_cache_keeps_existing_entry_when_serialization_reaches_deadline(
    monkeypatch, tmp_path
) -> None:
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put("source", "key", {"value": "existing"}, positive=True)
        cache.deadline = 5.0
        instants = iter((0.0, 0.0, 0.0, 5.0))
        with monkeypatch.context() as clock:
            clock.setattr(time, "monotonic", lambda: next(instants))
            cache.put("source", "key", {"value": "replacement"}, positive=True)
        cache.deadline = None

        assert cache.get("source", "key").payload == {"value": "existing"}
