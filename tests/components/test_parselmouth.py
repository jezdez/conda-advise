from __future__ import annotations

import time

import pytest

import conda_advise.components.parselmouth as parselmouth
from conda_advise.cache import AdvisoryCache
from conda_advise.models import CoverageStatus, FailureReason, Subject
from conda_advise.network import JsonResponse


def make_subject(*, sha256: str | None = "a" * 64) -> Subject:
    return Subject(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        subdir="noarch",
        channel="conda-forge",
        url="https://conda.anaconda.org/conda-forge/noarch/demo.conda",
        filename="demo.conda",
        sha256=sha256,
    )


@pytest.mark.parametrize(
    ("payload", "status", "reason"),
    [
        (
            {"pypi_normalized_names": [], "versions": {}},
            CoverageStatus.NOT_CHECKED,
            FailureReason.NO_COMPONENTS,
        ),
        (
            {"pypi_normalized_names": None, "versions": None},
            CoverageStatus.NOT_CHECKED,
            FailureReason.NO_COMPONENTS,
        ),
        (
            {"pypi_normalized_names": "demo", "versions": []},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        ({}, CoverageStatus.INCOMPLETE, FailureReason.INVALID_RESPONSE),
        (
            {"unexpected": True},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": None, "versions": {}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": [], "versions": None},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": ["demo"], "versions": {}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": [], "versions": {"demo": "1.0"}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": [""], "versions": {"": "1.0"}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": ["   "], "versions": {"   ": "1.0"}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": ["demo"], "versions": {"demo": "   "}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": ["demo"], "versions": {"demo": " 1.0 "}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {
                "pypi_normalized_names": ["demo"],
                "versions": {"demo": "1.0\nsecret"},
            },
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0\x00x"}},
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
        (
            {
                "pypi_normalized_names": ["demo"],
                "versions": {"demo": "\ud800"},
            },
            CoverageStatus.INCOMPLETE,
            FailureReason.INVALID_RESPONSE,
        ),
    ],
    ids=[
        "valid-empty",
        "parselmouth-null-empty",
        "malformed-fields",
        "missing-fields",
        "unexpected-fields",
        "null-names-only",
        "null-versions-only",
        "missing-component-version",
        "unlisted-component-version",
        "empty-name",
        "whitespace-name",
        "whitespace-version",
        "padded-version",
        "newline-version",
        "nul-version",
        "invalid-unicode-version",
    ],
)
def test_discover_components_distinguishes_empty_and_malformed(
    monkeypatch, tmp_path, payload, status, reason
) -> None:
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, payload, 200)
        },
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = parselmouth.discover_components(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.coverage[0].status is status
    assert result.coverage[0].reason is reason


@pytest.mark.parametrize(
    "payload",
    [
        {"pypi_normalized_names": [], "versions": {}},
        {"pypi_normalized_names": None, "versions": None},
    ],
    ids=["empty-containers", "parselmouth-null-empty"],
)
def test_discover_components_reuses_valid_empty_mapping(
    monkeypatch, tmp_path, payload
) -> None:
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, payload, 200)
        },
    )
    subject = make_subject()
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )
        monkeypatch.setattr(
            parselmouth,
            "fetch_json",
            lambda requests, **options: pytest.fail("fresh empty mapping was ignored"),
        )
        cached = parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert cached.coverage[0].status is CoverageStatus.NOT_CHECKED
    assert cached.coverage[0].reason is FailureReason.NO_COMPONENTS


def test_discover_components_treats_404_as_unmapped(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, None, 404)
        },
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = parselmouth.discover_components(
            [make_subject()],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.coverage[0].status is CoverageStatus.NOT_CHECKED
    assert result.coverage[0].reason is FailureReason.COMPONENT_NOT_MAPPED
    assert result.failures == ()


def test_discover_components_requires_sha256_without_network(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: pytest.fail("network should not be scheduled"),
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = parselmouth.discover_components(
            [make_subject(sha256=None)],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.coverage[0].reason is FailureReason.MISSING_SHA256


def test_discover_components_preserves_renamed_and_vendored_components(
    monkeypatch, tmp_path
) -> None:
    payload = {
        "pypi_normalized_names": ["Renamed_Project", "vendored-lib"],
        "versions": {"Renamed_Project": "1.0", "vendored-lib": "2.0"},
    }
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, payload, 200)
        },
    )
    subject = make_subject()

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        result = parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert {item.purl for item in result.components[subject.identifier]} == {
        "pkg:pypi/renamed-project@1.0",
        "pkg:pypi/vendored-lib@2.0",
    }


def test_discover_components_uses_stale_positive_after_failure(
    monkeypatch, tmp_path
) -> None:
    payload = {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0"}}
    subject = make_subject()
    now = time.time()
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(
                requests[0].key,
                None,
                503,
                FailureReason.REQUEST_FAILED,
                "failed",
            )
        },
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            f"parselmouth:{parselmouth.DEFAULT_PARSELMOUTH_URL}",
            subject.sha256,
            payload,
            positive=True,
            now=now - 2,
            ttl=1,
            stale_positive_ttl=10,
        )
        result = parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.components[subject.identifier]
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].stale


def test_discover_components_uses_stale_positive_after_malformed_success(
    monkeypatch, tmp_path
) -> None:
    payload = {"pypi_normalized_names": ["demo"], "versions": {"demo": "1.0"}}
    subject = make_subject()
    monkeypatch.setattr(
        parselmouth,
        "fetch_json",
        lambda requests, **options: {
            requests[0].key: JsonResponse(requests[0].key, {"unexpected": True}, 200)
        },
    )

    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            f"parselmouth:{parselmouth.DEFAULT_PARSELMOUTH_URL}",
            subject.sha256,
            payload,
            positive=True,
            now=time.time() - 2,
            ttl=1,
            stale_positive_ttl=10,
        )
        result = parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert result.components[subject.identifier]
    assert result.coverage[0].status is CoverageStatus.INCOMPLETE
    assert result.coverage[0].reason is FailureReason.INVALID_RESPONSE
    assert result.coverage[0].stale


def test_discover_components_does_not_reuse_expired_negative(
    monkeypatch, tmp_path
) -> None:
    calls = []
    subject = make_subject()

    def fetch(requests, **options):
        calls.extend(request.key for request in requests)
        return {requests[0].key: JsonResponse(requests[0].key, None, 404)}

    monkeypatch.setattr(parselmouth, "fetch_json", fetch)
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        cache.put(
            f"parselmouth:{parselmouth.DEFAULT_PARSELMOUTH_URL}",
            subject.sha256,
            {},
            positive=False,
            now=time.time() - 2,
            ttl=1,
        )
        parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
        )

    assert calls == [subject.sha256]


def test_discover_components_separates_configured_endpoint_caches(
    monkeypatch, tmp_path
) -> None:
    calls = []

    def fetch(requests, **options):
        request = requests[0]
        calls.append(request.url)
        name = "first" if ":8001/" in request.url else "second"
        payload = {
            "pypi_normalized_names": [name],
            "versions": {name: "1.0"},
        }
        return {request.key: JsonResponse(request.key, payload, 200)}

    monkeypatch.setattr(parselmouth, "fetch_json", fetch)
    subject = make_subject()
    with AdvisoryCache(tmp_path / "cache.sqlite3") as cache:
        parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            base_url="http://localhost:8001",
        )
        second = parselmouth.discover_components(
            [subject],
            cache=cache,
            deadline=time.monotonic() + 1,
            offline=False,
            refresh=False,
            base_url="http://localhost:8002",
        )

    assert len(calls) == 2
    assert second.components[subject.identifier][0].name == "second"
