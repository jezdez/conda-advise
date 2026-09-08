from __future__ import annotations

import pytest

from conda_advise.matching import AdvisoryMatch, build_findings, mark_kev
from conda_advise.models import (
    Evidence,
    EvidenceType,
    ProviderName,
    Severity,
    Subject,
)


def make_subject() -> Subject:
    return Subject(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        subdir="noarch",
        channel="conda-forge",
        url="https://conda.anaconda.org/conda-forge/noarch/demo.conda",
        filename="demo.conda",
        sha256="a" * 64,
    )


def make_match(
    payload: dict[str, object],
    *,
    evidence_type: EvidenceType = EvidenceType.ARTIFACT_COMPONENT,
    source_url: str = "https://mirror.example/v1/vulns/id",
) -> AdvisoryMatch:
    subject = make_subject()
    return AdvisoryMatch(
        subject=subject,
        provider=ProviderName.OSV,
        payload=payload,
        evidence=Evidence(
            type=evidence_type,
            provider=ProviderName.OSV,
            artifact_sha256=subject.sha256,
            component_purl="pkg:pypi/demo@1.0",
        ),
        queried_purl="pkg:pypi/demo@1.0",
        source_url=source_url,
    )


def test_aliases_merge_transitively_but_related_ids_do_not() -> None:
    common = {
        "modified": "2026-01-01T00:00:00Z",
        "summary": "Example",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
    }
    findings = build_findings(
        [
            make_match(
                {**common, "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1"]}
            ),
            make_match({**common, "id": "PYSEC-2026-1", "aliases": ["CVE-2026-1"]}),
            make_match({**common, "id": "OTHER-1", "related": ["CVE-2026-1"]}),
        ]
    )

    assert len(findings) == 2
    merged = next(finding for finding in findings if finding.id == "CVE-2026-1")
    assert merged.aliases == ("GHSA-aaaa-bbbb-cccc", "PYSEC-2026-1")
    assert len(merged.source_records) == 2
    assert merged.severity is Severity.CRITICAL
    assert merged.score == 9.8


def test_moderate_provider_label_maps_to_medium() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "modified": "2026-01-01T00:00:00Z",
                    "database_specific": {"severity": "MODERATE"},
                }
            )
        ]
    )

    assert findings[0].severity is Severity.MEDIUM


def test_numeric_zero_score_takes_precedence_over_provider_label() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "severity": [{"type": "CVSS_V3", "score": "0"}],
                    "database_specific": {"severity": "HIGH"},
                }
            )
        ]
    )

    assert findings[0].score == 0
    assert findings[0].severity is Severity.UNKNOWN
    assert not findings[0].qualifies(Severity.LOW)


@pytest.mark.parametrize(
    ("vectors", "expected"),
    [
        ([{"type": "CVSS_V2", "score": "10.0"}], Severity.HIGH),
        (
            [{"type": "CVSS_V2", "score": "10.0"}, {"type": "CVSS_V3", "score": "9.8"}],
            Severity.CRITICAL,
        ),
        (
            [{"type": "CVSS_V4", "score": "9.1"}, {"type": "CVSS_V2", "score": "10.0"}],
            Severity.CRITICAL,
        ),
    ],
    ids=["v2-only", "v2-and-v3", "v4-and-v2"],
)
def test_cvss_severity_uses_each_vectors_version(vectors, expected) -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "severity": vectors,
                }
            )
        ]
    )

    assert findings[0].score == 10
    assert findings[0].severity is expected
    assert findings[0].qualifies(Severity.CRITICAL) is (expected is Severity.CRITICAL)


def test_non_cvss_numeric_score_is_preserved_without_a_base_score() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "severity": [{"type": "EPSS", "score": "10"}],
                }
            )
        ]
    )

    assert findings[0].score is None
    assert findings[0].severity is Severity.UNKNOWN
    assert findings[0].source_records[0].severity[0].base_score is None


@pytest.mark.parametrize(
    "score",
    ["garbage", "NaN", "Infinity", "-1", "99"],
    ids=["malformed-vector", "nan", "infinity", "negative", "above-ten"],
)
def test_invalid_cvss_scores_are_retained_without_a_numeric_score(score: str) -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "severity": [{"type": "CVSS_V3", "score": score}],
                }
            )
        ]
    )

    assert findings[0].score is None
    assert findings[0].severity is Severity.UNKNOWN
    assert findings[0].source_records[0].severity[0].base_score is None


def test_source_record_keeps_configured_detail_url_and_all_fix_versions() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "demo"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"fixed": "2.0"}, {"fixed": "3.0"}],
                                }
                            ],
                        }
                    ],
                },
                source_url="https://self-hosted.example/v1/vulns/CVE-2026-1",
            )
        ]
    )

    assert findings[0].fixes == ("2.0", "3.0")
    assert findings[0].source_records[0].url == (
        "https://self-hosted.example/v1/vulns/CVE-2026-1"
    )


def test_affected_metadata_is_limited_to_the_queried_package() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "other"},
                            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"fixed": "99.0"}],
                                }
                            ],
                        },
                        {
                            "package": {
                                "purl": "pkg:pypi/Demo",
                                "ecosystem": "PyPI",
                                "name": "Demo",
                            },
                            "severity": [{"type": "CVSS_V3", "score": "5.5"}],
                            "ranges": [
                                {
                                    "type": "GIT",
                                    "events": [{"fixed": "deadbeef"}],
                                },
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"fixed": "2.0"}],
                                },
                            ],
                        },
                    ],
                }
            )
        ]
    )

    assert findings[0].score == 5.5
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].fixes == ("2.0",)


def test_withdrawn_records_are_excluded() -> None:
    findings = build_findings(
        [
            make_match(
                {
                    "id": "CVE-2026-1",
                    "modified": "2026-01-01T00:00:00Z",
                    "withdrawn": "2026-02-01T00:00:00Z",
                }
            )
        ]
    )

    assert findings == ()


def test_kev_alias_always_qualifies_and_stale_catalog_marks_finding() -> None:
    finding = build_findings(
        [
            make_match(
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2026-1"],
                    "modified": "2026-01-01T00:00:00Z",
                }
            )
        ]
    )

    marked = mark_kev(finding, {"CVE-2026-1"}, stale=True)

    assert marked[0].kev
    assert marked[0].stale
    assert marked[0].qualifies(Severity.CRITICAL)
