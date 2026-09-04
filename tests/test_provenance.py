from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from conda.models.records import PackageRecord

from conda_advise.provenance import (
    is_allowed_origin,
    is_recognized_subject,
    sanitize_channel_name,
    sanitize_url,
    subject_from_record,
    validate_endpoint,
)


@dataclass
class FakeChannel:
    canonical_name: str = "conda-forge"


@dataclass
class FakeRecord:
    name: str = "demo"
    version: str = "1.0"
    build: str = "py_0"
    build_number: int = 0
    subdir: str = "noarch"
    channel: FakeChannel = field(default_factory=FakeChannel)
    fn: str = "demo-1.0-py_0.conda"
    sha256: str = "a" * 64
    md5: str = "b" * 32
    url: str = (
        "https://user:password@conda.anaconda.org/t/tk-secret/conda-forge/"
        "noarch/demo-1.0-py_0.conda?token=query-secret#fragment-secret"
    )


def test_subject_from_record_removes_every_credential_form() -> None:
    subject = subject_from_record(FakeRecord())

    assert subject.url == (
        "https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda"
    )
    assert is_allowed_origin(subject.url)
    serialized = repr(subject.to_dict())
    for secret in ("user", "password", "tk-secret", "query-secret", "fragment-secret"):
        assert secret not in serialized


def test_subject_from_record_uses_channel_base_url_and_record_subdir() -> None:
    record = PackageRecord(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        channel="https://conda.anaconda.org/conda-forge",
        subdir="noarch",
        fn="demo-1.0-py_0.conda",
        sha256="a" * 64,
    )

    subject = subject_from_record(record)

    assert subject.url == (
        "https://conda.anaconda.org/conda-forge/noarch/demo-1.0-py_0.conda"
    )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("sha256", "A1" * 32, "a1" * 32),
        ("md5", "B2" * 16, "b2" * 16),
        ("sha256", "a" * 63, None),
        ("sha256", "a" * 65, None),
        ("sha256", "g" * 64, None),
        ("sha256", b"a" * 64, None),
        ("md5", "b" * 31, None),
        ("md5", "b" * 33, None),
        ("md5", "z" * 32, None),
        ("md5", b"b" * 32, None),
    ],
    ids=[
        "uppercase-sha256",
        "uppercase-md5",
        "short-sha256",
        "long-sha256",
        "non-hex-sha256",
        "bytes-sha256",
        "short-md5",
        "long-md5",
        "non-hex-md5",
        "bytes-md5",
    ],
)
def test_subject_from_record_normalizes_digests(
    field: str, value: object, expected: str | None
) -> None:
    record = FakeRecord()
    setattr(record, field, value)

    subject = subject_from_record(record)

    assert getattr(subject, field) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://conda.anaconda.org/conda-forge", True),
        ("https://conda.anaconda.org/conda-forge/label/dev/noarch/a.conda", True),
        ("https://prefix.dev/conda-forge/osx-arm64/a.conda", True),
        ("https://conda.anaconda.org/conda-forge-malicious/a.conda", False),
        ("https://conda.anaconda.org.evil.example/conda-forge/a.conda", False),
        ("https://conda.anaconda.org/conda-forge/../pkgs/main/a.conda", False),
        ("https://conda.anaconda.org/conda-forge/%2e%2e/pkgs/main/a.conda", False),
        ("https://conda.anaconda.org/conda-forge/%252e%252e/a.conda", False),
        ("https://conda.anaconda.org/conda-forge/%2f..%2fpkgs/a.conda", False),
        ("https://conda.anaconda.org/conda-forge\\..\\pkgs\\a.conda", False),
        ("http://conda.anaconda.org/conda-forge/a.conda", False),
        ("file:///tmp/a.conda", False),
    ],
    ids=[
        "channel-root",
        "label",
        "prefix-mirror",
        "path-spoof",
        "host-spoof",
        "dot-segment",
        "encoded-dot-segment",
        "double-encoded-dot-segment",
        "encoded-separator",
        "backslash-separator",
        "plain-http",
        "local-file",
    ],
)
def test_is_allowed_origin_matches_exact_https_paths(url: str, expected: bool) -> None:
    assert is_allowed_origin(url) is expected


def test_is_allowed_origin_accepts_only_explicit_loopback_http() -> None:
    value = "http://127.0.0.1:8765/channel/noarch/demo.conda"

    assert not is_allowed_origin(value)
    assert is_allowed_origin(value, ("http://127.0.0.1:8765/channel",))
    assert not is_allowed_origin(
        "http://mirror.example/conda-forge/noarch/demo.conda",
        ("http://mirror.example/conda-forge",),
    )


@pytest.mark.parametrize(
    ("name", "version", "subdir", "expected"),
    [
        ("demo-package", "1.0+local", "noarch", True),
        ("demo-package", "1.0", "win-arm64", True),
        ("_libgcc_mutex", "0.1", "linux-64", True),
        ("Demo-Package", "1.0", "noarch", False),
        ("foo?", "1.0", "noarch", False),
        ("foo|bar", "1.0", "noarch", False),
        ("foo,bar", "1.0", "noarch", False),
        ("foo/../bar", "1.0", "noarch", False),
        (r"foo\bar", "1.0", "noarch", False),
        ("foo@bar", "1.0", "noarch", False),
        ("foo%bar", "1.0", "noarch", False),
        ("", "1.0", "noarch", False),
        ("demo-package", "", "noarch", False),
        ("demo-package", " 1.0 ", "noarch", False),
        ("demo-package", "1.0\n", "noarch", False),
        ("demo-package", "1.0", "unknown-arch", False),
    ],
    ids=[
        "canonical",
        "windows-arm64",
        "leading-underscore",
        "uppercase-name",
        "question-mark",
        "pipe",
        "comma",
        "path-traversal",
        "backslash",
        "at-sign",
        "percent-sign",
        "empty-name",
        "empty-version",
        "padded-version",
        "control-character",
        "unknown-subdir",
    ],
)
def test_is_recognized_subject_uses_conda_platform_directories(
    name: str,
    version: str,
    subdir: str,
    expected: bool,
) -> None:
    subject = subject_from_record(FakeRecord(name=name, version=version, subdir=subdir))

    assert is_recognized_subject(subject) is expected


@pytest.mark.parametrize(
    "url",
    ["http://example.com", "file:///tmp/service", "not-a-url"],
    ids=["remote-http", "file", "relative"],
)
def test_validate_endpoint_rejects_non_https_remote_urls(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        validate_endpoint(url)


def test_validate_endpoint_accepts_loopback_http() -> None:
    assert validate_endpoint("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"


def test_sanitize_url_removes_anaconda_path_token_without_touching_filename() -> None:
    value = "https://repo.example/t/token/conda-forge/noarch/t/token.conda"

    assert sanitize_url(value) == (
        "https://repo.example/conda-forge/noarch/t/token.conda"
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "http://user:password@[::1]:8765/api?token=secret#fragment",
            "http://[::1]:8765/api",
        ),
        (
            "https://user:password@[2001:db8::1]/api?token=secret#fragment",
            "https://[2001:db8::1]/api",
        ),
    ],
    ids=["loopback", "public"],
)
def test_sanitize_url_preserves_bracketed_ipv6_hosts(url: str, expected: str) -> None:
    assert sanitize_url(url) == expected


def test_validate_endpoint_accepts_bracketed_ipv6_loopback() -> None:
    assert validate_endpoint("http://[::1]:8765/api") == "http://[::1]:8765/api"


def test_sanitize_url_rejects_invalid_ports() -> None:
    assert sanitize_url("https://conda.anaconda.org:not-a-port/conda-forge") == ""


@pytest.mark.parametrize(
    "url",
    ["https://user:secret@", "//user:secret@", "user:secret@"],
    ids=["scheme", "authority", "relative"],
)
def test_sanitize_url_never_returns_credentials_from_malformed_urls(url: str) -> None:
    sanitized = sanitize_url(url)

    assert "user" not in sanitized
    assert "secret" not in sanitized


@pytest.mark.parametrize(
    "channel",
    ["//user:secret@", "user:secret@"],
    ids=["authority", "relative"],
)
def test_subject_from_record_redacts_malformed_channel_credentials(
    channel: str,
) -> None:
    record = PackageRecord(
        name="demo",
        version="1.0",
        build="py_0",
        build_number=0,
        channel=channel,
        subdir="noarch",
        fn="demo-1.0-py_0.conda",
        url="",
        sha256="a" * 64,
    )

    subject = subject_from_record(record)
    serialized = repr(subject.to_dict())

    assert "secret" not in serialized
    assert sanitize_channel_name(subject.channel) == subject.channel
