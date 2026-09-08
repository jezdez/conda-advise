from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit

from conda.base.constants import KNOWN_SUBDIRS
from conda.common.url import join_url, split_anaconda_token
from conda.exceptions import InvalidMatchSpec, InvalidVersionSpec
from conda.models.match_spec import MatchSpec
from conda.models.version import VersionOrder

from .models import Subject

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import TypeGuard

    from conda.models.records import PackageRecord

DEFAULT_CONDA_FORGE_ORIGINS = (
    "https://conda.anaconda.org/conda-forge",
    "https://prefix.dev/conda-forge",
)
MAX_URL_LENGTH = 8192
MAX_DECODE_PASSES = 8


def sanitize_url(value: str) -> str:
    if not value or len(value) > MAX_URL_LENGTH:
        return ""
    try:
        without_token, _ = split_anaconda_token(value)
        parsed = urlsplit(without_token)
        if not parsed.hostname:
            return ""
        hostname = parsed.hostname.lower()
        port = parsed.port
    except (UnicodeError, ValueError):
        return ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))


def is_allowed_origin(
    value: str,
    origins: Sequence[str] = DEFAULT_CONDA_FORGE_ORIGINS,
) -> bool:
    candidate = _normalized_url(value)
    if candidate is None:
        return False
    for origin in origins:
        allowed = _normalized_url(origin)
        if allowed is None or not _secure_origin(allowed):
            continue
        if candidate.scheme != allowed.scheme or candidate.netloc != allowed.netloc:
            continue
        allowed_path = allowed.path.rstrip("/")
        if candidate.path == allowed_path or candidate.path.startswith(
            f"{allowed_path}/"
        ):
            return True
    return False


def _secure_origin(value: SplitResult) -> bool:
    return value.scheme == "https" or (
        value.scheme == "http" and value.hostname in {"127.0.0.1", "::1", "localhost"}
    )


def validate_endpoint(value: str) -> str:
    sanitized = sanitize_url(value).rstrip("/")
    parsed = urlsplit(sanitized)
    if parsed.scheme == "https" and parsed.hostname:
        return sanitized
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}:
        return sanitized
    raise ValueError("provider endpoints must use HTTPS or a loopback HTTP address")


def sanitize_channel_name(value: str) -> str:
    if len(value) > MAX_URL_LENGTH:
        return ""
    try:
        without_token, _ = split_anaconda_token(value)
    except (UnicodeError, ValueError):
        return ""
    if "://" in without_token or without_token.startswith("//"):
        return sanitize_url(without_token)
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._/-]*", without_token):
        return without_token
    return ""


def is_recognized_subject(subject: Subject) -> bool:
    if (
        not is_valid_text(subject.name)
        or not is_valid_text(subject.version)
        or re.fullmatch(r"[a-z0-9_][a-z0-9._-]*", subject.name) is None
        or subject.subdir not in KNOWN_SUBDIRS
    ):
        return False
    try:
        normalized_name = MatchSpec(subject.name).name
        VersionOrder(subject.version)
    except (InvalidMatchSpec, InvalidVersionSpec):
        return False
    return normalized_name == subject.name


def subject_from_record(record: PackageRecord) -> Subject:
    try:
        raw_url = str(record.url or "")
        channel_object = record.channel
        filename = str(record.fn or "")
        canonical_name = channel_object.canonical_name
        channel = sanitize_channel_name(str(canonical_name or ""))
        if not raw_url and channel:
            base_url = channel_object.base_url
            if base_url and record.subdir and filename:
                raw_url = join_url(base_url, record.subdir, filename)
        url = sanitize_url(raw_url)
        if not filename and url:
            filename = PurePosixPath(unquote(urlsplit(url).path)).name
        return Subject(
            name=str(record.name),
            version=str(record.version),
            build=str(record.build),
            build_number=int(record.build_number or 0),
            subdir=str(record.subdir or ""),
            channel=channel,
            url=url,
            filename=filename,
            sha256=_normalize_digest(record.sha256, length=64),
            md5=_normalize_digest(record.md5, length=32),
        )
    except Exception:
        # Conda lazily derives channel and filename fields from credential-bearing URLs.
        raise ValueError("package record contains invalid metadata") from None


def _normalize_digest(value: object, *, length: int) -> str | None:
    if not isinstance(value, str) or len(value) != length:
        return None
    if any(character not in "0123456789abcdefABCDEF" for character in value):
        return None
    return value.lower()


def is_valid_text(value: object) -> TypeGuard[str]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 16_384
        or value != value.strip()
    ):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _normalized_url(value: str) -> SplitResult | None:
    parsed = urlsplit(sanitize_url(value))
    if not parsed.scheme or not parsed.hostname:
        return None
    path = _normalized_path(parsed.path)
    if path is None:
        return None
    return SplitResult(
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path.rstrip("/"),
        "",
        "",
    )


def _normalized_path(value: str) -> str | None:
    if len(value) > MAX_URL_LENGTH:
        return None
    decoded = value
    for _ in range(MAX_DECODE_PASSES):
        if "\\" in decoded or any(part in {".", ".."} for part in decoded.split("/")):
            return None
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        if next_value.count("/") != decoded.count("/"):
            return None
        decoded = next_value
    else:
        return None
    return "/" + "/".join(part for part in decoded.split("/") if part)
