"""Conda plugin registration with lazy implementation imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from conda.plugins import hookimpl

if TYPE_CHECKING:
    from collections.abc import Iterable

    from conda.models.records import PackageRecord
    from conda.plugins.types import CondaPostSolve, CondaSetting, CondaSubcommand


PROVIDER_SETTING = "conda_advise_provider"
POST_SOLVE_SETTING = "conda_advise_post_solve"
MINIMUM_SEVERITY_SETTING = "conda_advise_minimum_severity"
TIMEOUT_SETTING = "conda_advise_timeout_seconds"
ORIGINS_SETTING = "conda_advise_conda_forge_origins"
OSV_URL_SETTING = "conda_advise_osv_url"
PARSELMOUTH_URL_SETTING = "conda_advise_parselmouth_url"
BASILISK_URL_SETTING = "conda_advise_basilisk_url"

DEFAULT_ORIGINS = (
    "https://conda.anaconda.org/conda-forge",
    "https://prefix.dev/conda-forge",
)
DEFAULT_OSV_URL = "https://api.osv.dev"
DEFAULT_PARSELMOUTH_URL = "https://conda-mapping.prefix.dev"
DEFAULT_BASILISK_URL = "https://api.basilisk.prefix.dev"


@hookimpl
def conda_subcommands() -> Iterable[CondaSubcommand]:
    from conda.plugins.types import CondaSubcommand

    from .cli import configure_parser, execute

    yield CondaSubcommand(
        name="advise",
        summary="Report advisory matches and coverage for a conda environment.",
        action=execute,
        configure_parser=configure_parser,
    )
    yield CondaSubcommand(
        name="advice",
        summary="Alias for 'conda advise'.",
        action=execute,
        configure_parser=configure_parser,
    )


@hookimpl
def conda_settings() -> Iterable[CondaSetting]:
    from urllib.parse import urlsplit

    from conda.common.configuration import PrimitiveParameter, SequenceParameter
    from conda.plugins.types import CondaSetting

    def choice(*choices: str):
        return lambda value: value in choices or f"must be one of: {', '.join(choices)}"

    def positive_timeout(value: int) -> bool | str:
        return (
            not isinstance(value, bool) and 1 <= value <= 30
        ) or "must be an integer from 1 through 30"

    def secure_url(value: str) -> bool | str:
        parsed = urlsplit(value)
        try:
            parsed.port
        except ValueError:
            return "must contain a valid port"
        is_loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        valid = (
            bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and (parsed.scheme == "https" or (parsed.scheme == "http" and is_loopback))
        )
        return valid or (
            "must be HTTPS, or HTTP on an exact loopback host, without credentials, "
            "query, or fragment"
        )

    def secure_urls(values: tuple[str, ...]) -> bool | str:
        return all(secure_url(value) is True for value in values) or (
            "must contain only HTTPS URLs, or HTTP URLs on exact loopback hosts, "
            "without credentials, queries, or fragments"
        )

    yield CondaSetting(
        name=PROVIDER_SETTING,
        description=(
            "Advisory provider used by conda-advise. "
            "The basilisk provider is experimental."
        ),
        parameter=PrimitiveParameter(
            "osv",
            element_type=str,
            validation=choice("osv", "basilisk"),
        ),
    )
    yield CondaSetting(
        name=POST_SOLVE_SETTING,
        description="Run conda-advise after solving package transactions.",
        parameter=PrimitiveParameter(
            "warn",
            element_type=str,
            validation=choice("off", "warn"),
        ),
    )
    yield CondaSetting(
        name=MINIMUM_SEVERITY_SETTING,
        description="Minimum advisory severity that qualifies a match.",
        parameter=PrimitiveParameter(
            "high",
            element_type=str,
            validation=choice("low", "medium", "high", "critical"),
        ),
    )
    yield CondaSetting(
        name=TIMEOUT_SETTING,
        description="Advisory scan deadline for manual and post-solve scans.",
        parameter=PrimitiveParameter(
            5,
            element_type=int,
            validation=positive_timeout,
        ),
    )
    yield CondaSetting(
        name=ORIGINS_SETTING,
        description="Artifact origins eligible for advisory provider requests.",
        parameter=SequenceParameter(
            PrimitiveParameter("", element_type=str),
            default=DEFAULT_ORIGINS,
            validation=secure_urls,
        ),
    )
    for name, description, default in (
        (OSV_URL_SETTING, "Base URL for the OSV API.", DEFAULT_OSV_URL),
        (
            PARSELMOUTH_URL_SETTING,
            "Base URL for the Parselmouth mapping API.",
            DEFAULT_PARSELMOUTH_URL,
        ),
        (
            BASILISK_URL_SETTING,
            "Base URL for the experimental Basilisk API.",
            DEFAULT_BASILISK_URL,
        ),
    ):
        yield CondaSetting(
            name=name,
            description=description,
            parameter=PrimitiveParameter(
                default,
                element_type=str,
                validation=secure_url,
            ),
        )


@hookimpl
def conda_post_solves() -> Iterable[CondaPostSolve]:
    from conda.plugins.types import CondaPostSolve

    yield CondaPostSolve(
        name="conda-advise",
        action=_post_solve,
    )


def _post_solve(
    repodata_fn: str,
    unlink_precs: tuple[PackageRecord, ...],
    link_precs: tuple[PackageRecord, ...],
) -> None:
    """Warn about qualifying matches without interrupting the transaction."""
    del repodata_fn, unlink_precs

    try:
        from conda.base.context import context

        settings = context.plugins
        if getattr(settings, POST_SOLVE_SETTING) == "off" or not link_precs:
            return

        from .reporting import apply_metadata_tags, render_hook_warning
        from .scanner import scan_records

        report = scan_records(
            link_precs,
            provider=getattr(settings, PROVIDER_SETTING),
            offline=context.offline,
            minimum_severity=getattr(settings, MINIMUM_SEVERITY_SETTING),
            timeout_seconds=float(getattr(settings, TIMEOUT_SETTING)),
            origins=tuple(getattr(settings, ORIGINS_SETTING)),
            osv_url=getattr(settings, OSV_URL_SETTING),
            parselmouth_url=getattr(settings, PARSELMOUTH_URL_SETTING),
            basilisk_url=getattr(settings, BASILISK_URL_SETTING),
            target=str(context.target_prefix),
        )
        apply_metadata_tags(report, link_precs)
        render_hook_warning(
            report,
            rich_output=not (
                context.json or getattr(context, "console", None) == "json"
            ),
        )
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "conda-advise could not complete the advisory check"
        )
