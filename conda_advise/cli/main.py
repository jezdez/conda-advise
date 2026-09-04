"""Argument parsing and execution for ``conda advise``."""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argparse import Namespace


PROVIDERS = ("osv", "basilisk")
SEVERITIES = ("low", "medium", "high", "critical")


def configure_parser(parser: ArgumentParser) -> None:
    """Configure arguments supplied by ``conda advise``."""
    from conda.cli.helpers import (
        add_parser_json,
        add_parser_networking,
        add_parser_prefix,
    )

    add_parser_prefix(parser)
    parser.add_argument(
        "--provider",
        choices=PROVIDERS,
        help=(
            "Select the advisory provider. The default is osv. The experimental "
            "basilisk provider sends names and versions from records whose sanitized "
            "package URL matches the configured allowed origins to Prefix.dev."
        ),
    )
    parser.add_argument(
        "--minimum-severity",
        choices=SEVERITIES,
        help=(
            "Minimum advisory severity that qualifies a match. "
            "Matches enriched from CISA KEV always qualify."
        ),
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Refresh cached mappings and advisory results.",
    )
    add_parser_networking(parser)
    add_parser_json(parser)


def build_parser() -> ArgumentParser:
    """Build a standalone parser for documentation and direct tests."""
    parser = ArgumentParser(
        prog="conda advise",
        description="Report advisory matches and coverage for a conda environment.",
    )
    configure_parser(parser)
    return parser


def execute(args: Namespace) -> int:
    """Scan the selected environment and render one report."""
    from conda.base.context import context, determine_target_prefix
    from conda.core.prefix_data import PrefixData

    from ..plugin import (
        BASILISK_URL_SETTING,
        MINIMUM_SEVERITY_SETTING,
        ORIGINS_SETTING,
        OSV_URL_SETTING,
        PARSELMOUTH_URL_SETTING,
        PROVIDER_SETTING,
        TIMEOUT_SETTING,
    )
    from ..reporting import render_error, render_report, report_exit_code

    json_output = (
        context.json
        or bool(getattr(args, "json", False))
        or (getattr(args, "console", None) == "json")
    )
    offline = bool(getattr(args, "offline", False)) or context.offline
    if offline and args.refresh:
        render_error(
            "--offline and --refresh cannot be used together",
            json_output=json_output,
        )
        return 2

    settings = context.plugins
    provider = args.provider or getattr(settings, PROVIDER_SETTING)
    minimum_severity = args.minimum_severity or getattr(
        settings, MINIMUM_SEVERITY_SETTING
    )

    try:
        prefix = Path(determine_target_prefix(context, args))
        prefix_data = PrefixData(prefix)
        if assert_environment := getattr(prefix_data, "assert_environment", None):
            assert_environment()
        else:
            from conda.base.constants import PREFIX_MAGIC_FILE
            from conda.exceptions import EnvironmentLocationNotFound

            if not (prefix / PREFIX_MAGIC_FILE).is_file():
                raise EnvironmentLocationNotFound(prefix)

        from ..scanner import scan_records

        report = scan_records(
            tuple(prefix_data.iter_records()),
            provider=provider,
            offline=offline,
            refresh=args.refresh,
            minimum_severity=minimum_severity,
            timeout_seconds=float(getattr(settings, TIMEOUT_SETTING)),
            origins=tuple(getattr(settings, ORIGINS_SETTING)),
            osv_url=getattr(settings, OSV_URL_SETTING),
            parselmouth_url=getattr(settings, PARSELMOUTH_URL_SETTING),
            basilisk_url=getattr(settings, BASILISK_URL_SETTING),
            target=str(prefix),
        )
    except Exception as error:
        render_error(
            str(error),
            json_output=json_output,
            target=str(prefix) if "prefix" in locals() else None,
        )
        return 2

    try:
        render_report(
            report,
            json_output=json_output,
        )
    except (OverflowError, RecursionError, TypeError, ValueError):
        render_error(
            "report contains unsupported JSON values",
            json_output=json_output,
            target=str(prefix),
        )
        return 2
    return report_exit_code(report)
