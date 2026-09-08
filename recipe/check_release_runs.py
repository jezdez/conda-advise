"""Require successful runs of the release commit's trusted main workflows."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


def check_runs(
    payload: dict[str, Any], repository: str, sha: str, workflow_path: str
) -> None:
    workflow = payload["workflow"]
    if workflow["path"] != workflow_path or workflow["state"] != "active":
        raise ValueError(
            "required workflow is missing, inactive, or has a different path"
        )
    runs = [
        run
        for page in payload["pages"]
        for run in page["workflow_runs"]
        if run["workflow_id"] == workflow["id"]
        and run["path"] == workflow_path
        and run["repository"]["full_name"].lower() == repository.lower()
        and run["head_repository"]["full_name"].lower() == repository.lower()
        and run["head_sha"] == sha
        and run["head_branch"] == "main"
        and run["event"] == "push"
    ]
    if not runs:
        raise ValueError(
            f"{workflow_path} has no trusted main run for the release commit"
        )
    latest = max(runs, key=lambda run: (run["run_number"], run["run_attempt"]))
    if latest["status"] != "completed" or latest["conclusion"] != "success":
        raise ValueError(
            f"{workflow_path} latest main run did not complete successfully"
        )


def main() -> None:
    repository, sha, workflow_path = sys.argv[1:]
    try:
        check_runs(json.load(sys.stdin), repository, sha, workflow_path)
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"Release workflow check failed: {error}") from None


if __name__ == "__main__":
    main()
