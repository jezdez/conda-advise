from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from recipe.check_release_runs import check_runs

if TYPE_CHECKING:
    from typing import Any

REPOSITORY = "example/conda-advise"
SHA = "a" * 40
WORKFLOW = ".github/workflows/tests.yml"


@pytest.fixture
def workflow_payload() -> dict[str, Any]:
    return {
        "workflow": {"id": 10, "path": WORKFLOW, "state": "active"},
        "pages": [
            {
                "workflow_runs": [
                    {
                        "workflow_id": 10,
                        "path": WORKFLOW,
                        "repository": {"full_name": REPOSITORY},
                        "head_repository": {"full_name": REPOSITORY},
                        "head_sha": SHA,
                        "head_branch": "main",
                        "event": "push",
                        "run_number": 1,
                        "run_attempt": 1,
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            }
        ],
    }


def test_release_accepts_trusted_main_run(workflow_payload: dict[str, Any]) -> None:
    check_runs(workflow_payload, REPOSITORY, SHA, WORKFLOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", 20),
        ("path", ".github/workflows/untrusted.yml"),
        ("repository", {"full_name": "attacker/conda-advise"}),
        ("head_repository", {"full_name": "attacker/conda-advise"}),
        ("head_sha", "b" * 40),
        ("head_branch", "feature"),
        ("event", "pull_request"),
        ("event", "workflow_dispatch"),
    ],
    ids=[
        "different-workflow-id",
        "different-workflow-path",
        "different-repository",
        "fork-head",
        "different-commit",
        "different-branch",
        "pull-request",
        "manual-run",
    ],
)
def test_release_rejects_untrusted_run(
    workflow_payload: dict[str, Any], field: str, value: Any
) -> None:
    workflow_payload["pages"][0]["workflow_runs"][0][field] = value
    with pytest.raises(ValueError, match="no trusted main run"):
        check_runs(workflow_payload, REPOSITORY, SHA, WORKFLOW)


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [("completed", "failure"), ("in_progress", None), ("completed", "cancelled")],
    ids=["failed", "pending", "cancelled"],
)
@pytest.mark.parametrize("retry", [False, True], ids=["new-run", "rerun"])
def test_release_rejects_unsuccessful_latest_run(
    workflow_payload: dict[str, Any], status: str, conclusion: str | None, retry: bool
) -> None:
    earlier = workflow_payload["pages"][0]["workflow_runs"][0]
    latest = dict(earlier)
    latest.update(status=status, conclusion=conclusion)
    latest["run_attempt" if retry else "run_number"] = 2
    workflow_payload["pages"].append({"workflow_runs": [latest]})

    with pytest.raises(ValueError, match="did not complete successfully"):
        check_runs(workflow_payload, REPOSITORY, SHA, WORKFLOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [("path", ".github/workflows/untrusted.yml"), ("state", "disabled_manually")],
    ids=["wrong-path", "disabled"],
)
def test_release_rejects_changed_workflow(
    workflow_payload: dict[str, Any], field: str, value: str
) -> None:
    workflow_payload["workflow"][field] = value
    with pytest.raises(ValueError, match="missing, inactive, or has a different path"):
        check_runs(workflow_payload, REPOSITORY, SHA, WORKFLOW)
