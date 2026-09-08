from __future__ import annotations

import pytest

from conda_advise.models import is_json_value


@pytest.mark.parametrize(
    ("payload", "valid"),
    [
        ({"items": [None, True, 3, 1.5, "normal"]}, True),
        ({"items": [0] * 100_000}, False),
        ({"data": "a" * (1024 * 1024 + 1)}, False),
        ({"a" * 16_385: True}, False),
        ({"value": float("inf")}, False),
    ],
    ids=["ordinary", "node-limit", "string-limit", "key-limit", "nonfinite"],
)
def test_json_values_have_resource_limits(payload, valid) -> None:
    assert is_json_value(payload) is valid


@pytest.mark.parametrize("depth", [64, 65], ids=["allowed", "too-deep"])
def test_json_depth_is_bounded(depth) -> None:
    payload = None
    for _ in range(depth):
        payload = [payload]
    assert is_json_value(payload) is (depth == 64)


def test_json_rejects_cycles_without_recursion() -> None:
    payload = []
    payload.append(payload)
    assert not is_json_value(payload)
