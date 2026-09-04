from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from conda.base.context import context
from conda.gateways.connection.session import get_session

from .models import FailureReason, is_json_value

if TYPE_CHECKING:
    from concurrent.futures import Future
    from typing import Any


@dataclass(frozen=True, slots=True)
class JsonRequest:
    key: str
    method: str
    url: str
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class JsonResponse:
    key: str
    payload: dict[str, object] | None
    status_code: int | None
    reason: FailureReason | None = None
    message: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.payload is not None and self.reason is None

    @property
    def not_found(self) -> bool:
        return self.status_code == 404


def fetch_json(
    requests: list[JsonRequest],
    *,
    deadline: float,
    max_workers: int,
) -> dict[str, JsonResponse]:
    by_key: dict[str, JsonRequest] = {}
    for request in requests:
        by_key.setdefault(request.key, request)
    if not by_key:
        return {}
    representatives: dict[tuple[str, str, str], JsonRequest] = {}
    representative_keys: dict[str, str] = {}
    for request in by_key.values():
        signature = (
            request.method.upper(),
            request.url,
            json.dumps(request.payload, sort_keys=True, separators=(",", ":")),
        )
        representative = representatives.setdefault(signature, request)
        representative_keys[request.key] = representative.key
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {key: _deadline_response(key) for key in by_key}
    executor = ThreadPoolExecutor(
        max_workers=min(max_workers, len(representatives)),
        thread_name_prefix="conda-advise",
    )
    futures: dict[Future[JsonResponse], str] = {
        executor.submit(_fetch_one, request, deadline): key
        for key, request in (
            (request.key, request) for request in representatives.values()
        )
    }
    done, pending = wait(futures, timeout=remaining)
    responses: dict[str, JsonResponse] = {}
    for future in done:
        key = futures[future]
        try:
            responses[key] = future.result()
        except Exception:
            responses[key] = JsonResponse(
                key=key,
                payload=None,
                status_code=None,
                reason=FailureReason.REQUEST_FAILED,
                message="request worker failed",
            )
    for future in pending:
        key = futures[future]
        future.cancel()
        responses[key] = _deadline_response(key)
    executor.shutdown(wait=False, cancel_futures=True)
    return {
        key: replace(responses[representative_keys[key]], key=key) for key in by_key
    }


def _fetch_one(request: JsonRequest, deadline: float) -> JsonResponse:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _deadline_response(request.key)
    timeout = (
        min(float(context.remote_connect_timeout_secs), remaining),
        min(float(context.remote_read_timeout_secs), remaining),
    )
    response = None
    try:
        session = get_session(request.url)
        response = session.request(
            request.method,
            request.url,
            json=request.payload,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return JsonResponse(request.key, None, 404)
        if 300 <= response.status_code < 400:
            return JsonResponse(
                key=request.key,
                payload=None,
                status_code=response.status_code,
                reason=FailureReason.REQUEST_FAILED,
                message="provider redirect rejected",
            )
        response.raise_for_status()
    except Exception as error:
        error_status = getattr(getattr(error, "response", None), "status_code", None)
        return JsonResponse(
            key=request.key,
            payload=None,
            status_code=(
                error_status
                if error_status is not None
                else getattr(response, "status_code", None)
            ),
            reason=FailureReason.REQUEST_FAILED,
            message="provider request failed",
        )
    try:
        payload: Any = response.json()
    except Exception:
        return JsonResponse(
            key=request.key,
            payload=None,
            status_code=response.status_code,
            reason=FailureReason.INVALID_RESPONSE,
            message="provider returned invalid JSON",
        )
    if not isinstance(payload, dict):
        return JsonResponse(
            key=request.key,
            payload=None,
            status_code=response.status_code,
            reason=FailureReason.INVALID_RESPONSE,
            message="provider returned a non-object JSON response",
        )
    try:
        valid_payload = is_json_value(payload)
    except RecursionError:
        valid_payload = False
    if not valid_payload:
        return JsonResponse(
            key=request.key,
            payload=None,
            status_code=response.status_code,
            reason=FailureReason.INVALID_RESPONSE,
            message="provider returned unsupported JSON values",
        )
    return JsonResponse(request.key, payload, response.status_code)


def _deadline_response(key: str) -> JsonResponse:
    return JsonResponse(
        key=key,
        payload=None,
        status_code=None,
        reason=FailureReason.DEADLINE_EXCEEDED,
        message="provider deadline exceeded",
    )
