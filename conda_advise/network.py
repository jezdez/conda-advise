from __future__ import annotations

import importlib
import json
import multiprocessing
import pickle
import time
from argparse import Namespace
from dataclasses import dataclass, replace
from multiprocessing.connection import wait
from types import ModuleType
from typing import TYPE_CHECKING

from conda.base.context import context, reset_context
from conda.gateways.connection.session import CondaSession, get_session
from conda.models.channel import Channel
from requests import Request

from .models import FailureReason, is_json_value

if TYPE_CHECKING:
    from multiprocessing.connection import Connection
    from multiprocessing.process import BaseProcess
    from typing import Any

    from requests import Response

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_WORKERS = 4
MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
_READ_BYTES = 64 * 1024


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


@dataclass(frozen=True)
class _CondaState:
    raw_data: Any
    argparse_args: Any
    parameters: dict[str, Any]
    plugins: tuple[tuple[str, Any], ...]

    @classmethod
    def capture(cls) -> _CondaState:
        # Carry the active CLI configuration and plugin selection into spawn workers.
        # Unserializable plugins fail the request instead of falling back to no auth.
        return cls(
            raw_data={
                source: {
                    key: value
                    for key, value in values.items()
                    if key != "_plugin_subcommand"
                }
                for source, values in context.raw_data.items()
            },
            argparse_args=Namespace(
                **{
                    key: value
                    for key, value in context._argparse_args.items()
                    if key != "_plugin_subcommand"
                }
            ),
            parameters={
                name: getattr(context, name) for name in context.parameter_names
            },
            plugins=tuple(
                (name, plugin.__name__ if isinstance(plugin, ModuleType) else plugin)
                for name, plugin in context.plugin_manager.list_name_plugin()
            ),
        )

    def restore(self) -> None:
        reset_context(search_path=(), argparse_args=self.argparse_args)
        context.raw_data.clear()
        context._set_raw_data(self.raw_data)
        context._cache_.update(self.parameters)
        manager = context.plugin_manager
        for name, plugin in manager.list_name_plugin():
            if plugin is None:
                manager.unblock(name)
            else:
                manager.unregister(plugin)
        for name, plugin in self.plugins:
            if plugin is None:
                manager.set_blocked(name)
            else:
                manager.register(
                    importlib.import_module(plugin)
                    if isinstance(plugin, str)
                    else plugin,
                    name=name,
                )
        # Unpickling plugin instances can import modules that cache initial sessions.
        context.__dict__.pop("plugins", None)
        Channel._reset_state()
        for name in (
            "get_cached_solver_backend",
            "get_cached_session_headers",
            "get_cached_request_headers",
        ):
            if cached := getattr(manager, name, None):
                cached.cache_clear()
        get_session.cache_clear()
        CondaSession.cache_clear()


@dataclass
class _Worker:
    process: BaseProcess
    connection: Connection
    request: JsonRequest


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
    responses = {key: _deadline_response(key) for key in by_key}
    if deadline <= time.monotonic():
        return responses
    try:
        state = pickle.dumps(_CondaState.capture())
    except Exception:
        return {
            key: JsonResponse(
                key,
                None,
                None,
                FailureReason.REQUEST_FAILED,
                "conda configuration or authentication plugin could not be "
                "transferred to a request worker",
            )
            for key in by_key
        }
    pending = iter(representatives.values())
    workers: list[_Worker] = []
    received_bytes = 0
    budget_exhausted = False
    process_context = multiprocessing.get_context("spawn")
    try:
        for _ in range(min(max(1, max_workers), MAX_WORKERS, len(representatives))):
            if deadline <= time.monotonic():
                break
            request = next(pending)
            connection, child_connection = process_context.Pipe()
            process = process_context.Process(
                target=_request_worker,
                args=(child_connection, state, request, deadline),
                name="conda-advise-request",
                daemon=True,
            )
            try:
                process.start()
            except Exception:
                connection.close()
                process.close()
                responses[request.key] = _worker_failure(request.key)
            else:
                workers.append(_Worker(process, connection, request))
            finally:
                child_connection.close()
        active = list(workers)
        while active and (remaining := deadline - time.monotonic()) > 0:
            ready = wait([worker.connection for worker in active], timeout=remaining)
            for worker in tuple(active):
                if worker.connection not in ready:
                    continue
                try:
                    data = worker.connection.recv_bytes(
                        MAX_RESPONSE_BYTES + 1024 * 1024
                    )
                    received_bytes += len(data)
                    if received_bytes > MAX_TOTAL_RESPONSE_BYTES:
                        budget_exhausted = True
                        break
                    response = pickle.loads(data)
                except (EOFError, OSError):
                    response = _worker_failure(worker.request.key)
                    active.remove(worker)
                else:
                    if response is None:
                        response = _worker_failure(worker.request.key)
                        active.remove(worker)
                responses[worker.request.key] = response
                if worker not in active:
                    continue
                request = next(pending, None)
                if request is None or deadline <= time.monotonic():
                    active.remove(worker)
                    continue
                worker.request = request
                try:
                    worker.connection.send(request)
                except (BrokenPipeError, EOFError, OSError):
                    responses[request.key] = _worker_failure(request.key)
                    active.remove(worker)
            if budget_exhausted:
                break
        if budget_exhausted:
            for key, response in responses.items():
                if response.reason is FailureReason.DEADLINE_EXCEEDED:
                    responses[key] = JsonResponse(
                        key,
                        None,
                        None,
                        FailureReason.INVALID_RESPONSE,
                        "provider responses exceed the scan size limit",
                    )
    finally:
        # Threads cannot cancel DNS, retries or a continuously trickling body. Kill
        # each isolated request process before returning, including on exceptions.
        for worker in workers:
            if worker.process.is_alive():
                worker.process.kill()
        for worker in workers:
            worker.process.join()
            worker.connection.close()
            worker.process.close()
    return {
        key: replace(responses[representative_keys[key]], key=key) for key in by_key
    }


def _request_worker(
    connection: Connection, state: bytes, request: JsonRequest, deadline: float
) -> None:
    try:
        # This pickle only contains state supplied by our parent through private IPC.
        pickle.loads(state).restore()
        while True:
            connection.send(_fetch_one(request, deadline))
            request = connection.recv()
    except EOFError:
        pass
    except Exception:
        connection.send(None)
    finally:
        connection.close()


class _RejectedResponse(Exception):
    def __init__(self, response: Response, message: str, reason: FailureReason):
        self.status_code = response.status_code
        self.message = message
        self.reason = reason
        response.close()


def _guard_response(response: Response, **_: object) -> Response:
    if response.status_code == 407 or 300 <= response.status_code < 400:
        raise _RejectedResponse(
            response,
            "provider proxy authentication challenge rejected"
            if response.status_code == 407
            else "provider redirect rejected",
            FailureReason.REQUEST_FAILED,
        )
    # Reading compressed bytes through Requests can allocate an unbounded decoded
    # buffer before iter_content yields its first bounded chunk.
    if response.headers.get("Content-Encoding", "identity").strip().lower() not in (
        "",
        "identity",
    ):
        raise _RejectedResponse(
            response,
            "provider returned an unsupported content encoding",
            FailureReason.INVALID_RESPONSE,
        )
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            oversized = int(length) > MAX_RESPONSE_BYTES
        except ValueError:
            oversized = True
        if oversized:
            raise _RejectedResponse(
                response,
                "provider response exceeds the size limit",
                FailureReason.INVALID_RESPONSE,
            )
    return response


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
        prepared = session.prepare_request(
            Request(
                request.method,
                request.url,
                json=request.payload,
                headers={"Accept-Encoding": "identity"},
            )
        )
        # Authentication installs response hooks during preparation. Our guard must
        # run before conda's 407 handler and Requests' eager redirect body reading.
        prepared.hooks["response"].insert(0, _guard_response)
        options = session.merge_environment_settings(
            prepared.url, {}, stream=True, verify=None, cert=None
        )
        response = session.send(
            prepared, timeout=timeout, allow_redirects=False, **options
        )
        _guard_response(response)
        if response.status_code == 404:
            return JsonResponse(request.key, None, 404)
        response.raise_for_status()
        body = bytearray()
        while True:
            if time.monotonic() >= deadline:
                return _deadline_response(request.key)
            chunk = response.raw.read(
                min(_READ_BYTES, MAX_RESPONSE_BYTES + 1 - len(body)),
                decode_content=False,
            )
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                return JsonResponse(
                    request.key,
                    None,
                    response.status_code,
                    FailureReason.INVALID_RESPONSE,
                    "provider response exceeds the size limit",
                )
        try:
            payload = json.loads(body)
        except (ValueError, RecursionError):
            return JsonResponse(
                request.key,
                None,
                response.status_code,
                FailureReason.INVALID_RESPONSE,
                "provider returned invalid JSON",
            )
        if not isinstance(payload, dict):
            return JsonResponse(
                request.key,
                None,
                response.status_code,
                FailureReason.INVALID_RESPONSE,
                "provider returned a non-object JSON response",
            )
        if not is_json_value(payload):
            return JsonResponse(
                request.key,
                None,
                response.status_code,
                FailureReason.INVALID_RESPONSE,
                "provider returned unsupported JSON values",
            )
        return JsonResponse(request.key, payload, response.status_code)
    except _RejectedResponse as error:
        return JsonResponse(
            request.key, None, error.status_code, error.reason, error.message
        )
    except Exception as error:
        error_status = getattr(getattr(error, "response", None), "status_code", None)
        return JsonResponse(
            request.key,
            None,
            error_status
            if error_status is not None
            else getattr(response, "status_code", None),
            FailureReason.REQUEST_FAILED,
            "provider request failed",
        )
    finally:
        if response is not None:
            response.close()


def _worker_failure(key: str) -> JsonResponse:
    return JsonResponse(
        key, None, None, FailureReason.REQUEST_FAILED, "request worker failed"
    )


def _deadline_response(key: str) -> JsonResponse:
    return JsonResponse(
        key,
        None,
        None,
        FailureReason.DEADLINE_EXCEEDED,
        "provider deadline exceeded",
    )
