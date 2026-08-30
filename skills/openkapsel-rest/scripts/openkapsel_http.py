#!/usr/bin/env python3
"""Small standard-library OpenKapsel REST client used by the skill."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from openkapsel_config import Credentials, resolve_credentials, update_env_file


AUTO_RENEW_WINDOW = timedelta(days=2)


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


def parse_pair(value: str, separator: str = "=") -> tuple[str, str]:
    key, found, item = value.partition(separator)
    if not found or not key.strip():
        raise argparse.ArgumentTypeError(f"expected NAME{separator}VALUE")
    return key.strip(), item


def build_url(base_url: str | None, endpoint: str, query: Iterable[tuple[str, str]]) -> tuple[str, bool]:
    parsed = urlsplit(endpoint)
    absolute = parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    if absolute:
        url = endpoint
    else:
        if not base_url:
            raise ValueError("set OPENKAPSEL_BASE_URL or pass --base-url")
        url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
    pairs = list(query)
    if pairs:
        url += ("&" if "?" in url else "?") + urlencode(pairs)
    return url, absolute


def context_headers(plan_id: int, taskname: str, message: str) -> dict[str, str]:
    return {
        "OpenKapsel-Plan-Id": str(plan_id),
        "OpenKapsel-Taskname": taskname,
        "OpenKapsel-Message": message,
    }


def api_request(
    method: str,
    endpoint: str,
    *,
    base_url: str | None,
    control_token: str | None,
    auth_mode: str = "auto",
    query: Iterable[tuple[str, str]] = (),
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 60.0,
    output_stream: BinaryIO | None = None,
) -> HttpResult:
    url, absolute = build_url(base_url, endpoint, query)
    request_headers = {"Accept": "application/json", **(headers or {})}
    should_authenticate = auth_mode == "control" or (
        auth_mode == "auto" and not absolute and bool(control_token)
    )
    if should_authenticate:
        if not control_token:
            raise ValueError("set OPENKAPSEL_CONTROL_TOKEN or pass --control-token")
        request_headers.setdefault("Authorization", f"Bearer {control_token}")
    if data is not None:
        request_headers.setdefault("Content-Length", str(len(data)))
    request = Request(url, data=data, headers=request_headers, method=method.upper())
    try:
        with urlopen(request, timeout=timeout) as response:
            response_headers = dict(response.headers.items())
            if output_stream is None:
                body = response.read()
            else:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    output_stream.write(chunk)
                    output_stream.flush()
                body = b""
            return HttpResult(response.status, response_headers, body)
    except HTTPError as exc:
        try:
            return HttpResult(exc.code, dict(exc.headers.items()), exc.read())
        finally:
            exc.close()
    except URLError as exc:
        raise RuntimeError(f"request failed: {exc.reason}") from exc


def decode_json_result(result: HttpResult) -> object:
    try:
        return json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"HTTP {result.status} did not return valid JSON: "
            f"{result.body[:300]!r}"
        ) from exc


def require_success(result: HttpResult) -> HttpResult:
    if 200 <= result.status < 300:
        return result
    try:
        detail = json.dumps(decode_json_result(result), ensure_ascii=False)
    except RuntimeError:
        detail = result.body[:1000].decode("utf-8", errors="replace")
    raise RuntimeError(f"HTTP {result.status}: {detail}")


def _parse_expiry(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def ensure_fresh_credentials(credentials: Credentials) -> Credentials:
    """Renew directory-scoped credentials when less than two days remain."""
    if (
        credentials.env_file is None
        or not credentials.base_url
        or not credentials.control_token
    ):
        return credentials

    expiry_text = credentials.credentials_expires_at
    discovered_expiry = False
    if not expiry_text:
        discovery = api_request(
            "GET",
            "",
            base_url=credentials.base_url,
            control_token=credentials.control_token,
            auth_mode="control",
        )
        require_success(discovery)
        payload = decode_json_result(discovery)
        if not isinstance(payload, dict):
            raise RuntimeError("OpenKapsel Discovery response is not an object")
        authentication = payload.get("authentication")
        if not isinstance(authentication, dict):
            raise RuntimeError("OpenKapsel Discovery does not publish credential expiration")
        expiry_text = authentication.get("control_token_expires_at")
        if not isinstance(expiry_text, str) or not expiry_text:
            raise RuntimeError("OpenKapsel Discovery does not publish credential expiration")
        credentials = credentials.updated(credentials_expires_at=expiry_text)
        discovered_expiry = True

    remaining = _parse_expiry(expiry_text) - datetime.now(timezone.utc)
    if remaining >= AUTO_RENEW_WINDOW:
        if discovered_expiry:
            update_env_file(credentials.env_file, credentials)
        return credentials
    if remaining.total_seconds() <= 0:
        raise RuntimeError("OpenKapsel credentials expired; an administrator must renew them")

    renewed = api_request(
        "POST",
        "credentials/renew",
        base_url=credentials.base_url,
        control_token=credentials.control_token,
        auth_mode="control",
    )
    if renewed.status == 409:
        error = decode_json_result(renewed)
        if (
            isinstance(error, dict)
            and isinstance(error.get("error"), dict)
            and error["error"].get("code") == "credentials_renewal_not_due"
        ):
            update_env_file(credentials.env_file, credentials)
            return credentials
    require_success(renewed)
    payload = decode_json_result(renewed)
    if not isinstance(payload, dict):
        raise RuntimeError("credential renewal response is not an object")
    base_url = payload.get("workspace_url")
    control_token = payload.get("control_token")
    expires_at = payload.get("credentials_expires_at")
    if not all(isinstance(value, str) and value for value in (base_url, control_token, expires_at)):
        raise RuntimeError("credential renewal response is incomplete")
    credentials = credentials.updated(
        base_url=base_url.rstrip("/"),
        control_token=control_token,
        credentials_expires_at=expires_at,
    )
    update_env_file(credentials.env_file, credentials)
    return credentials


def load_json_argument(inline: str | None, filename: str | None) -> dict[str, object] | None:
    if inline is None and filename is None:
        return None
    if inline is not None:
        text = sys.stdin.read() if inline == "-" else inline
    else:
        text = Path(filename or "").read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("the JSON request body must be an object")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Call a OpenKapsel REST endpoint")
    result.add_argument("method", help="HTTP method")
    result.add_argument("endpoint", help="workspace-relative path or absolute URL")
    result.add_argument("--base-url")
    result.add_argument("--control-token")
    result.add_argument("--env-file", help="credential file; defaults to nearest .openkapsel.env")
    result.add_argument("--auth", choices=("auto", "control", "none"), default="auto")
    result.add_argument("--query", action="append", default=[], metavar="NAME=VALUE")
    body = result.add_mutually_exclusive_group()
    body.add_argument("--json", help="JSON object or - to read it from stdin")
    body.add_argument("--json-file", help="read a JSON object from a file")
    body.add_argument("--data-file", help="read a raw body from a file or - for stdin")
    result.add_argument("--header", action="append", default=[], metavar="NAME:VALUE")
    result.add_argument("--plan-id", type=int)
    result.add_argument("--taskname")
    result.add_argument("--message")
    result.add_argument("--output", help="write the response body to this file")
    result.add_argument("--stream", action="store_true", help="stream the response to stdout")
    result.add_argument("--include-headers", action="store_true")
    result.add_argument("--timeout", type=float, default=60.0)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        credentials = resolve_credentials(
            base_url=args.base_url,
            control_token=args.control_token,
            env_file=args.env_file,
        )
        endpoint_parts = urlsplit(args.endpoint)
        if args.auth != "none" and not (
            endpoint_parts.scheme in {"http", "https"} and endpoint_parts.netloc
        ):
            credentials = ensure_fresh_credentials(credentials)
        args.base_url = credentials.base_url
        args.control_token = credentials.control_token
        query = [parse_pair(value) for value in args.query]
        headers = dict(parse_pair(value, ":") for value in args.header)
        context_values = (args.plan_id, args.taskname, args.message)
        if any(value is not None for value in context_values) and not all(
            value is not None for value in context_values
        ):
            raise ValueError("--plan-id, --taskname, and --message must be supplied together")

        json_body = load_json_argument(args.json, args.json_file)
        if json_body is not None:
            if args.plan_id is not None:
                json_body.setdefault("plan_id", args.plan_id)
                json_body.setdefault("taskname", args.taskname)
                json_body.setdefault("message", args.message)
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif args.data_file is not None:
            data = sys.stdin.buffer.read() if args.data_file == "-" else Path(args.data_file).read_bytes()
            if args.plan_id is not None:
                headers.update(context_headers(args.plan_id, args.taskname, args.message))
        else:
            data = None
            if args.plan_id is not None:
                headers.update(context_headers(args.plan_id, args.taskname, args.message))

        output_handle: BinaryIO | None = None
        close_output = False
        if args.output:
            output_handle = open(args.output, "wb")
            close_output = True
        elif args.stream:
            output_handle = sys.stdout.buffer
        try:
            response = api_request(
                args.method,
                args.endpoint,
                base_url=args.base_url,
                control_token=args.control_token,
                auth_mode=args.auth,
                query=query,
                headers=headers,
                data=data,
                timeout=args.timeout,
                output_stream=output_handle,
            )
        finally:
            if close_output and output_handle is not None:
                output_handle.close()

        if args.include_headers:
            print(f"HTTP {response.status}", file=sys.stderr)
            for name, value in response.headers.items():
                print(f"{name}: {value}", file=sys.stderr)
        if not 200 <= response.status < 300:
            require_success(response)
        if output_handle is None and response.body:
            content_type = response.headers.get("Content-Type", "").lower()
            if "json" in content_type:
                print(json.dumps(decode_json_result(response), ensure_ascii=False, indent=2))
            else:
                sys.stdout.buffer.write(response.body)
                sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"openkapsel_http.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
