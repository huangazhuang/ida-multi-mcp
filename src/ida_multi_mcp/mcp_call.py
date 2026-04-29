"""One-shot JSON-RPC caller for ida-multi-mcp.

This is a pragmatic fallback for MCP clients that can start ida-multi-mcp but do
not expose the server's dynamic MCP tools directly in the model tool surface.
It launches the local stdio server, sends initialize + one request, prints JSON,
and exits.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any


def _json_arg(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--args-json is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("--args-json must decode to a JSON object")
    return parsed


def _server_cmd(idalib_python: str | None = None) -> list[str]:
    cmd = [sys.executable, "-m", "ida_multi_mcp"]
    if idalib_python:
        cmd.extend(["--idalib-python", idalib_python])
    return cmd


def _run_mcp(requests: list[dict[str, Any]], *, timeout: int, idalib_python: str | None) -> dict[int, dict[str, Any]]:
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "ida-mcp-call", "version": "1"},
        },
    }
    payload = [init] + requests
    stdin_text = "\n".join(json.dumps(req, separators=(",", ":")) for req in payload) + "\n"

    proc = subprocess.Popen(
        _server_cmd(idalib_python),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = proc.communicate(stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise SystemExit(
            json.dumps(
                {
                    "error": f"ida-multi-mcp request timed out after {timeout}s",
                    "stderr_tail": stderr[-4000:],
                },
                ensure_ascii=False,
                indent=2,
            )
        )

    responses: dict[int, dict[str, Any]] = {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("id"), int):
            responses[obj["id"]] = obj

    if proc.returncode not in (0, None) and not responses:
        raise SystemExit(
            json.dumps(
                {
                    "error": f"ida-multi-mcp exited with {proc.returncode}",
                    "stderr_tail": stderr[-4000:],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return responses


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_tools(args: argparse.Namespace) -> int:
    responses = _run_mcp(
        [{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}],
        timeout=args.timeout,
        idalib_python=args.idalib_python,
    )
    resp = responses.get(2, {})
    if args.names:
        names = [tool.get("name") for tool in resp.get("result", {}).get("tools", [])]
        _print_json(names)
    else:
        _print_json(resp)
    return 0


def cmd_resources(args: argparse.Namespace) -> int:
    responses = _run_mcp(
        [{"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}}],
        timeout=args.timeout,
        idalib_python=args.idalib_python,
    )
    _print_json(responses.get(2, {}))
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    tool_args = _json_arg(args.args_json)
    if args.input_path:
        tool_args["input_path"] = args.input_path
    if args.idalib_timeout is not None:
        tool_args["idalib_timeout"] = args.idalib_timeout
    if args.max_output_chars is not None:
        tool_args["max_output_chars"] = args.max_output_chars

    responses = _run_mcp(
        [
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": args.tool, "arguments": tool_args},
            }
        ],
        timeout=args.timeout,
        idalib_python=args.idalib_python,
    )
    resp = responses.get(2, {})
    result = resp.get("result", {})
    if args.structured and isinstance(result, dict) and "structuredContent" in result:
        _print_json(result["structuredContent"])
    elif args.text and isinstance(result, dict):
        content = result.get("content") or []
        print(content[0].get("text", "") if content else "")
    else:
        _print_json(resp)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="One-shot JSON-RPC helper for ida-multi-mcp tools."
    )
    parser.add_argument("--timeout", type=int, default=240, help="Overall request timeout in seconds")
    parser.add_argument(
        "--idalib-python",
        default=None,
        help="Python executable with idapro installed; defaults to this Python.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    tools = sub.add_parser("tools", help="List MCP tools")
    tools.add_argument("--names", action="store_true", help="Print only tool names")
    tools.set_defaults(func=cmd_tools)

    resources = sub.add_parser("resources", help="List MCP resources")
    resources.set_defaults(func=cmd_resources)

    call = sub.add_parser("call", help="Call an ida-multi-mcp tool")
    call.add_argument("tool", help="Tool name, e.g. list_funcs or decompile")
    call.add_argument("--args-json", default="{}", help="JSON object passed as tool arguments")
    call.add_argument("--input-path", help="Binary/IDB path for automatic headless IDA Pro open")
    call.add_argument("--idalib-timeout", type=int, help="Headless open timeout")
    call.add_argument("--max-output-chars", type=int, help="Forward max_output_chars")
    call.add_argument("--text", action="store_true", help="Print MCP text content only")
    call.add_argument("--structured", action="store_true", help="Print structuredContent only")
    call.set_defaults(func=cmd_call)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
