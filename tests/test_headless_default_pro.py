"""Tests for the headless-default IDA Pro fork behavior."""

import json
import os
from unittest.mock import MagicMock, patch

from ida_multi_mcp.server import IdaMultiMcpServer
from ida_multi_mcp.tools import idalib


def _dispatch(server: IdaMultiMcpServer, method: str, params=None):
    request = {"jsonrpc": "2.0", "method": method, "id": 1}
    if params is not None:
        request["params"] = params
    return server.server.registry.dispatch(request)


@patch("ida_multi_mcp.idalib_manager.query_binary_metadata", return_value={})
@patch("ida_multi_mcp.idalib_manager.subprocess.Popen")
@patch("ida_multi_mcp.idalib_manager.ping_instance", return_value=True)
def test_idalib_manager_defaults_to_unsafe(
    _mock_ping,
    mock_popen,
    _mock_metadata,
    tmp_path,
    tmp_registry,
):
    from ida_multi_mcp.idalib_manager import IdalibManager

    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)

    proc = MagicMock()
    proc.pid = 12345
    proc.poll.return_value = None
    mock_popen.return_value = proc

    with patch("ida_multi_mcp.idalib_manager.is_idalib_available", return_value=True):
        result = IdalibManager(tmp_registry).spawn_session(str(binary))

    assert "error" not in result
    cmd = mock_popen.call_args.args[0]
    assert "--unsafe" in cmd


def test_idalib_open_defaults_to_unsafe():
    class Manager:
        def __init__(self):
            self.calls = []

        def spawn_session(self, input_path, *, timeout, unsafe):
            self.calls.append((input_path, timeout, unsafe))
            return {"instance_id": "abcd"}

    manager = Manager()
    old_manager = idalib._manager
    idalib.set_manager(manager)

    try:
        result = idalib.idalib_open({"input_path": "D:/target.exe"})
    finally:
        idalib._manager = old_manager

    assert result == {"instance_id": "abcd"}
    assert manager.calls == [("D:/target.exe", 120, True)]


def test_resources_list_exposes_ida_multi_mcp_status(tmp_path):
    server = IdaMultiMcpServer(registry_path=str(tmp_path / "instances.json"))

    response = _dispatch(server, "resources/list")

    assert "error" not in response
    resources = response["result"]["resources"]
    uris = {resource["uri"] for resource in resources}
    assert "ida-multi-mcp://status" in uris
    assert "ida-multi-mcp://instances" in uris
    assert "ida-multi-mcp://headless-help" in uris


def test_static_ida_tool_schema_accepts_input_path(tmp_path):
    server = IdaMultiMcpServer(registry_path=str(tmp_path / "instances.json"))
    with patch("ida_multi_mcp.server.rediscover_instances", return_value=[]):
        server._refresh_tools()

    response = _dispatch(server, "tools/list")

    tools = response["result"]["tools"]
    list_funcs = next(tool for tool in tools if tool["name"] == "list_funcs")
    schema = list_funcs["inputSchema"]
    assert "input_path" in schema["properties"]
    assert "idalib_timeout" in schema["properties"]
    assert schema["properties"]["unsafe"]["default"] is True
    assert "instance_id" not in schema.get("required", [])


def test_input_path_spawns_headless_and_routes_without_helper_args(tmp_path):
    server = IdaMultiMcpServer(registry_path=str(tmp_path / "instances.json"))
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")

    routed_payload = {"functions": []}
    ida_response = {
        "content": [{"type": "text", "text": json.dumps(routed_payload)}],
        "structuredContent": routed_payload,
        "isError": False,
    }

    with patch.object(
        server.idalib_manager,
        "spawn_session",
        return_value={"instance_id": "abcd", "host": "127.0.0.1", "port": 1234},
    ) as spawn_session:
        with patch.object(server, "_refresh_tools"):
            with patch.object(server.router, "route_request", return_value=ida_response) as route_request:
                response = _dispatch(
                    server,
                    "tools/call",
                    {
                        "name": "list_funcs",
                        "arguments": {
                            "input_path": str(binary),
                            "queries": {"count": 50, "offset": 0},
                        },
                    },
                )

    assert response["result"]["isError"] is False
    spawn_session.assert_called_once_with(
        os.path.realpath(str(binary)),
        timeout=120,
        unsafe=True,
    )
    routed_arguments = route_request.call_args.args[1]["arguments"]
    assert routed_arguments["instance_id"] == "abcd"
    assert routed_arguments["queries"] == {"count": 50, "offset": 0}
    assert "input_path" not in routed_arguments
    assert "unsafe" not in routed_arguments
    assert "idalib_timeout" not in routed_arguments
