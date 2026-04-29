# Routing Contract

Last updated: 2026-04-29
Version: v2

## Authority
This contract defines the accepted target-selection inputs and error shape for IDA tool routing requests.

## Rules
- IDA tool calls may target a running instance with `instance_id`.
- IDA tool calls may omit `instance_id` when `input_path` is supplied; the central server must open or reuse an IDA Pro `idalib` headless session and inject the resulting `instance_id` before forwarding the request.
- IDA tool calls may omit `instance_id` when exactly one instance is registered; the router may auto-select that instance.
- If a target cannot be selected or opened, the response must contain `error`; when available, it should include `hint` and `available_instances`.
- Routing-only helper inputs such as `input_path`, `idalib_timeout`, `headless_timeout`, and `unsafe` must not be forwarded to the underlying IDA tool after target selection.

## Traceability
- Router impl: `src/ida_multi_mcp/router.py`
- Headless target preparation: `src/ida_multi_mcp/server.py`
- idalib lifecycle: `src/ida_multi_mcp/idalib_manager.py`
- Error envelope shaping: `src/ida_multi_mcp/server.py`
