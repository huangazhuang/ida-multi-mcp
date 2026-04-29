# Headless-default IDA Pro mode

Last updated: 2026-04-29
Status: Active

This fork defaults to IDA Pro `idalib` headless operation.  Contract authority lives in:

- `docs/.ssot/contracts/routing_contract.md`
- `docs/.ssot/contracts/tool_contract.md`

## Usage

Call regular IDA tools with `input_path` when no GUI IDA instance is already selected.

```json
{
  "name": "list_funcs",
  "arguments": {
    "input_path": "D:\\path\\target.exe",
    "queries": {"count": 50, "offset": 0}
  }
}
```

The server opens or reuses a headless `idalib` session, injects the resolved `instance_id`, strips helper-only arguments, and forwards the call to the IDA tool.

## Defaults

- `unsafe=true` by default for `idalib_open` and automatic `input_path` opens.
- `idalib_timeout=120` seconds by default.
- `instance_id` remains supported for explicitly targeting GUI or headless instances.

## Discoverability

`resources/list` exposes these server-level resources:

- `ida-multi-mcp://status`
- `ida-multi-mcp://instances`
- `ida-multi-mcp://headless-help`

## Implementation traceability

- `src/ida_multi_mcp/server.py`
- `src/ida_multi_mcp/tools/idalib.py`
- `src/ida_multi_mcp/idalib_manager.py`
- `src/ida_multi_mcp/idalib_worker.py`
