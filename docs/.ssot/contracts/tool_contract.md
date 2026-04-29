# Tool Federation Contract

Last updated: 2026-04-29
Version: v2

## Authority
This contract defines the central MCP server's tool schema federation, headless-default inputs, and large-response handling rules.

## Schema Rules
- IDA tools expose `instance_id` as an optional routing input.
- IDA tools expose `input_path` as an optional routing input for automatic IDA Pro `idalib` headless opening.
- IDA tools expose `idalib_timeout` and `unsafe` as optional headless-session controls.
- `unsafe` defaults to `true` for IDA Pro headless sessions in this fork.
- For client compatibility, the output schema must be object-compatible.

## Output Rules
- Large outputs may be served as preview + cache pagination.
- Cache retrieval is performed via `get_cached_output` using offset/size.

## Resource Rules
- The central server exposes lightweight MCP resources so clients can discover the server even before an IDA database is open:
  - `ida-multi-mcp://status`
  - `ida-multi-mcp://instances`
  - `ida-multi-mcp://headless-help`

## Traceability
- Tool cache/federation: `src/ida_multi_mcp/server.py`
- Headless idalib tool defaults: `src/ida_multi_mcp/tools/idalib.py`
- Cache model: `src/ida_multi_mcp/cache.py`
