# Contracts Index (Authoritative SSOT)

Last updated: 2026-04-29
Status: Active

## Authority
This directory (`docs/.ssot/contracts/*`) is the top-level SSOT for the project.
Other documents do not redefine contracts; they only link to or reference them.

## Contract Set
- `routing_contract.md` (v2: `instance_id` or headless `input_path` target selection)
- `registry_contract.md` (v1 baseline)
- `tool_contract.md` (v2: headless-default tool inputs and resources)

## Traceability
- Router impl: `src/ida_multi_mcp/router.py`
- Registry impl: `src/ida_multi_mcp/registry.py`
- Tool federation impl: `src/ida_multi_mcp/server.py`
- idalib lifecycle impl: `src/ida_multi_mcp/idalib_manager.py`
