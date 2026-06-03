# 04 — AI Agent Security Layer (MCP)

**Leverage:** Category ownership | **Effort:** Large | **Dependencies:** 02 (correlation) makes it stronger

---

## Why

2026 is the year AI coding agents and MCP servers became mainstream. Every agent executes code, installs packages, calls tools, and reads files — all of which are attack surfaces PicoSentry already covers. The competitors (Snyk, Socket, Endor) are retrofitting agent awareness. We already ship:

- A **syscall sandbox** (seccomp-bpf, L3) — can gate agent-executed commands
- **Prompt injection detection** (L5, watch) — can scan agent prompts before tool calls
- **Output policy enforcement** (L6, watch) — can validate agent outputs before returning to user
- **ml_context formatter** — explicitly designed to inject scan results safely into LLM context
- **Sigstore + Rekor** — for non-repudiation of agent actions

**The play**: position PicoSentry as the security layer for AI coding agents and MCP servers. Scan MCP manifests/tools the way you scan npm packages. Gate or sandbox agent-executed tool calls through L3/L4. Return verdicts via the ml_context channel. This is a category we can own.

## Architecture

### Layer model for agent security

```
User prompt ──→ [PicoSentry Watch] ──→ prompt injection score?
                     ↓ safe
              [MCP Tool Selector] ──→ which tool to call?
                     ↓
              [PicoSentry Sandbox] ──→ gate/sandbox the execution
                     ↓ result
              [PicoSentry Watch] ──→ output policy check? PII redaction?
                     ↓ safe
              [LLM Context Builder] ──→ ml_context with scan findings
                     ↓
              Agent response ──→ User
```

### New component: MCP Gateway

A lightweight FastAPI middleware that sits between the MCP client (Claude Code, Cursor, Codex) and the MCP server, proxying every tool call through the PicoSentry security layers.

**File:** `picosentry/serve/services/mcp_gateway.py`

```python
class MCPGateway:
    """
    Proxies MCP tool calls through PicoSentry's security layers.
    
    - Each tool:tool_call is scanned for prompt injection (watch)
    - Each tool whose execution involves commands/network is sandboxed (sandbox)
    - Each tool result is checked against output policy (watch)
    - Tool results can be tagged with ml_context for the agent's awareness
    """
    
    async def handle_call(
        self,
        tool_name: str,
        arguments: dict,
        session_id: str,
    ) -> MCPCallResult: ...
    
    async def handle_list_tools(
        self,
        session_id: str,
    ) -> list[MCPSecureTool]: ...
```

### Data model

```python
@dataclass
class MCPSecureTool:
    name: str                   # tool name
    description: str            # tool description
    input_schema: dict          # JSON schema for arguments
    security_level: str         # "sandbox" | "gate" | "allow" | "block"
    sandbox_profile: str | None # "network_isolated" | "read_only" | "full"
    allowed_commands: list[str] # for tools that execute commands

@dataclass  
class MCPCallResult:
    tool_name: str
    arguments: dict
    prompt_score: float         # 0.0-1.0 from watch
    prompt_verdict: str         # PASS | WARN | BLOCK
    sandbox_result: dict | None # from sandbox if tool was sandboxed
    output_verdict: str         # PASS | VIOLATION
    output_redacted: str | None # redacted output if PII was found
    kill_chain_score: float | None # from correlation engine if available
    content: str                # actual tool response (may be redacted)
```

## MCP Server Scanning

### What it covers

MCP servers advertise tools via `tools/list`. Each tool has a name, description, and JSON schema for arguments. PicoSentry can:

1. **Scan tool descriptions for prompt injection** — is the tool's help text trying to override the agent's instructions?
2. **Scan tool names for typosquatting** — `filesystem` vs `file-system` vs `filessytem`?
3. **Validate argument schemas for exfiltration vectors** — does a file-read tool accept an arbitrary path?
4. **Check tool capabilities against security policy** — does this server need read-only access but advertise write operations?

### Implementation

**File:** `picosentry/watch/mcp_scanner.py`

```python
def scan_mcp_server(
    name: str,
    tools: list[MCPToolDef],
) -> MCPVerdict:
    """
    Evaluate an MCP server's tool surface.
    Returns a verdict with per-tool security ratings.
    """
```

**CLI integration**

```bash
picosentry watch scan-mcp --server my-server --url http://localhost:8088/mcp
picosentry watch scan-mcp --manifest mcp-servers.json
```

The `mcp-servers.json` manifest format follows the emerging MCP server registry pattern:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path"],
      "env": {}
    }
  }
}
```

## Agent Context Integration

The existing `ml_context` formatter is the hook. Currently it formats scan results so a human (or LLM) can read them. Extend it to produce a structured, verifiable context block that agents can ingest:

**File:** `picosentry/watch/formatters/agent_context.py`

```python
@dataclass
class AgentContextBlock:
    session_id: str
    allowed_tools: list[str]
    blocked_tools: list[str]
    current_sandbox: str          # "none" | "read_only" | "network_isolated" | "full"
    active_findings: list[dict]   # condensed findings for this project
    latest_kill_chains: list[dict] # from CorrelationEngine
    prompt_guard_status: str      # "active" | "bypassed" | "error"
    output_policy: str            # "strict" | "permissive" | "off"
    signed: str                   # HMAC-SHA256 of the above for non-repudiation
    
    def to_text(self) -> str:
        """For inclusion in LLM system prompts."""
        ...
    
    def to_json(self) -> str:
        """For ingestion by agent frameworks."""
        ...
```

### MCP headers

Use MCP's `_meta` field to pass PicoSentry context through tool calls:

```python
tool_call = {
    "name": "read_file",
    "arguments": {"path": "/etc/passwd"},
    "_meta": {
        "picosentry_session": session_id,
        "picosentry_verdict": sandbox_result,
    }
}
```

This gives the MCP server visibility into what security checks were applied upstream, enabling cooperative security (e.g., "the prompt was flagged, so I'll log this call at higher detail").

## Phase Plan

### Phase 1: MCP Gateway (core proxy)

- `MCPGateway` class with tool call proxying through watch (prompt scan) + sandbox (execution gate) + watch (output validation)
- Config file: `.picosentry.mcp.json` defining which tools get what security level
- Standalone mode: `picosentry serve mcp-gateway --port 8767` — runs as an MCP proxy server
- **Fast to MVP**: the existing watch server already has `/v1/scan/prompt` and `/v1/scan/output`. The gateway wires them together.

### Phase 2: MCP Server Scanning

- `mcp_scanner.py` — tool description analysis, typosquat detection for MCP server names
- `scan-mcp` CLI subcommand
- MCP server manifest (JSON) parsing
- Rule: `L5-MCP-TYPO-001` — typosquat MCP server names
- Rule: `L5-MCP-TOOL-001` — suspicious tool descriptions / argument schemas

### Phase 3: Agent Context + Non-Repudiation

- `AgentContextBlock` formatter
- HMAC-signed context blocks for agent system prompts
- `_meta` header injection into MCP tool calls
- Dashboard "Agent Sessions" panel showing active agent connections and their security posture

### Phase 4: IDE/Pre-commit Fast Path

Because the highest-leverage point for agent security is *before the agent runs*, not during:

- **Pre-commit hook**: `picosentry scan --staged` — scans only git-staged files for supply-chain issues
- **IDE extension spec**: VS Code extension with Live Share / inline annotations
- **IDE daemon**: `picosentry serve ide-daemon --watch` — watches the workspace for changes and provides inline annotations via LSP protocol

This isn't strictly MCP-related but is the natural complement — developers need security feedback *before* an agent touches the code, not after.

## Integration Points

| Existing | Used For |
|----------|----------|
| Watch server `/v1/scan/prompt` | Pre-call prompt injection check |
| Watch server `/v1/scan/output` | Post-call output validation |
| Sandbox daemon `POST /api/v1/scan` | Gate tool execution |
| OutputGuard PII detection | 15+ PII patterns in agent output |
| ml_context formatter | Structured agent context block |
| Sigstore + Rekor | Non-repudiation of agent actions |
| Webhook system | Real-time agent activity alerts |
| Serve dashboard | Agent session monitoring |

## Verification

- Unit: MCPGateway proxies a tool call through all 3 security layers (prompt → sandbox → output)
- Unit: MCP server scan identifies a typosquatted tool name
- Integration: `picosentry watch scan-mcp --server filesystem` produces a tool-level security report
- Integration: `AgentContextBlock` round-trips through JSON and validates HMAC signature
- End-to-end: Claude Code connecting through MCP Gateway executes a sandboxed command and gets properly redacted output

## MCP Protocol Compatibility

The MCP Gateway implements the **Model Context Protocol** (`jsonrpc` over stdio/SSE):

- `tools/list` — intercepted and returned with security annotations
- `tools/call` — intercepted, security-checked, forwarded, output-checked  
- `resources/read` — optionally sandbox-gated for file-reading tools
- `prompts/get` — scanned for prompt injection before forwarding to the LLM

The gateway can run in two modes:
1. **Proxy mode**: `mcp-gateway --upstream /path/to/mcp-server` — wraps an existing MCP server
2. **Embedded mode**: Import `MCPGateway` inside an MCP server implementation for native security