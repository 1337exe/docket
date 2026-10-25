# Docket as an MCP server

Let an AI agent check its own findings **before** it reports them. The agent gets four things: the rules of the
engagement, a verdict with reasons for each finding, and its own kill statistics.

## Setup (Claude Code, Claude Desktop, Cursor, any MCP client)

Add to your client's MCP config (`examples/mcp.json` in this repo):

```json
{
  "mcpServers": {
    "docket": {
      "command": "docket",
      "args": ["mcp", "--scope", "/path/to/scope.json", "--target", "/path/to/repo", "--auto-verify"]
    }
  }
}
```

Claude Code: `claude mcp add docket -- docket mcp --scope /path/to/scope.json --target /path/to/repo --auto-verify`

Optional flags are the same as `docket try`: `--facts`, `--judge provider:model`, `--escalate provider:model`,
`--active` (live probes, own hosts only), `--config docket.json`.

## Tools

| Tool | Use |
|---|---|
| `court_scope` | **Call first.** Returns accepted impacts, attacker states, targets, ineligible patterns. Plan from the impact you are allowed to report, not from a vulnerability class. |
| `court_try_finding` | Submit one finding (`id`, `title`, `impact`, `vuln_class`, `target`, `assumptions`, `evidence`, `probes`, `root_cause`, `repro_steps`). Returns the verdict and every check's reason. |
| `court_stats` | Session counts by outcome and the check that kills most. Use it to change habits. |

Tell your agent (system prompt / CLAUDE.md):

> Before reporting any security finding: call `court_scope`, then `court_try_finding`. Report only `survived`.
> For `needs-human`, read `next_steps` and gather that evidence. For `killed`, stop chasing it and say why it died.
> Never edit a finding to get past a check; add evidence instead.

## What a call looks like (real output, trimmed)

```text
court_try_finding {"id":"a","title":"x","impact":"self-xss","repro_steps":["a","b"]}
-> {"outcome": "killed", "killed_by": "impact", ... "checks": [... {"name": "impact", "status": "fail",
    "reason": "'self-xss' is not an accepted impact (interesting is not enough)"} ...]}
court_stats -> {"tried": 1, "by_outcome": {"killed": 1}, "killed_by": {"impact": 1}, ...}
```

## Notes

* The server speaks MCP over stdio. It reads nothing outside `--target`, and it only contacts hosts in
  `scope.active_hosts` when `--active` is set.
* An agent cannot talk its way past Docket: reasoning, severity and confidence fields are ignored by the checks.
  Findings text is treated as untrusted data even inside AI prompts.
