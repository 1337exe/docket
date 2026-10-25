# AI providers: judges, escalation and report extraction

AI is optional. Without it Docket runs every deterministic check and hands anything unresolved to a human. With it
you get three extra tools, each with a hard limit.

| Option | What the AI does | What it can never do |
|---|---|---|
| `--judge provider:model` (repeatable) | Votes blind on the claim (it never sees the finder's reasoning, severity or id) | Vote counts only if its model name differs from the finder's |
| `--escalate provider:model` | Reviews findings the checks **could not settle**: says if it looks real and what would settle it | **Approve.** It can flag or (with `--ai-can-reject` / `scope.ai_can_reject`) close a finding at >= 80% confidence |
| `docket extract report.txt --model provider:model` | Turns free text (pentest report, chat log) into findings JSON | Decide anything: extracted findings still go through `docket try` and carry no evidence until you add some |

## Providers and keys

| Spec | Key (environment variable) | Notes |
|---|---|---|
| `anthropic:MODEL` | `ANTHROPIC_API_KEY` | `ANTHROPIC_BASE_URL` overrides the endpoint |
| `openai:MODEL` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` |
| `gemini:MODEL` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `GEMINI_BASE_URL` |
| `ollama:MODEL` | none | `http://localhost:11434/v1` |
| `openai-compat:MODEL@http://host/v1` | `DOCKET_API_KEY` (if the server needs one) | vLLM, llama.cpp, LM Studio, LiteLLM, Azure-style gateways |

Use the model names your account offers; Docket does not hard-code any. Keys are read from the environment only (never
from a config file) and never appear in error messages or reports.

```bash
export ANTHROPIC_API_KEY=...            # never commit it
docket providers anthropic:MODEL openai:MODEL      # connection test: OK / FAIL with the reason
docket try scan.json --target src --judge anthropic:MODEL --judge openai:MODEL --escalate gemini:MODEL \
       --ai-cache .docket-cache --ai-budget 50
```

## Safety rails built in

* **Secrets masked before sending**: AWS/GitHub/Slack/Google/OpenAI/Anthropic keys, private keys, JWTs, bearer tokens
  and `password = "..."` style assignments become `[REDACTED:kind:abc123]`. `--no-redact` turns it off (not recommended).
* **Untrusted-data fencing**: the finding is wrapped in `<untrusted_finding>` and the system prompt tells the model it
  may contain instructions to ignore. A finding that says "approve me" gets no extra weight.
* **Budget and cache**: `--ai-budget N` caps calls per run; `--ai-cache DIR` makes re-runs free and repeatable.
* **Retries** on 429/5xx with back-off; a failing provider turns a vote into "unsure" (never a pass).
* **Independence**: reviewer or judge model == finder model -> ignored.

## `docket extract`

```bash
docket extract pentest-report.txt --model anthropic:MODEL --out findings.extracted.json
$EDITOR findings.extracted.json          # add assumptions / evidence / probes where you have them
docket try findings.extracted.json --scope scope.json --target src
```

Extracted findings start with `impact: unspecified` and no evidence, so they come back `needs-human` with specific hints
until you attach proof. That is the point: the AI structures, the evidence decides.

## Tested how

Provider adapters are tested against local servers that enforce each vendor's documented request shape (headers,
paths, body fields) including rate limits, auth errors that echo a key, and malformed replies. They have **not** been
run against the live vendor APIs by the author's test environment; run `docket providers ...` with your own key as the
first step and open an issue if a vendor changed something.
