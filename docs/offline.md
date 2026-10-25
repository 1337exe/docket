# Offline and air-gapped use

Docket has **no dependencies** and makes **no network calls** unless you turn something on. Everything below works on a
machine with no internet once Docket is installed.

## Install without internet

On a connected machine: `pip download git+https://github.com/1337exe/docket -d wheels` (or `pip wheel . -w wheels`
inside a clone). Copy the `wheels/` folder and run `pip install --no-index --find-links wheels docket` on the
closed network. Python 3.10+ is the only requirement.

## What works offline (everything deterministic)

| Capability | Offline? |
|---|---|
| Scanner imports (SARIF, Semgrep, Bandit, Nuclei, Trivy, Gitleaks) | yes |
| Reachability, taint, test-code, secret, dependency, S3/IAM/network checks | yes (they read your code, lockfiles and `facts.json`) |
| Per-class proof rules and the report | yes |
| Live probes against your own hosts (`--active`) | yes, if the hosts are on your network |
| Proof packs, `docket replay`, audit log | yes |
| `docket selftest`, `docket lab`, `docket kit` | yes (localhost only) |
| Cloud facts | yes: export them once (`aws iam get-account-authorization-details`, security groups, S3 settings) into `facts.json` |

## AI without sending code anywhere

Run a local model and point Docket at it:

```bash
ollama serve &                      # any OpenAI-compatible server works (llama.cpp, vLLM, LM Studio)
docket try scan.json --scope scope.json --target src \
    --judge ollama:llama3 --escalate ollama:qwen2.5 --ai-cache .docket-cache
# other servers:  --judge "openai-compat:MODEL@http://10.0.0.5:8000/v1"
```

Only the finding fields go to the model (claim, class, target, the cited line, repro steps), after secrets are masked.
Local models are weaker judges, so prefer a panel of two different models over one. A judge that has the same model
name as the finder is ignored (independence is enforced by name).

## Hand verdicts to someone else, offline

```bash
docket try scan.json --scope scope.json --target src --pack proof-pack.zip
# on another machine, with no access to the original code or models:
docket replay proof-pack.zip        # re-runs the checks from the pack, verifies the hashes, compares every verdict
```

The pack contains the findings, scope, facts, the **recorded** judge/probe/AI answers and the cited source files
(Python and lockfiles up to a size cap). A reviewer gets the same verdicts without trusting you, a model or a network.
`replay` exits 3 if any file was modified and 1 if any verdict differs.
