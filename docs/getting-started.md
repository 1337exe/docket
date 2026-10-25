# Getting started: five ways to use Docket

Pick the line that matches what you have. Every path starts with `pip install` and `docket doctor`.

| You have | Do this | Guide |
|---|---|---|
| Output from a scanner (Bandit, Semgrep, Nuclei, Trivy, Gitleaks, any SARIF) | `docket try scan.json --scope scope.json --target ./src` | below |
| A CI pipeline (GitHub Actions, GitLab CI) | add one job, fail the build on survivors | [ci-cd.md](ci-cd.md) |
| An AI agent (Claude Code, Cursor, your own) | `docket mcp`, the agent checks its findings before reporting | [mcp.md](mcp.md) |
| A closed network, or code that cannot leave the building | everything runs locally; use Ollama if you want a judge | [offline.md](offline.md) |
| A pentest report, bug write-up or chat transcript | `docket extract` turns the text into findings, then `docket try` | [ai-providers.md](ai-providers.md) |
| Your own checks (internal tools, other languages) | write a plugin verifier in any language | [reference.md](reference.md#plugin-verifiers) |

## The 10-minute path on your own project

```bash
pip install git+https://github.com/1337exe/docket
docket doctor                                   # tells you exactly what to fix, if anything
docket init . --profile ci                      # writes scope.json, docket.json, an empty suppressions file
$EDITOR scope.json                              # list the impacts you would actually fix or pay for

bandit -r src -f json -o scan.json              # any supported scanner
docket try scan.json --target src --pack proof-pack.zip
open docket-report.html                         # survivors first, then "needs a human", then the killed with reasons
```

What happens: Docket reads the scanner output, looks at the code each result cites, and checks whether the code is
reachable from a route, whether request data reaches the dangerous call, whether it is test code, whether a value
that looks like a secret really is one, and whether the dependency version is really affected. A finding survives only
when a check backed by **evidence** passes. Everything it could not decide is `needs-human` with a "what to do next" box.

## Understand the verdicts

| Verdict | Meaning | What you do |
|---|---|---|
| `survived` | Every check passed or was skipped by your scope, and the claim rests on more than "this code is reachable" (taint, proof, a probe, a secret/dependency/policy fact) | Review it, fix it or report it |
| `needs-human` | Nothing failed, but something could not be verified | Read the "What to do next" box (each hint names the exact flag or evidence to add) |
| `killed` | A check failed. The report says which one and why | Nothing. If you disagree, the reason is specific enough to argue with |
| `duplicate` | Same root cause already seen in this run, in `known_issues`, or in a `--baseline` report | Nothing |
| `suppressed` | A person said "ignore this" in `docket-suppressions.json`, with a reason and an author | Re-review when the rule expires |

Rule that never changes: **AI may say no; only evidence can say yes.** A model's opinion can kill or flag a finding.
It can never make one survive.

## Make it yours

* `scope.json` is the contract. What do you consider a real problem on this system? ([reference](reference.md#scope))
* `docket.json` holds your defaults so the command stays short. Command-line flags always win.
* `docket-suppressions.json` records accepted risk. Each entry needs `reason` and `author`; `expires` is optional but
  recommended. Expired entries are ignored and printed as a warning, so nothing is hidden forever.
* `--audit-log docket-audit.jsonl` appends a hash-chained record of every verdict. `docket audit docket-audit.jsonl`
  detects edits and deletions (tamper-evident, not tamper-proof: keep a copy of the last hash somewhere else).
* `--pack proof-pack.zip` bundles the inputs, the recorded judge/probe/AI answers, the cited source and a hash manifest.
  `docket replay proof-pack.zip` re-runs everything offline and fails if a single verdict differs or a file was altered.
