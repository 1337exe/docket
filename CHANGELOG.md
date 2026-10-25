# Changelog

## 0.3.0
Docket now works on real work, not only samples.
- **Importers**: SARIF, Semgrep, Bandit, Nuclei, Trivy, Gitleaks (auto-detected), scanner paths matched to `--target`.
- **AI providers** (optional): Anthropic, OpenAI, Gemini, Ollama and any OpenAI-compatible server as blind judges (`--judge`),
  escalation reviewers that can argue against but never approve (`--escalate`), and `docket extract` for free-text reports.
  Retries, response cache, call budget, secret masking, untrusted-data fencing.
- **Auto-verify**: reachability and taint checks derived from the cited code; sink class read from the code, not trusted from the scanner.
- **Checks**: taint across 9 sink classes with sanitizer awareness, dependency (lockfile + import), secret plausibility, S3 public access, test-code detection, plugin verifiers (any language).
- **Proof**: 9 new classes (path traversal, open redirect, XXE, CORS, JWT, mass assignment, rate limit, CSRF, command injection).
  New probes: header expectations, repeat (rate limit), sequence (business logic); request budget and delay.
- **Team features**: audited suppressions, hash-chained audit log, baseline, annotated SARIF, `docket.json` config, `init --profile`.
- **Proof packs** (`--pack`) and offline `docket replay` with tamper detection; record/replay of judge, probe and AI answers.
- **MCP**: `court_scope` and `court_stats` tools next to `court_try_finding`.
- **Commands**: `doctor`, `providers`, `extract`, `replay`, `audit`.
- **Lab** grew to 28 claims over 14 classes; **demo** to 30 findings (code, dependencies, secrets, cloud).
- Report: search, "what to do next", suppressed outcome, pinned-hash CSP.
- Rule change: a finding supported only by reachability or an attacker state cannot survive; it needs taint, proof, a probe or a fact.
- Fixes found by running on public repos: wrong scanner class labels killing real bugs, framework-called methods reported as dead code, assigning into `os.environ` treated as an environment read, config-key secrets missed.

## 0.2.0
Tool renamed to Docket. Python taint/reachability checks, live probes with canary, MCP server, ledger, selftest and kit.

## 0.1.0
First version (findingcourt): four checks, blind judge, SARIF export.
