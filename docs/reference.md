# Reference

## Input formats (auto-detected; force one with `--format`)

SARIF 2.1 (any tool) · Semgrep JSON · Bandit JSON · Nuclei JSONL · Trivy JSON · Gitleaks JSON · Docket JSON (a list, or
`{"findings": [...]}`). Scanners rarely say what a bug would *mean*, so Docket maps the finding class to an impact with
`scope.impact_map` (or `--default-impact`). With no impact at all the finding is `needs-human`, never killed for it.
Scanner paths (`src/app/x.py`, `./x.py`, absolute) are matched to `--target` automatically. Because scanners give a
location and not a story, Docket writes two repro steps from that location ("open file:line", "confirm the reported condition").

## scope.json {#scope}

| Key | Meaning |
|---|---|
| `accepted_impacts` | Impacts you would fix or pay for. Anything else is killed ("interesting is not enough") |
| `out_of_scope_impacts`, `ineligible_patterns` | Explicit no-gos; regexes on titles |
| `known_issues` | Fingerprints or title fragments already reported |
| `attacker_states`, `forbidden_states` | Where an attacker may start; keywords for states the protocol never allows |
| `in_scope_targets` | Glob patterns for `finding.target` (empty = anything) |
| `active_hosts` | The only hosts live probes may touch |
| `impact_map` | `vuln_class -> impact` for scanner imports |
| `max_repro_steps` (8) | Longer repro chains cannot be rebuilt by hand |
| `require_proof`, `require_judge` (true), `judge_quorum` (`majority`/`unanimous`/`any`) | How strict the proof and judge checks are |
| `ai_can_reject` | Let a confident `--escalate` AI close a finding it believes is false. It can never approve |
| `external_verifiers` | `name -> command` for plugin verifiers |

## Finding

`id title impact vuln_class target found_by severity assumptions evidence probes root_cause repro_steps`.
`root_cause` is `{"file","line","quote"}` (code) or `{"fact_path": "policies.web-role"}` (cloud facts).
Classes with built-in proof rules: sqli, idor, auth-bypass, xss, ssrf, rce, ssti, file-upload, logic, path-traversal,
open-redirect, xxe, cors, jwt, mass-assignment, rate-limit, csrf, cmdi.

## Assumption kinds (reachability check)

| Kind | Fields | Decides |
|---|---|---|
| `attacker_state` | `state` | start state allowed by scope |
| `entrypoint_reaches` | `function` | reachable from a Flask/FastAPI/Django/DRF/Tornado-style route or view class (Python) |
| `taint_flow` | `function`, `sink`, `vuln_class`, `sanitizers`, `sources` | request data reaches a sink of that class without a sanitizer |
| `production_code` | `file` | not test/fixture code |
| `secret_plausible` | `file`, `line` | value matches a known key format or looks like a hardcoded credential, not a placeholder. **Liveness is not verified** |
| `dependency_vuln` | `package`, `fixed` | lockfile version is below the fixed version and the package is imported |
| `aws_policy_allows` / `aws_trust_allows` / `network_exposed` / `aws_s3_public` | policy / role / security group / bucket names from `facts.json` | cloud claims |
| `flag_enabled`, `fact`, `file_contains` | | config and file facts |
| `external` | `verifier` (+ anything) | your own plugin |

Sink classes understood by `taint_flow`: sqli, cmdi, path-traversal, ssrf, deserialization, ssti, xss, open-redirect, code-exec.
Safe-by-construction patterns are recognised (parameterized SQL, argv-list subprocess without a shell, `yaml` safe
loaders, `shlex.quote`, `os.path.basename`, `html.escape`, `int()`, `ast.literal_eval`, ...). A function parameter that
no route is shown to feed is `unverified` ("caller's data flow is not traced"), never a pass.

## Evidence types (proof check)

`boolean_pair timing db_error oob_callback cross_account unauth_access dom_exec marker_output expression_eval
upload_retrieved sequence file_read redirect_observed cors_misconfig token_accepted privilege_changed no_throttle
cross_origin_state_change`. Never counts as proof: `scanner_alert cve_match status_200 status_500 agent_explanation
confidence screenshot reflection error_names_host`. A computed value must not appear in the payload (otherwise the
response may just be an echo).

## Live probes (need `--active`; own hosts in `scope.active_hosts` only)

`http_probe` (status, body regex, `expect_headers`, `expect_absent_headers`) · `boolean_probe` (true/false control pair
against a baseline) · `ssrf_probe` (a nonce URL on Docket's canary; only a real callback counts) · `repeat_probe`
(n requests, fails if throttled; max 50) · `sequence_probe` (2–10 ordered steps for business-logic flaws).
Safety: GET/HEAD/POST, redirects never followed, bodies capped at 64 KB, `--max-probe-requests` (default 300), `--probe-delay`.

## Plugin verifiers {#plugin-verifiers}

```json
"external_verifiers": {"kms-check": "python3 tools/kms_check.py"}
```
```json
{"kind": "external", "verifier": "kms-check", "key_id": "alias/prod"}
```
Docket runs the command (no shell) with `{"assumption": {...}, "target": "/path"}` on stdin; it must print
`{"status": "pass|fail|unverified", "reason": "..."}`. Any language. A crash, timeout or bad output is `unverified`.

## docket.json (defaults; command-line flags win; unknown keys are an error)

`scope facts target judge judge_cmd judge_file escalate ai_can_reject ai_cache ai_budget no_redact suppressions audit_log
auto_verify active max_probe_requests probe_delay canary_log out json_out sarif_out markdown_out ledger baseline
default_impact fail_on`. Relative paths are relative to the config file. `auto_verify` defaults to on for scanner imports
that come with `--target`, off for hand-written Docket JSON.

## Suppressions file

```json
[{"id": "bandit-B608-5", "reason": "internal tool, ticket SEC-142", "author": "you", "expires": "2027-03-01"}]
```
Matchers: `fingerprint`, `id`, `title_contains` (all given must match). `reason` and `author` are required.
Unknown keys are rejected. Expired rules never match and are printed as warnings.

## Commands

`try` · `replay` · `mcp` · `extract` · `providers` · `doctor` · `audit` · `init [--profile ci|bugbounty|cloud]` ·
`demo` · `lab [--serve]` · `canary` · `stats` · `selftest` · `kit`.
Exit codes: `0` ok · `1` error (bad input; never a silent green) · `2` `--fail-on` tripped · `3` replay found a modified file.
