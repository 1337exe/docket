# Docket in CI/CD

Goal: scanners and agents can be as noisy as they like; **only findings with evidence fail the build**.

## GitHub Actions (copy this file to `.github/workflows/docket.yml`)

```yaml
name: docket
on: [pull_request]
permissions: { contents: read, security-events: write }
jobs:
  court:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/1337exe/docket bandit
      - run: bandit -r src -f json -o scan.json || true        # any scanner; the exit code is Docket's job
      - name: put the findings on trial
        run: |
          docket try scan.json --scope .docket/scope.json --target . \
            --suppressions .docket/suppressions.json --audit-log .docket/audit.jsonl \
            --json report.json --sarif-out survivors.sarif --markdown-out summary.md \
            --pack proof-pack.zip --fail-on survived
      - if: always()
        run: cat summary.md >> "$GITHUB_STEP_SUMMARY"
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: survivors.sarif }
      - if: always()
        uses: actions/upload-artifact@v4
        with: { name: docket, path: "docket-report.html\nreport.json\nproof-pack.zip" }
```

* Exit code **2** means something survived (`--fail-on survived`) or also needs a human (`--fail-on needs-human`).
  Exit code 1 means Docket itself could not run (bad input), which is never silently green.
* The job summary shows the table; `docket-report.html` and `proof-pack.zip` are downloadable artifacts.
* If your scanner already uploads SARIF to code scanning and you want the killed results hidden there, run
  `--annotate-sarif annotated.sarif`: it writes a copy of the **input** SARIF where every killed, duplicate or
  suppressed result carries a SARIF `suppressions` entry with Docket's reason. Upload that file instead.

### The reusable action

This repository ships `action.yml`:

```yaml
- uses: 1337exe/docket@main
  with:
    findings: scan.sarif
    scope: .docket/scope.json
    fail-on: survived
    extra-args: "--suppressions .docket/suppressions.json"
```

## GitLab CI

```yaml
docket:
  image: python:3.12
  script:
    - pip install git+https://github.com/1337exe/docket bandit
    - bandit -r src -f json -o scan.json || true
    - docket try scan.json --scope .docket/scope.json --target . --json report.json --markdown-out summary.md --pack proof-pack.zip --fail-on survived
  artifacts: { when: always, paths: [docket-report.html, report.json, summary.md, proof-pack.zip] }
```

## Adding AI in CI (optional)

```yaml
        env: { ANTHROPIC_API_KEY: "${{ secrets.ANTHROPIC_API_KEY }}" }
        run: docket try scan.json --scope .docket/scope.json --target . --escalate anthropic:MODEL \
               --ai-budget 25 --ai-cache .docket/ai-cache --fail-on survived
```

Keep `--ai-budget` set so a noisy scanner cannot run up a bill. Docket masks anything that looks like a secret before
sending text to a provider. Commit `.docket/ai-cache` if you want identical re-runs without new calls.
Docket never sends the AI anything beyond the finding fields (claim, class, target, cited code line, repro steps).

## Baselines and suppressions in a team

* `--baseline last/report.json` skips anything an earlier run already killed or reported, so each PR only shows what is new.
* Put accepted risks in `.docket/suppressions.json` (reviewed in PRs like any code):
  `{"id": "bandit-B608-5", "reason": "internal admin tool, ticket SEC-142", "author": "you", "expires": "2027-03-01"}`.
* Keep the audit log in the repo or a bucket and run `docket audit` on a schedule.

## Gating live probes

`--active` is for staging systems you own. In CI keep it off unless the job runs against an ephemeral environment,
and list that environment's hosts in `scope.active_hosts`. Docket refuses to contact anything else, caps the number of
requests (`--max-probe-requests`, default 300) and never follows redirects.
