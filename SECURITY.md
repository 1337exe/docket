# Security and responsible use

- Report vulnerabilities in Docket through GitHub's **private vulnerability reporting** on this repository (Security tab > Report a vulnerability).
- Live probes (`--active`) send real requests. Use them only on systems you own or are authorised to test, and list
  those hosts in `scope.active_hosts`; Docket contacts nothing else. Redirects are never followed and a request budget applies.
- `docket lab` runs a deliberately vulnerable app. It binds to 127.0.0.1 only. Never expose it to a network.
- API keys are read from environment variables only, never from config, scope or findings files, and never printed.
  Secrets found in findings are masked before anything is sent to an AI provider and in reports (`--no-redact` disables this).
- Docket reads code and lockfiles; it never executes the code it analyses. Plugin verifiers and judge commands you configure *are* executed (without a shell): only configure commands you trust.
- A proof pack contains the cited source files. Check it before sharing outside your organisation.
- The audit log is tamper-evident, not tamper-proof: store the latest hash somewhere an attacker cannot also edit.
