#!/usr/bin/env python3
"""Blind judge backed by the Anthropic Messages API (stdlib only).

    export ANTHROPIC_API_KEY=...        # never commit it
    export JUDGE_MODEL=<model id>       # pick a model DIFFERENT from the one that found the finding
    docket try findings.json --scope scope.json --judge-cmd "python examples/judge_anthropic.py"

Simpler: `docket try ... --judge anthropic:<model>` does the same with retries, caching and secret masking.
This file stays as a minimal, readable example of the judge contract (JSON in, JSON out).
Tested against a local mock that enforces the Messages API request shape; not run against the live API.
"""
import json
import os
import sys
import urllib.request

payload = json.load(sys.stdin)
model = os.environ["JUDGE_MODEL"]
prompt = ("You are an independent security reviewer. You have NOT seen anyone else's reasoning. "
          "Decide whether the claim below is real, using only the evidence pointers given. Be sceptical: "
          "if you cannot confirm it from what is given, answer \"unsure\". Reply with JSON only: "
          '{"reproduced": true|false|"unsure", "reason": "<one sentence>"}\n\n' + json.dumps(payload, indent=2))
base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
req = urllib.request.Request(base + "/v1/messages", method="POST", data=json.dumps({
    "model": model, "max_tokens": 400, "messages": [{"role": "user", "content": prompt}]}).encode(),
    headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01", "content-type": "application/json"})
with urllib.request.urlopen(req, timeout=120) as r:
    text = "".join(b.get("text", "") for b in json.load(r)["content"] if b.get("type") == "text")
start, end = text.find("{"), text.rfind("}")
verdict = json.loads(text[start:end + 1]) if start >= 0 else {"reproduced": "unsure", "reason": "unparseable reply"}
verdict["model"] = model  # the court compares this with the finder's model to enforce independence
print(json.dumps(verdict))
