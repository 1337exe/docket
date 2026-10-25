#!/usr/bin/env python3
"""Offline stand-in judge for testing the plumbing (no model involved).

Reads the blind payload on stdin, answers on stdout. Replace with a real model call (see judge_anthropic.py).
Rule: it only 'reproduces' claims that name a root cause with a quote. It exists to show the contract.
"""
import json
import sys

p = json.load(sys.stdin)
rc = p.get("root_cause") or {}
print(json.dumps({"reproduced": bool(rc.get("quote") or rc.get("fact_path")), "model": "stub-judge",
                  "reason": "stub: root cause was cited" if rc else "stub: nothing cited"}))
