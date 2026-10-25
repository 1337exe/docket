"""The blind judge panel.

Each judge gets the claim and evidence pointers, but NOT the finder's reasoning, severity or id, so
it cannot be persuaded by the story that produced the finding. Independence is enforced per vote:
a judge that names the same model as the finder, or names no model, does not count.
"""
from __future__ import annotations

import json
import shlex
import subprocess


def blind_payload(f) -> dict:
    return {"claim": f.title, "impact": f.impact, "vuln_class": f.vuln_class, "target": f.target,
            "root_cause": f.root_cause, "repro_steps": f.repro_steps,
            "question": "Independently decide whether this claim is real. Reply as JSON: "
                        '{"reproduced": true|false|"unsure", "reason": "...", "model": "<your model name>"}'}


class FileJudge:
    """Recorded verdicts (id -> verdict), for CI and offline replays."""

    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self.data = json.load(fh)

    def __call__(self, finding, payload):
        return self.data.get(finding.id)


class CommandJudge:
    """Runs your own command (any model/CLI). JSON payload on stdin, JSON verdict on stdout. No shell."""

    def __init__(self, cmd: str, timeout: int = 180):
        self.argv, self.timeout = shlex.split(cmd), timeout

    def __call__(self, finding, payload):
        out = subprocess.run(self.argv, input=json.dumps(payload), capture_output=True, text=True,
                             timeout=self.timeout, check=True).stdout
        return json.loads(out)
