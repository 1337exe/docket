"""Import SARIF results (from any scanner) as findings. Scanners rarely state impact, so a default is required."""
from __future__ import annotations

import json

from .models import Finding


def load_sarif(path, default_impact="unspecified"):
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = []
    for run in doc.get("runs", []):
        tool = ((run.get("tool") or {}).get("driver") or {}).get("name", "sarif")
        for i, r in enumerate(run.get("results", [])):
            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            region = loc.get("region") or {}
            rc = None
            if uri and region.get("startLine"):
                snippet = ((region.get("snippet") or {}).get("text") or "").strip().splitlines()
                rc = {"file": uri, "line": region["startLine"], "quote": snippet[0].strip() if snippet else ""}
            props = r.get("properties") or {}
            out.append(Finding(id=f"{tool}-{r.get('ruleId', 'rule')}-{i}",
                               title=(r.get("message") or {}).get("text", r.get("ruleId", "finding")),
                               impact=props.get("impact", default_impact), severity=r.get("level", ""),
                               target=uri, root_cause=rc, repro_steps=list(props.get("repro_steps", [])),
                               assumptions=list(props.get("assumptions", [])), found_by=tool))
    return out
