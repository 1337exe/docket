"""Turn 'unverified' into a to-do list: what would settle this finding."""
from __future__ import annotations


def hints_for(v) -> list:
    out = []
    f = v.finding
    if v.outcome != "needs-human":
        return out
    for c in v.checks:
        if c.status != "unverified":
            continue
        r = c.reason.lower()
        if c.name == "reachability" and c.status == "unverified":
            if "no verifier for assumption kind" in r:
                out.append("Replace the free-text assumption with a supported kind (fact, aws_policy_allows, entrypoint_reaches, taint_flow, "
                           "dependency_vuln, ...) or add a plugin verifier under scope.external_verifiers.")
            elif "declares no assumptions" in r:
                out.append("Add assumptions to the finding, or run with --auto-verify and --target for Python code findings.")
            elif "no --target" in r:
                out.append("Pass --target <source dir> so code assumptions can be checked.")
            elif "not in facts file" in r:
                out.append("Add the missing object to facts.json (export it from your cloud/IaC) so the claim can be checked.")
            elif "caller's data flow" in r:
                out.append("The sink gets a function parameter. Name the entrypoint that calls it, or add a probe/evidence showing attacker input arrives.")
            else:
                out.append("Reachability could not be decided: " + c.reason[:140])
        elif c.name == "proof":
            out.append(f"Add evidence for a {f.vuln_class or 'classed'} finding (see README: proof rules) or a live probe, then run with --active.")
        elif c.name == "judge" and c.status == "unverified":
            if "no independent judge" in r:
                out.append("Configure a judge: --judge anthropic:MODEL / openai:MODEL / gemini:MODEL / ollama:MODEL (use a model other than the finder's), or --judge-cmd.")
            elif "same model" in r or "vote ignored" in r:
                out.append("Use a judge from a different model family than the finder; same-model votes are ignored.")
            else:
                out.append("Judge was unsure or failed: " + c.reason[:140])
        elif c.name == "reconstruct" and c.status == "unverified":
            out.append("Pass --target so the cited file/line/quote can be checked, or add a quote to root_cause.")
        elif c.name == "ai-review" and c.details:
            w = c.details[0].get("what_would_settle_it", "")
            if w:
                out.append("AI suggestion: " + w)
    return [h for h in dict.fromkeys(out) if h]
