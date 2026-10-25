"""Give scanner findings something checkable: derive reachability and taint assumptions from the cited code."""
from __future__ import annotations

from . import codeverify


def add_auto_assumptions(f, target_dir):
    """Return the list of assumptions that were added (also appended to f.assumptions, marked auto)."""
    rc = f.root_cause or {}
    if not target_dir or not rc.get("file") or not isinstance(rc.get("line"), int):
        return []
    kinds = {a.get("kind") for a in f.assumptions}
    added = []
    cls = codeverify.canon(f.vuln_class)
    if "production_code" not in kinds and cls != "secrets":  # a secret leaked into a test file is still leaked
        added.append({"kind": "production_code", "file": rc["file"], "auto": True, "text": "the cited file ships to production (is not test code)"})
    if cls == "secrets":  # a committed secret is exposed wherever it sits: "is the function called?" is the wrong question
        if "secret_plausible" not in kinds:
            added.append({"kind": "secret_plausible", "file": rc["file"], "line": rc["line"], "auto": True, "text": "the cited value looks like a real secret"})
        f.assumptions.extend(added)
        return added
    if cls == "dependency":
        f.assumptions.extend(added)
        return added
    fn = codeverify.enclosing_function(target_dir, rc["file"], rc["line"])
    if not fn:
        f.assumptions.extend(added)
        return added
    if "entrypoint_reaches" not in kinds:
        added.append({"kind": "entrypoint_reaches", "function": fn, "auto": True, "text": f"{fn}() is reachable from a route"})
    seen_cls = codeverify.class_at_line(target_dir, rc["file"], rc["line"])  # trust the code over the scanner's label
    if seen_cls and seen_cls != cls:
        cls = seen_cls
        if not f.vuln_class:
            f.vuln_class = seen_cls
    if "taint_flow" not in kinds and cls in codeverify.SINKS:
        added.append({"kind": "taint_flow", "function": fn, "vuln_class": cls, "auto": True,
                      "text": f"attacker data reaches a {cls} sink in {fn}()"})
    f.assumptions.extend(added)
    return added
