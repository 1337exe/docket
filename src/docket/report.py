from __future__ import annotations

from . import __version__

import base64
import hashlib
import html
import json

from .court import summarize
from .models import CHECKS
from .redact import redact_obj, redact_text

REDACT = True


def E(x):
    """HTML-escape, masking anything that looks like a secret first (reports get shared)."""
    x = str(x)
    return html.escape(redact_text(x) if REDACT else x)

CSS = """
:root{--bg:#f7f7f5;--fg:#1b1b1b;--mut:#666;--card:#fff;--line:#ddd;--ok:#1a7f37;--bad:#c62828;--warn:#b26a00;--bar:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#eee;--mut:#9a9a9a;--card:#1d1d1d;--line:#333;--ok:#4cc26b;--bad:#ff6b6b;--warn:#e8a33d;--bar:#7c93ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:20px 16px 60px}h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--mut);margin:0 0 20px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:22px}
.c{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.c b{display:block;font-size:26px}
.f{margin:0 0 22px}.row{display:flex;align-items:center;gap:10px;margin:6px 0}.lab{width:150px;flex:none;font-size:13px;color:var(--mut)}
.track{flex:1;background:var(--line);border-radius:6px;height:18px;overflow:hidden}.fill{background:var(--bar);height:100%}.n{width:34px;text-align:right;font-variant-numeric:tabular-nums}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:0}summary{cursor:pointer;padding:10px 12px;display:flex;gap:8px;flex-wrap:wrap;align-items:baseline}
.tag{font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;border:1px solid currentColor}
.survived{color:var(--ok)}.killed{color:var(--bad)}.needs-human{color:var(--warn)}.duplicate{color:var(--mut)}.suppressed{color:var(--mut)}.skipped,.ignored{color:var(--mut)}.next{margin:8px 0 0;padding:8px 10px;border-left:3px solid var(--warn);background:var(--bg);font-size:13px}.next li{margin:2px 0}#q{width:100%;padding:8px 10px;margin:0 0 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font:inherit}.meta{font-size:12px;color:var(--mut);margin-top:20px}.sm{font-size:12px;color:var(--mut);margin:2px 0 0}
.body{padding:0 12px 12px}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:5px 6px;border-top:1px solid var(--line);vertical-align:top}
.pass{color:var(--ok)}.fail{color:var(--bad)}.unverified{color:var(--warn)}.mut{color:var(--mut)}
"""


ORDER = {"survived": 0, "needs-human": 1, "killed": 2, "duplicate": 3, "suppressed": 4}


def render_json(verdicts) -> str:
    data = {"summary": summarize(verdicts), "verdicts": [v.to_dict() for v in verdicts]}
    return json.dumps(redact_obj(data) if REDACT else data, indent=2)


def funnel(verdicts):
    remaining = len(verdicts)
    rows = [("Candidates", remaining)]
    remaining -= sum(1 for v in verdicts if v.outcome == "duplicate")
    rows.append(("After duplicates", remaining))
    for c in CHECKS:
        remaining -= sum(1 for v in verdicts if v.outcome == "killed" and v.killed_by == c)
        rows.append((f"After {c}", remaining))
    return rows


def render_html(verdicts, title="Docket report", meta=None) -> str:
    s = summarize(verdicts)
    total = max(s["total"], 1)
    bars = "".join(
        f'<div class="row"><div class="lab">{E(l)}</div><div class="track"><div class="fill" '
        f'style="width:{n / total * 100:.1f}%"></div></div><div class="n">{n}</div></div>' for l, n in funnel(verdicts))
    order = ORDER
    items = []
    for v in sorted(verdicts, key=lambda v: (order[v.outcome], v.finding.id)):
        f = v.finding
        def cell(c):
            sub = "".join(f'<div class="sm">{E(str(x.get("status", "")))}: ' + E(str(x.get("reason", x.get("assumption", ""))))
                          + "</div>" for x in c.details[:8] if isinstance(x, dict))
            return f'<tr><td>{E(c.name)}</td><td class="{E(c.status)}">{E(c.status)}</td><td>{E(c.reason)}{sub}</td></tr>'
        rows = "".join(cell(c) for c in v.checks) or '<tr><td colspan="3" class="mut">not tried: duplicate</td></tr>'
        why = f' <span class="mut">died at {E(v.killed_by)}</span>' if v.killed_by else \
            f' <span class="mut">duplicate of {E(v.duplicate_of)}</span>' if v.duplicate_of else ""
        nxt = ""
        if v.next_steps:
            nxt = '<div class="next"><b>What to do next</b><ul>' + "".join(f"<li>{E(x)}</li>" for x in v.next_steps) + "</ul></div>"
        if v.note:
            nxt += f'<div class="next"><b>Suppressed:</b> {E(v.note)}</div>'
        items.append(
            f'<details data-q="{E((f.title + " " + f.id + " " + v.outcome + " " + f.vuln_class + " " + f.found_by).lower())}"><summary><span class="tag {E(v.outcome)}">{E(v.outcome)}</span><b>{E(f.title)}</b>'
            f'<span class="mut">{E(f.id)} · {E(f.impact)} · {E(f.found_by or "unknown finder")}</span>{why}</summary>'
            f'<div class="body"><table>{rows}</table>{nxt}</div></details>')
    cards = (f'<div class="c"><b>{s["total"]}</b>candidates</div><div class="c"><b class="survived">{s["survived"]}</b>survived</div>'
             f'<div class="c"><b class="needs-human">{s["needs_human"]}</b>need a human</div>'
             f'<div class="c"><b class="killed">{s["killed"]}</b>killed</div>'
             f'<div class="c"><b class="duplicate">{s["duplicates"]}</b>duplicates</div>'
             f'<div class="c"><b class="suppressed">{s["suppressed"]}</b>suppressed</div>')
    metaline = ""
    if meta:
        metaline = '<p class="meta">' + E(" · ".join(f"{k}: {v}" for k, v in meta.items())) + "</p>"
    js_body = ("document.getElementById('q').addEventListener('input',function(e){var t=e.target.value.toLowerCase();"
          "document.querySelectorAll('details[data-q]').forEach(function(d){d.style.display=d.dataset.q.indexOf(t)<0?'none':''})})")
    js = "<script>" + js_body + "</script>"
    csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + base64.b64encode(hashlib.sha256(js_body.encode()).digest()).decode() + "'"
    kb = " · ".join(f"{c}: {n}" for c, n in s["killed_by"].items())
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
            f'<title>{E(title)}</title><style>{CSS}</style></head><body><main><h1>{E(title)}</h1>'
            f'<p class="sub">Checks per finding: reachability, impact, proof, judge, reconstruct (+ optional AI review). Killed by check: {E(kb)}</p><div class="cards">{cards}</div>'
            f'<div class="f">{bars}</div><input id="q" placeholder="Filter by title, outcome, class, finder..." aria-label="filter findings">'
            f'{"".join(items)}{metaline}</main>{js}</body></html>')


def render_markdown(verdicts) -> str:
    s = summarize(verdicts)
    lines = ["## Docket", "",
             f"{s['total']} candidates: **{s['survived']} survived**, {s['needs_human']} need a human, "
             f"{s['killed']} killed, {s['duplicates']} duplicates, {s['suppressed']} suppressed.", "",
             "| Outcome | Finding | Impact | Why |", "|---|---|---|---|"]
    order = ORDER
    for v in sorted(verdicts, key=lambda v: (order[v.outcome], v.finding.id)):
        why = next((c.reason for c in v.checks if c.name == v.killed_by), "") if v.killed_by else \
            ("duplicate of " + v.duplicate_of if v.duplicate_of else
             "; ".join(f"{c.name}: {c.reason}" for c in v.checks if c.status == "unverified")[:200] or "all checks passed")
        t = lambda x: str(x).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {v.outcome} | {t(v.finding.id)}: {t(v.finding.title)} | {t(v.finding.impact)} | "
                     + (f"died at {v.killed_by}: " if v.killed_by else "") + f"{t(why)[:160]} |")
    return "\n".join(lines) + "\n"


def render_sarif(verdicts) -> str:
    """Survivors and needs-human findings as SARIF, so GitHub code scanning / other tools can ingest them."""
    results = []
    for v in verdicts:
        if v.outcome not in ("survived", "needs-human"):
            continue
        f, rc = v.finding, v.finding.root_cause or {}
        r = {"ruleId": f"docket/{f.vuln_class or f.impact}", "level": "error" if v.outcome == "survived" else "warning",
             "message": {"text": f"{f.title} [{v.outcome}]"},
             "partialFingerprints": {"docket": v.fingerprint},
             "properties": {"outcome": v.outcome, "impact": f.impact, "found_by": f.found_by}}
        if rc.get("file") and isinstance(rc.get("line"), int):
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": rc["file"]},
                                                    "region": {"startLine": rc["line"]}}}]
        results.append(r)
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "docket", "version": __version__}}, "results": results}]}, indent=2)
