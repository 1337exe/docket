import json
import sys
import textwrap

import pytest

from docket.cli import main
from docket.court import try_finding
from docket.judge import CommandJudge, blind_payload
from docket.models import Finding
from docket.scope import Scope
from docket.verifiers import evaluate_policy, safe_join

SCOPE = Scope.from_dict({"accepted_impacts": ["rce"], "out_of_scope_impacts": ["self-xss"],
                         "attacker_states": ["unauthenticated"], "max_repro_steps": 5})


def doc(*s):
    return {"Version": "2012-10-17", "Statement": list(s)}


def test_policy_evaluation():
    allow = doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
    assert evaluate_policy(allow, "s3:GetObject", "arn:x") == "allowed"
    assert evaluate_policy(allow, "iam:PassRole", "*") == "implicit-deny"
    deny = doc({"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"})
    assert evaluate_policy(deny, "s3:DeleteObject", "*") == "denied"
    cond = doc({"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"x": "true"}}})
    assert evaluate_policy(cond, "s3:GetObject", "*") == "unknown"  # never guesses
    assert evaluate_policy(doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}), "s3:Get", "*") == "unknown"


def test_safe_join_blocks_traversal(tmp_path):
    (tmp_path / "a.py").write_text("x")
    assert safe_join(tmp_path, "a.py") is not None
    assert safe_join(tmp_path, "../etc/passwd") is None and safe_join(tmp_path, "/etc/passwd") is None


def mk(**kw):
    base = dict(id="X", title="t", impact="rce", target="app/a.py", found_by="finder",
                assumptions=[{"kind": "attacker_state", "state": "unauthenticated"}],
                root_cause={"file": "a.py", "line": 1, "quote": "danger()"}, repro_steps=["a", "b"])
    base.update(kw)
    return Finding(**base)


@pytest.fixture
def tgt(tmp_path):
    (tmp_path / "a.py").write_text("danger()\n")
    return tmp_path


def good_judge(f, p):
    return {"reproduced": True, "model": "other", "reason": "ok"}


PROOF = [{"type": "marker_output", "payload": "; expr 7 \\* 7191", "expected": "50337", "response_body": "ping ok\n50337"}]


def test_survives_only_when_all_checks_pass(tgt):
    assert try_finding(mk(vuln_class="rce", evidence=PROOF), SCOPE, good_judge, {}, tgt).outcome == "survived"


def test_reachability_alone_is_not_evidence(tgt):
    # a finding whose only support is "an attacker could stand here / this code is called" cannot survive
    v = try_finding(mk(), SCOPE, good_judge, {}, tgt)
    assert v.outcome == "needs-human" and "not evidence" in v.checks[0].reason


def test_each_check_can_kill(tgt):
    k = lambda f, j=good_judge: try_finding(f, SCOPE, j, {}, tgt)
    assert k(mk(assumptions=[{"kind": "attacker_state", "state": "admin"}])).killed_by == "reachability"
    assert k(mk(impact="self-xss")).killed_by == "impact"
    assert k(mk(impact="whatever")).killed_by == "impact"  # not accepted = killed
    assert k(mk(), lambda f, p: {"reproduced": False, "model": "other", "reason": "no"}).killed_by == "judge"
    assert k(mk(root_cause={"file": "a.py", "line": 1, "quote": "eval(q)"})).killed_by == "reconstruct"
    assert k(mk(root_cause={"file": "../x", "line": 1, "quote": "q"})).killed_by == "reconstruct"
    assert k(mk(repro_steps=list("abcdef"))).killed_by == "reconstruct"
    assert k(mk(repro_steps=[])).killed_by == "reconstruct"


def test_unknowns_never_pass(tgt):
    v = try_finding(mk(assumptions=[{"kind": "mystery", "text": "?"}]), SCOPE, good_judge, {}, tgt)
    assert v.outcome == "needs-human" and v.checks[0].status == "unverified"
    assert try_finding(mk(assumptions=[]), SCOPE, good_judge, {}, tgt).outcome == "needs-human"
    assert try_finding(mk(), SCOPE, None, {}, tgt).outcome == "needs-human"  # no judge configured
    assert try_finding(mk(), SCOPE, good_judge, {}, None).outcome == "needs-human"  # code can't be checked


def test_judge_must_be_independent_and_robust(tgt):
    same = lambda f, p: {"reproduced": True, "model": "Finder", "reason": "x"}
    assert try_finding(mk(), SCOPE, same, {}, tgt).checks[3].status == "unverified"
    anon = lambda f, p: {"reproduced": True}
    assert try_finding(mk(), SCOPE, anon, {}, tgt).checks[3].status == "unverified"

    def boom(f, p):
        raise RuntimeError("down")
    assert try_finding(mk(), SCOPE, boom, {}, tgt).checks[3].status == "unverified"  # failure is not a pass
    unsure = lambda f, p: {"reproduced": "unsure", "model": "other"}
    assert try_finding(mk(), SCOPE, unsure, {}, tgt).checks[3].status == "unverified"


def test_judge_is_blind():
    p = blind_payload(mk(reasoning="TRUST ME it is critical", severity="critical", id="SECRET-ID"))
    blob = json.dumps(p)
    assert "TRUST ME" not in blob and "critical" not in blob and "SECRET-ID" not in blob and "finder" not in blob


def test_command_judge(tmp_path):
    s = tmp_path / "j.py"
    s.write_text(textwrap.dedent("""
        import json, sys
        p = json.load(sys.stdin)
        print(json.dumps({"reproduced": "claim" in p, "model": "cmd-judge", "reason": "ran"}))
    """))
    j = CommandJudge(f"{sys.executable} {s}")
    assert j(mk(), blind_payload(mk()))["reproduced"] is True


def test_fact_path_and_network_verifiers(tgt):
    facts = {"security_groups": {"sg": {"ingress": [{"cidr": "0.0.0.0/0", "from": 22, "to": 22}]}}}
    f = mk(assumptions=[{"kind": "network_exposed", "resource": "sg", "port": 22}], root_cause={"fact_path": "security_groups.sg"})
    assert try_finding(f, SCOPE, good_judge, facts, tgt).outcome == "survived"
    f2 = mk(assumptions=[{"kind": "network_exposed", "resource": "sg", "port": 3306}])
    assert try_finding(f2, SCOPE, good_judge, facts, tgt).killed_by == "reachability"


def test_demo_matches_the_story(tmp_path):
    assert main(["demo", "--out-dir", str(tmp_path)]) == 0
    d = json.loads((tmp_path / "report.json").read_text())
    assert d["summary"] == {"total": 30, "survived": 7, "needs_human": 1, "killed": 20, "duplicates": 2, "suppressed": 0,
                            "killed_by": {"reachability": 13, "impact": 3, "proof": 0, "judge": 2, "reconstruct": 2, "ai-review": 0}}
    assert [v["id"] for v in d["verdicts"] if v["outcome"] == "survived"] == ["F01", "F19", "F20", "F22", "F24", "F26", "F28"]
    # F13 fooled the judge but the cited code does not exist -> caught by the reconstruct check
    f13 = next(v for v in d["verdicts"] if v["id"] == "F13")
    assert f13["checks"][3]["status"] == "pass" and f13["killed_by"] == "reconstruct"
    html_ = (tmp_path / "report.html").read_text()
    assert html_.count("<script") == 1 and "Content-Security-Policy" in html_ and "script-src 'sha256-" in html_  # one pinned script, no remote code


def test_sarif_import_and_exit_code(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("danger()\n")
    sarif = {"runs": [{"tool": {"driver": {"name": "scanner"}}, "results": [{
        "ruleId": "R1", "message": {"text": "bad"}, "level": "error",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/a.py"},
                                            "region": {"startLine": 1, "snippet": {"text": "danger()"}}}}],
        "properties": {"repro_steps": ["x", "y"], "assumptions": [{"kind": "attacker_state", "state": "unauthenticated"}]}}]}]}
    (tmp_path / "r.sarif").write_text(json.dumps(sarif))
    (tmp_path / "scope.json").write_text(json.dumps({"accepted_impacts": ["rce"]}))
    out = tmp_path / "o.json"
    args = ["try", str(tmp_path / "r.sarif"), "--scope", str(tmp_path / "scope.json"), "--target", str(tmp_path),
            "--default-impact", "rce", "--out", str(tmp_path / "o.html"), "--json", str(out)]
    assert main(args + ["--fail-on", "needs-human"]) == 2  # no judge -> needs a human
    assert json.loads(out.read_text())["verdicts"][0]["outcome"] == "needs-human"


def test_html_escapes_untrusted_text(tmp_path, tgt):
    from docket.report import render_html
    v = try_finding(mk(title="<script>alert(1)</script>", id="<b>"), SCOPE, None, {}, tgt)
    page = render_html([v])
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_bad_input_exits_cleanly(tmp_path):
    (tmp_path / "f.json").write_text("[{\"nope\": 1}]")
    (tmp_path / "s.json").write_text("{}")
    with pytest.raises(SystemExit) as e:
        main(["try", str(tmp_path / "f.json"), "--scope", str(tmp_path / "s.json")])
    assert e.value.code == 1
