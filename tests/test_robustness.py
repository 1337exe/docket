"""Hostile / malformed input must never crash the court or turn into a pass."""
import json
import random

import pytest

from docket.court import Court
from docket.models import Finding

SCOPE = {"accepted_impacts": ["rce"], "attacker_states": ["unauthenticated"], "require_judge": False,
         "active_hosts": ["127.0.0.1"]}
WEIRD = [None, 0, -1, 1.5, True, "", "x" * 50000, "ünïcödé 💥", [], {}, [None], [[]], {"a": {"b": None}}, "../../etc/passwd", "/etc/passwd"]


def test_fuzzed_findings_never_crash_or_pass():
    rnd, court = random.Random(1337), Court(SCOPE, target_dir="/tmp", facts={"policies": {"p": {"Statement": [None, 5, "x"]}}})
    keys = ["assumptions", "evidence", "probes", "root_cause", "repro_steps", "impact", "vuln_class", "target", "found_by"]
    for i in range(400):
        d = {"id": f"f{i}", "title": "t"}
        for k in rnd.sample(keys, rnd.randint(1, len(keys))):
            d[k] = rnd.choice(WEIRD)
        if rnd.random() < .5:
            d["assumptions"] = [{"kind": rnd.choice(["fact", "aws_policy_allows", "network_exposed", "file_contains", "taint_flow",
                                                      "entrypoint_reaches", "aws_trust_allows", "flag_enabled", "attacker_state"]),
                                 **{k: rnd.choice(WEIRD) for k in ("path", "policy", "action", "resource", "port", "function", "sink", "op", "value", "pattern", "role", "principal", "name")}}]
        if rnd.random() < .5:
            d["evidence"] = [{"type": rnd.choice(["timing", "boolean_pair", "cross_account", "oob_callback", "marker_output", "sequence", "dom_exec", "upload_retrieved", "unauth_access", "db_error"]),
                              **{k: rnd.choice(WEIRD) for k in ("baseline_ms", "payload_ms", "delay_ms", "status", "marker", "response_body", "nonce", "payload", "expected", "steps")}}]
        try:
            v = court.try_one(d)
        except ValueError:
            continue  # rejected as invalid input is fine
        assert v["outcome"] in ("killed", "needs-human", "duplicate", "survived")
        if v["outcome"] == "survived":  # garbage must not sneak through all checks
            pytest.fail(f"garbage survived: {json.dumps(d)[:200]}")


def test_from_dict_rejects_bad_shapes():
    for bad in (None, [], "x", {}, {"id": "a"}, {"title": "a"}, {"id": "", "title": "t"}):
        with pytest.raises(ValueError):
            Finding.from_dict(bad)


def test_probe_to_unlisted_host_is_never_contacted():
    from docket.active import run_probe
    from docket.scope import Scope
    sc = Scope.from_dict(SCOPE)
    for url in ("http://169.254.169.254/latest/meta-data/", "http://[::1]/", "file:///etc/passwd", "ftp://127.0.0.1/", "http://127.0.0.1.evil.com/"):
        assert run_probe({"kind": "http_probe", "url": url}, sc)[0] in ("unverified", "fail")
