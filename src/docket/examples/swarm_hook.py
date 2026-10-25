"""Embed the court in your own agent loop: nothing leaves the building until it survives."""
from docket.court import Court
from docket.judge import CommandJudge
from docket.scope import Scope

court = Court(Scope.load("scope.json"),
              judges=[CommandJudge("python examples/judge_stub.py")],   # swap for real, different-model judges
              facts={}, target_dir="./src")


def report_if_real(finding: dict):
    verdict = court.try_one(finding)            # same dict shape as findings.json
    if verdict["outcome"] == "survived":
        print("REPORT:", finding["title"])      # file the ticket / send to the human
    elif verdict["outcome"] == "needs-human":
        print("REVIEW:", finding["title"], [c["reason"] for c in verdict["checks"] if c["status"] == "unverified"])
    else:                                       # killed or duplicate: feed the reason back to the agent so it stops chasing it
        print("DROP:", finding["title"], verdict["killed_by"] or verdict["duplicate_of"])
    return verdict
