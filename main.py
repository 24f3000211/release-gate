from fastapi import FastAPI
from typing import Any

app = FastAPI()

ALLOWED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

HEX = set("0123456789abcdef")


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})
    target = payload.get("target")
    event = payload.get("event")

    # Permissions must be exactly least privilege.
    if workflow.get("permissions") != ALLOWED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # Pull requests must use pull_request, not pull_request_target.
    if event == "pull_request" and workflow.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # Tests, matrix, and fail-fast requirements.
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # Action pinning.
    for action in workflow.get("actions", []):
        if action.get("owner") == "actions":
            continue

        ref = action.get("ref", "")

        if (
            not isinstance(ref, str)
            or len(ref) != 40
            or any(c not in HEX for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # Image hardening.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Production requirements.
    if target == "production":
        if event != "push" or payload.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)