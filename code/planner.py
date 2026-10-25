"""
planner.py: Generates findings, remediation, and verification steps.

For each case:
1. Classify intent (NOT_APPLICABLE if not a deletion request)
2. Resolve user profile
3. Reconstruct state at audit_at via evidence
4. Apply deletion policy
5. Build step list: FINDING -> REMEDIATION -> VERIFICATION
"""
from typing import List, Dict, Any, Optional, Tuple

from code.intent import classify_request_intent
from code.identity import IdentityGraph
from code.state import reconstruct_state
from code.policy import (
    get_required_action,
    is_compliant,
    FINDING_OPERATIONS,
    REMEDIATION_OPERATIONS,
    VERIFICATION_OPERATIONS,
    STATE_TO_VERIFY_OP,
)
from code.evidence.index import EvidenceIndex


# ===========================================================================
# Lazy singletons
# ===========================================================================
_IDENTITY_GRAPH: Optional[IdentityGraph] = None
_EVIDENCE_INDEX: Optional[EvidenceIndex] = None


def get_identity_graph() -> IdentityGraph:
    global _IDENTITY_GRAPH
    if _IDENTITY_GRAPH is None:
        _IDENTITY_GRAPH = IdentityGraph()
    return _IDENTITY_GRAPH


def get_evidence_index() -> EvidenceIndex:
    global _EVIDENCE_INDEX
    if _EVIDENCE_INDEX is None:
        _EVIDENCE_INDEX = EvidenceIndex()
    return _EVIDENCE_INDEX


# ===========================================================================
# Step builders
# ===========================================================================

def _finding_step(system_id: str, resource_id: str, operation: str, state: str, evidence_id: str) -> Dict[str, Any]:
    return {
        "phase": "FINDING",
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def _remediation_step(system_id: str, resource_id: str, operation: str, state: str) -> Dict[str, Any]:
    return {
        "phase": "REMEDIATION",
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": "",
    }


def _verification_step(system_id: str, resource_id: str, operation: str, state: str, evidence_id: str = "") -> Dict[str, Any]:
    return {
        "phase": "VERIFICATION",
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


# ===========================================================================
# Map from action to expected resulting state (for remediation)
# ===========================================================================
ACTION_TARGET_STATE = {
    "DELETE": "ABSENT",
    "REDACT": "REDACTED",
    "ANONYMIZE": "ANONYMIZED",
    "DISABLE": "DISABLED",
    "RETAIN": "PRESENT",
    "BLOCK_RESTORE": "BLOCKED",
}


# ===========================================================================
# Core planning function
# ===========================================================================

def plan_case(case: Dict[str, str]) -> Dict[str, Any]:
    """
    Plans a single deletion case.
    
    Args:
        case: dict with case_id, email, requested_at, reported_status,
              reported_at, audit_at, request_text
    
    Returns:
        dict with 'case_id', 'deletion_status', 'steps'
    """
    case_id = case["case_id"]
    email = case["email"].strip()
    request_text = case.get("request_text", "")
    audit_at = case["audit_at"]
    reported_at = case.get("reported_at", "")
    requested_at = case.get("requested_at", "")

    # 1. Classify intent
    is_deletion = classify_request_intent(request_text, case_id)
    if not is_deletion:
        return {"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps": []}

    # 2. Resolve user profile
    graph = get_identity_graph()
    profile = graph.resolve_email(email)
    if profile is None:
        # Fallback: try hash lookup
        from code.identity import compute_email_hash
        h = compute_email_hash(email)
        profile = graph.resolve_hash(h)

    if profile is None:
        # Can't identify user - treat as incomplete with no specific findings
        return {"case_id": case_id, "deletion_status": "INCOMPLETE", "steps": []}

    # 3. Reconstruct state at audit_at
    evidence_index = get_evidence_index()
    resource_states = reconstruct_state(
        profile, audit_at, reported_at, requested_at, evidence_index
    )

    # 4. Apply policy checks
    violations = []
    compliant_records = []

    for rec in resource_states:
        category = rec.get("category", "USER_PROFILE")
        state = rec.get("state", "PRESENT")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")
        file_id = rec.get("file_id", "")

        # Skip resources with no valid state/resource
        if not sys_id or not res_id:
            continue

        # Security audit logs and legal hold records always RETAIN - always compliant if PRESENT
        if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") and state == "PRESENT":
            compliant_records.append(rec)
            continue

        action = get_required_action(category)
        compliant = is_compliant(category, state)

        if compliant:
            compliant_records.append(rec)
        else:
            violations.append(rec)

    # 5. Build steps
    if not violations:
        # COMPLETE: only verification steps with evidence
        steps = _build_complete_steps(profile, compliant_records, resource_states, audit_at)
        return {"case_id": case_id, "deletion_status": "COMPLETE", "steps": steps}
    else:
        # INCOMPLETE: findings + remediation + verification
        steps = _build_incomplete_steps(
            profile, violations, compliant_records, resource_states, audit_at
        )
        return {"case_id": case_id, "deletion_status": "INCOMPLETE", "steps": steps}


def _build_complete_steps(
    profile,
    compliant_records: List[Dict[str, Any]],
    all_records: List[Dict[str, Any]],
    audit_at: str,
) -> List[Dict[str, Any]]:
    """
    For COMPLETE cases: build verification steps citing evidence.
    Only include records that are relevant and actually verified.
    """
    steps = []
    seen = set()  # (system_id, resource_id)

    for rec in compliant_records:
        category = rec.get("category", "")
        state = rec.get("state", "")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")
        file_id = rec.get("file_id", "")

        if not sys_id or not res_id or not file_id:
            continue

        key = (sys_id, res_id)
        if key in seen:
            continue
        seen.add(key)

        verify_op = STATE_TO_VERIFY_OP.get(state)
        if verify_op is None:
            continue

        steps.append(_verification_step(sys_id, res_id, verify_op, state, file_id))

    return steps


def _build_incomplete_steps(
    profile,
    violations: List[Dict[str, Any]],
    compliant_records: List[Dict[str, Any]],
    all_records: List[Dict[str, Any]],
    audit_at: str,
) -> List[Dict[str, Any]]:
    """
    For INCOMPLETE cases: build findings + remediation + verification steps.
    """
    finding_steps = []
    remediation_steps = []
    verification_steps = []

    # Track seen resource pairs across sections
    found_set = set()     # (sys_id, res_id) for findings
    remediated_set = set()  # (sys_id, res_id) for remediation

    # ---- FINDINGS ----
    for rec in violations:
        category = rec.get("category", "USER_PROFILE")
        state = rec.get("state", "PRESENT")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")
        file_id = rec.get("file_id", "")

        if not sys_id or not res_id:
            continue

        key = (sys_id, res_id)
        if key in found_set:
            continue
        found_set.add(key)

        # Get the finding operation for this category
        find_op = FINDING_OPERATIONS.get(category, "REPORT_REMAINING_RECORD")

        # Determine state for finding
        find_state = state
        if find_op == "REPORT_RESTORE_RISK":
            find_state = "ACTIVE"
        elif find_op == "REPORT_ACTIVE_DATA_FLOW":
            find_state = "ACTIVE"

        finding_steps.append(_finding_step(sys_id, res_id, find_op, find_state, file_id))

    # ---- REMEDIATION ----
    # First: DISABLE_DATA_FLOW and BLOCK_RESTORE (before modifying records)
    for rec in violations:
        category = rec.get("category", "USER_PROFILE")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")

        if not sys_id or not res_id:
            continue

        key = (sys_id, res_id)

        action = get_required_action(category)

        if action == "DISABLE" and key not in remediated_set:
            remediated_set.add(key)
            remediation_steps.append(_remediation_step(
                sys_id, res_id, "DISABLE_DATA_FLOW", "DISABLED"
            ))

        # BACKUP_ARCHIVE: block restore
        if category == "BACKUP_ARCHIVE" and key not in remediated_set:
            remediated_set.add(key)
            remediation_steps.append(_remediation_step(
                sys_id, res_id, "BLOCK_RESTORE", "BLOCKED"
            ))

    # Then: DELETE, REDACT, ANONYMIZE
    for rec in violations:
        category = rec.get("category", "USER_PROFILE")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")

        if not sys_id or not res_id:
            continue

        key = (sys_id, res_id)
        if key in remediated_set:
            continue

        action = get_required_action(category)
        if action in ("DISABLE", "RETAIN"):
            continue  # already handled or not needed

        rem_op = REMEDIATION_OPERATIONS.get(action)
        if rem_op is None:
            rem_op = "DELETE_RECORD"

        target_state = ACTION_TARGET_STATE.get(action, "ABSENT")
        remediated_set.add(key)
        remediation_steps.append(_remediation_step(sys_id, res_id, rem_op, target_state))

    # ---- VERIFICATION (post-remediation, evidence_id="") ----
    # Include verification for: account (if found in evidence), security audit,
    # and all remediated records

    # Gather unique account resources (USER_PROFILE from account_service)
    # that were present in ANY evidence (compliant or violation)
    verify_set = set()

    # 1. Verify remediated records
    for rec in violations:
        category = rec.get("category", "USER_PROFILE")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")

        if not sys_id or not res_id:
            continue

        key = (sys_id, res_id)
        if key in verify_set:
            continue

        action = get_required_action(category)
        target_state = ACTION_TARGET_STATE.get(action, "ABSENT")
        verify_op = VERIFICATION_OPERATIONS.get(action)

        if action == "DISABLE":
            verify_op = "VERIFY_DATA_FLOW_DISABLED"
        elif action == "BLOCK_RESTORE" or category == "BACKUP_ARCHIVE":
            verify_op = "VERIFY_RESTORE_BLOCKED"
            target_state = "BLOCKED"
        elif action == "DELETE":
            verify_op = "VERIFY_RECORD_ABSENT"
        elif action == "REDACT":
            verify_op = "VERIFY_RECORD_REDACTED"
        elif action == "ANONYMIZE":
            verify_op = "VERIFY_RECORD_ANONYMIZED"

        if verify_op:
            verify_set.add(key)
            verification_steps.append(_verification_step(sys_id, res_id, verify_op, target_state))

    # 2. Verify compliant retained records (security audit logs, etc.)
    for rec in compliant_records:
        category = rec.get("category", "")
        state = rec.get("state", "")
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")

        if not sys_id or not res_id:
            continue

        key = (sys_id, res_id)
        if key in verify_set:
            continue

        if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") and state == "PRESENT":
            verify_set.add(key)
            verification_steps.append(_verification_step(
                sys_id, res_id, "VERIFY_RECORD_PRESENT", "PRESENT"
            ))
        elif category == "USER_PROFILE" and state == "ABSENT" and sys_id == "account_service":
            # Account was already deleted - verify it's absent
            verify_set.add(key)
            verification_steps.append(_verification_step(
                sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT"
            ))

    # 3. If we have no account_service verification yet, add one from violations
    has_account_verify = any(
        s.get("system_id") == "account_service" for s in verification_steps
    )
    if not has_account_verify:
        # Look for account resource in all records
        for rec in all_records:
            sys_id = rec.get("system_id", "")
            res_id = rec.get("resource_id", "")
            category = rec.get("category", "")
            if sys_id == "account_service" and category == "USER_PROFILE":
                key = (sys_id, res_id)
                if key not in verify_set:
                    verify_set.add(key)
                    verification_steps.append(_verification_step(
                        sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT"
                    ))
                break

    all_steps = finding_steps + remediation_steps + verification_steps
    return all_steps
