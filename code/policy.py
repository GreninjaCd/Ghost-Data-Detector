"""
policy.py: Deletion rules engine.

Maps evidence record categories to required actions based on deletion_rules.csv.
Determines whether a resource is compliant or has a violation.
"""
from typing import Dict, List, Tuple, Any


# Policy map: data category -> required action
# Actions: DELETE, REDACT, ANONYMIZE, RETAIN
CATEGORY_POLICY: Dict[str, str] = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_ATTACHMENT": "DELETE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "ACCOUNT_TOMBSTONE": "REDACT",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN",  # retain but block restore access
    "DATA_FLOW": "DISABLE",      # active data flows must be disabled
}

# State that satisfies the policy for each action
COMPLIANT_STATES: Dict[str, List[str]] = {
    "DELETE": ["ABSENT"],
    "REDACT": ["REDACTED"],
    "ANONYMIZE": ["ANONYMIZED"],
    "RETAIN": ["PRESENT"],
    "DISABLE": ["DISABLED"],
}

# Map category -> finding operation when non-compliant
FINDING_OPERATIONS: Dict[str, str] = {
    "USER_PROFILE": "REPORT_REMAINING_RECORD",
    "SECONDARY_IDENTIFIER": "REPORT_REMAINING_RECORD",
    "SEARCH_INDEX_ENTRY": "REPORT_REMAINING_RECORD",
    "CACHE_ENTRY": "REPORT_REMAINING_RECORD",
    "SUPPORT_ATTACHMENT": "REPORT_REMAINING_RECORD",
    "USER_EXPORT": "REPORT_REMAINING_RECORD",
    "MARKETING_PROFILE": "REPORT_REMAINING_RECORD",
    "SUPPORT_MESSAGE": "REPORT_EXPOSED_PII",
    "EMAIL_DELIVERY_LOG": "REPORT_EXPOSED_PII",
    "ACCOUNT_TOMBSTONE": "REPORT_EXPOSED_PII",
    "ANALYTICS_PROFILE": "REPORT_EXPOSED_PII",
    "PRODUCT_TELEMETRY": "REPORT_EXPOSED_PII",
    "DATA_FLOW": "REPORT_ACTIVE_DATA_FLOW",
    "BACKUP_ARCHIVE": "REPORT_RESTORE_RISK",
}

# Map action -> remediation operation
REMEDIATION_OPERATIONS: Dict[str, str] = {
    "DELETE": "DELETE_RECORD",
    "REDACT": "REDACT_RECORD",
    "ANONYMIZE": "ANONYMIZE_RECORD",
    "DISABLE": "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE": "BLOCK_RESTORE",
}

# Map required action -> verification operation
VERIFICATION_OPERATIONS: Dict[str, str] = {
    "DELETE": "VERIFY_RECORD_ABSENT",
    "REDACT": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
    "RETAIN": "VERIFY_RECORD_PRESENT",
    "DISABLE": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}

# Map state -> operation for COMPLETE verification
STATE_TO_VERIFY_OP: Dict[str, str] = {
    "ABSENT": "VERIFY_RECORD_ABSENT",
    "REDACTED": "VERIFY_RECORD_REDACTED",
    "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED",
    "PRESENT": "VERIFY_RECORD_PRESENT",
    "DISABLED": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCKED": "VERIFY_RESTORE_BLOCKED",
}


def get_required_action(category: str) -> str:
    """Returns the required policy action for a data category."""
    return CATEGORY_POLICY.get(category, "DELETE")


def is_compliant(category: str, current_state: str) -> bool:
    """Returns True if a resource's current state satisfies the deletion policy."""
    action = get_required_action(category)
    compliant = COMPLIANT_STATES.get(action, ["ABSENT"])
    return current_state in compliant


def check_violations(
    resource_states: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Checks each resource against deletion policy.

    Returns:
        violations: list of resources that violate policy (need remediation).
        compliant: list of resources that are policy-compliant.
    """
    violations = []
    compliant = []

    for rec in resource_states:
        category = rec.get("category", "USER_PROFILE")
        state = rec.get("state", "PRESENT")
        action = get_required_action(category)

        if is_compliant(category, state):
            compliant.append(rec)
        else:
            # Special case: BACKUP_ARCHIVE active = REPORT_RESTORE_RISK
            # SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD are always compliant when PRESENT
            if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD") and state == "PRESENT":
                compliant.append(rec)
            else:
                violations.append(rec)

    return violations, compliant
