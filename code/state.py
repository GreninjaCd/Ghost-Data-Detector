"""
state.py: Point-in-time resource state reconstruction at audit_at.

Gathers all evidence records for a user filtered to <=audit_at, then
reconstructs the 'winning' state for each (system_id, resource_id) pair.
"""
from typing import List, Dict, Any, Optional
from code.identity import UserProfile
from code.loaders import load_system_activity
from code.evidence.index import EvidenceIndex


# Lazy-loaded singletons
_SYSTEM_ACTIVITY: Optional[List[Dict[str, str]]] = None


def _get_system_activity() -> List[Dict[str, str]]:
    global _SYSTEM_ACTIVITY
    if _SYSTEM_ACTIVITY is None:
        _SYSTEM_ACTIVITY = load_system_activity()
    return _SYSTEM_ACTIVITY


def get_deletion_batch_resources(profile: UserProfile, reported_at: str, requested_at: str) -> Dict[str, str]:
    """
    Finds all resources associated with a user's deletion workflow batch in system_activity.
    
    Looks for deletion-related events that reference any of the user's identifiers
    within a time window around the reported_at timestamp (±48 hours).
    
    Returns a dict of resource_id -> source_system mapping.
    """
    uid = profile.user_id
    # Build a set of all known IDs for this user to match against activity details
    user_ids = {uid}
    user_ids.update(profile.emails)
    user_ids.update(profile.phones)
    user_ids.update(profile.hashes)

    # Also build numeric ID for matching account_XXXX patterns
    uid_number = uid.replace("user_", "")

    activities = _get_system_activity()

    # Parse reported_at and requested_at
    # Window: from 1 day before requested_at to 3 days after reported_at
    try:
        from datetime import datetime, timedelta, timezone
        rep_dt = datetime.fromisoformat(reported_at.replace("Z", "+00:00"))
        req_dt = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))
        window_start = req_dt - timedelta(days=1)
        window_end = rep_dt + timedelta(days=3)
    except Exception:
        window_start = None
        window_end = None

    resources = {}
    deletion_event_types = {
        "DELETE_RECORD", "DISABLE_CONNECTOR", "BLOCK_RESTORE",
        "ANONYMIZE_RECORD", "REDACT_RECORD", "PURGE_EXPORT",
        "REDACT_SUPPORT", "ANONYMIZE_ANALYTICS"
    }

    for act in activities:
        event_time = act.get("event_time", "")
        event_type = act.get("event_type", "")
        resource_id = act.get("resource_id", "")
        details = act.get("details", "")
        source_system = act.get("source_system", "")
        target_system = act.get("target_system", "")

        if not resource_id:
            continue

        # Check time window
        if window_start and window_end:
            try:
                from datetime import datetime
                ev_dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                if ev_dt < window_start or ev_dt > window_end:
                    continue
            except Exception:
                continue

        # Check if this activity references this user
        is_user_match = False

        # Check if the details/resource mentions the user
        combined_text = f"{details} {resource_id}".lower()

        for uid_val in user_ids:
            if uid_val.lower() in combined_text:
                is_user_match = True
                break

        # Also check numeric ID pattern in resource_id (e.g. account_123 for user_123)
        if not is_user_match and uid_number:
            if (f"account_{uid_number}" in resource_id or
                    f"search_{uid_number}" in resource_id or
                    f"analytics_{uid_number}" in resource_id or
                    f"support_{uid_number}" in resource_id or
                    f"backup_{uid_number}" in resource_id or
                    f"data_flow_{uid_number}" in resource_id or
                    f"export_{uid_number}" in resource_id or
                    f"tombstone_{uid_number}" in resource_id or
                    f"audit_record_{uid_number}" in resource_id):
                is_user_match = True

        if is_user_match and event_type in deletion_event_types:
            sys = target_system or source_system
            resources[resource_id] = sys

    return resources


def reconstruct_state(
    profile: UserProfile,
    audit_at: str,
    reported_at: str,
    requested_at: str,
    evidence_index: EvidenceIndex,
) -> List[Dict[str, Any]]:
    """
    Returns all evidence records relevant to a user, filtered to <=audit_at.
    
    For each (system_id, resource_id) pair, we return the latest evidence record
    captured at or before audit_at.
    
    Returns a list of resource state dicts:
    {
        'system_id', 'resource_id', 'category', 'state', 'pii_exposed',
        'file_id', 'captured_at', 'identifiers', 'details'
    }
    """
    user_records = evidence_index.get_records_for_user(profile, audit_at)

    # Deduplicate: keep the latest record per (system_id, resource_id)
    latest: Dict[tuple, Dict[str, Any]] = {}
    for rec in user_records:
        sys_id = rec.get("system_id", "")
        res_id = rec.get("resource_id", "")
        if not sys_id or not res_id:
            continue
        key = (sys_id, res_id)
        existing = latest.get(key)
        if existing is None or rec.get("captured_at", "") >= existing.get("captured_at", ""):
            latest[key] = rec

    return list(latest.values())
