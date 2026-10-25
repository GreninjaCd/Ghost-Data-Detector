import json
import re
from pathlib import Path
from typing import List, Dict, Any


def parse_log_evidence(file_path: Path, file_id: str, captured_at: str) -> List[Dict[str, Any]]:
    """
    Parses key-value formatted and JSON-lines formatted log traces under dataset/evidence/logs/.
    """
    records = []
    # Track resources across lines in the same trace
    trace_context: Dict[str, Dict[str, Any]] = {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log file {file_path}: {e}")
        return records

    for line in lines:
        line = line.strip()
        if not line:
            continue

        timestamp = line.split(" ")[0] if " " in line else captured_at

        # Check if line contains JSON payload
        kv = {}
        json_start = line.find("{")
        json_end = line.rfind("}")
        if json_start != -1 and json_end != -1 and json_end > json_start:
            try:
                kv = json.loads(line[json_start:json_end+1])
            except Exception:
                kv = {}

        # Fallback to key=value regex parsing if not JSON
        if not kv:
            for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([^\s]+))', line):
                key = m.group(1)
                val = m.group(2) if m.group(2) is not None else m.group(3)
                kv[key] = val

        trace_id = kv.get("trace_id")
        res_id = kv.get("resource_id")
        service = kv.get("service") or kv.get("logger")
        event = kv.get("event", "")

        # Collect identifiers
        idents = set()
        for k in ["lookup_key", "subject_key", "scan_key", "subject_ref", "correlation_key",
                  "customer_email", "customer_reference", "requester_email",
                  "owner_email", "email", "match_key", "matched_value"]:
            val = kv.get(k)
            if val and str(val).lower() not in ("null", "none", ""):
                idents.add(str(val))

        # Update trace context
        if trace_id:
            if trace_id not in trace_context:
                trace_context[trace_id] = {"identifiers": set(), "resource_id": None, "service": service}
            trace_context[trace_id]["identifiers"].update(idents)
            if res_id:
                trace_context[trace_id]["resource_id"] = res_id
            if service:
                trace_context[trace_id]["service"] = service

            # Inherit identifiers or resource_id from trace context if missing on this line
            idents.update(trace_context[trace_id]["identifiers"])
            if not res_id:
                res_id = trace_context[trace_id]["resource_id"]
            if not service:
                service = trace_context[trace_id]["service"]

        if not res_id or not service:
            continue

        state = "PRESENT"
        category = "USER_PROFILE"
        pii_exposed = False

        if "profile_lookup" in event:
            service = "account_service"
            category = "USER_PROFILE"
            http_status = str(kv.get("http_status", ""))
            rows = str(kv.get("rows", ""))
            if http_status == "404" or rows == "0":
                state = "ABSENT"
                pii_exposed = False
            elif http_status == "200" or rows == "1":
                state = "PRESENT"
                pii_exposed = True
            else:
                continue

        elif "index_query" in event:
            service = "search_service"
            category = "SEARCH_INDEX_ENTRY"
            res = kv.get("result", "")
            hits = str(kv.get("total_hits", ""))
            if res == "hit" or (hits and hits != "0"):
                state = "PRESENT"
                pii_exposed = True
            elif res == "miss" or hits == "0":
                state = "ABSENT"
                pii_exposed = False
            else:
                continue

        elif event in ["message_pii_scan", "attachment_pii_scan"]:
            service = "support_platform"
            category = "SUPPORT_ATTACHMENT" if "attachment" in event else "SUPPORT_MESSAGE"
            state = "PRESENT"
            pii_exposed = True

        elif "audit_record_read" in event or event == "audit_record_read_completed":
            service = "security_service"
            category = "SECURITY_AUDIT_LOG"
            state = "PRESENT"
            pii_exposed = False

        elif "analytics_profile_read" in event or "analytics_profile_scan" in event:
            service = "analytics_platform"
            category = "ANALYTICS_PROFILE"
            email = kv.get("email")
            phone = kv.get("phone")
            e_hash = kv.get("email_hash")
            has_pii = any(v and str(v).lower() != "null" for v in [email, phone, e_hash])
            state = "PRESENT" if has_pii else "ANONYMIZED"
            pii_exposed = has_pii

        elif "connector_config_read" in event:
            service = "integration_service"
            category = "DATA_FLOW"
            enabled = str(kv.get("enabled", "")).lower()
            state = "ACTIVE" if enabled == "true" else "DISABLED"
            pii_exposed = False

        elif "restore_policy_read" in event or "restore_policy_check" in event:
            service = "backup_service"
            category = "BACKUP_ARCHIVE"
            allowed = str(kv.get("restore_allowed", "")).lower()
            state = "ACTIVE" if allowed == "true" else "BLOCKED"
            pii_exposed = False

        elif "restore_candidate_evaluated" in event:
            service = "backup_service"
            category = "BACKUP_ARCHIVE"
            eligible = str(kv.get("eligible", "")).lower()
            state = "ACTIVE" if eligible == "true" else "BLOCKED"
            pii_exposed = False

        elif "support_ticket_read" in event or "contact_query_completed" in event or "message_pii_scan" in event:
            service = "support_platform"
            category = "SUPPORT_MESSAGE" if "contact_query" in event or "support_ticket" in event else "SUPPORT_ATTACHMENT"
            r_email = kv.get("requester_email") or kv.get("resolved_email")
            r_phone = kv.get("requester_phone") or kv.get("resolved_phone")
            r_name = kv.get("requester_name")
            resolved = kv.get("resolved_email") or kv.get("resource_id")
            has_pii = any(v and str(v).lower() not in ("null", "none", "") for v in [r_email, r_phone, r_name])
            state = "PRESENT" if has_pii else "REDACTED"
            pii_exposed = has_pii

        elif "attachment_pii_scan" in event:
            service = "support_platform"
            category = "SUPPORT_ATTACHMENT"
            state = "PRESENT"
            pii_exposed = True

        else:
            continue

        records.append({
            "file_id": file_id,
            "captured_at": captured_at,
            "system_id": service,
            "resource_id": res_id,
            "category": category,
            "subject_reference": None,
            "identifiers": list(idents),
            "state": state,
            "pii_exposed": pii_exposed,
            "details": f"Log event: {event}"
        })

    return records
