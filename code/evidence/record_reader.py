import json
from pathlib import Path
from typing import List, Dict, Any


def parse_record_evidence(file_path: Path, file_id: str, captured_at: str) -> List[Dict[str, Any]]:
    """
    Parses JSON snapshot bundles and TXT handover reports under dataset/evidence/records/.
    """
    records = []
    ext = file_path.suffix.lower()

    # 1. Plain text shift handover notes
    if ext == ".txt":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    t_str, sys_id, res_id, cat, result, subject = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                    
                    # Normalize states
                    state = "PRESENT"
                    pii_exposed = False
                    if result == "NOT_FOUND":
                        state = "ABSENT"
                    elif result in ["FOUND", "IDENTIFIABLE"]:
                        state = "PRESENT"
                        pii_exposed = True
                    elif result == "ANONYMIZED":
                        state = "ANONYMIZED"
                        pii_exposed = False
                    elif result == "REDACTED":
                        state = "REDACTED"
                        pii_exposed = False
                    elif result == "ACTIVE":
                        state = "ACTIVE"
                    elif result in ["BLOCKED", "DISABLED"]:
                        state = result

                    records.append({
                        "file_id": file_id,
                        "captured_at": captured_at,
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "category": cat,
                        "subject_reference": subject,
                        "identifiers": [subject] if subject and subject != "no direct identifier" else [],
                        "state": state,
                        "pii_exposed": pii_exposed,
                        "details": f"Shift handover entry: {result}"
                    })
        except Exception as e:
            print(f"Error reading TXT {file_path}: {e}")
        return records

    # 2. JSON bundle files
    if ext == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading JSON {file_path}: {e}")
            return records

        # Bundle format A: "snapshots" (e.g. customer_data_snapshot_bundle_*.json)
        if "snapshots" in data:
            for snap in data.get("snapshots", []):
                store = snap.get("data_store", "")
                coll = snap.get("collection", "")
                snap_records = snap.get("records", [])

                for rec in snap_records:
                    res_id = rec.get("resource_id")
                    if not res_id:
                        continue
                    uid = rec.get("subject_reference") or rec.get("user_id") or rec.get("customer_reference")
                    email = rec.get("email") or rec.get("requester_email") or rec.get("owner_email")
                    phone = rec.get("phone") or rec.get("requester_phone")
                    name = rec.get("name") or rec.get("full_name") or rec.get("requester_name")
                    e_hash = rec.get("email_hash")

                    state = "PRESENT"
                    cat = "USER_PROFILE"
                    has_pii = bool(email or phone or name or e_hash)

                    if store == "identity_service" and "tombstone" in res_id:
                        cat = "ACCOUNT_TOMBSTONE"
                        state = "PRESENT" if has_pii else "REDACTED"
                    elif store == "security_service":
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif store == "analytics_platform":
                        cat = "ANALYTICS_PROFILE"
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif store == "account_service":
                        cat = "USER_PROFILE"
                        status = rec.get("account_status", "ACTIVE")
                        state = "PRESENT" if status == "ACTIVE" else "ABSENT"

                    records.append({
                        "file_id": file_id,
                        "captured_at": captured_at,
                        "system_id": store,
                        "resource_id": res_id,
                        "category": cat,
                        "subject_reference": uid,
                        "identifiers": [i for i in [email, phone, name, uid, e_hash] if i],
                        "state": state,
                        "pii_exposed": has_pii,
                        "details": f"Snapshot {store}/{coll}"
                    })

        # Bundle format B: "service_exports" (e.g. service_resource_export_*.json)
        elif "service_exports" in data:
            exports = data.get("service_exports", {})

            # account_service
            for item in exports.get("account_service", {}).get("profile_lookups", []):
                res_id = item.get("resource_id")
                code = item.get("status_code", 404)
                prof = item.get("profile") or {}
                email = prof.get("email")
                uid = prof.get("customer_reference")
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "account_service",
                    "resource_id": res_id,
                    "category": "USER_PROFILE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "ABSENT" if code == 404 else "PRESENT",
                    "pii_exposed": code != 404,
                    "details": f"Service export profile lookup code={code}"
                })

            # analytics_platform
            for item in exports.get("analytics_platform", {}).get("profiles", []):
                res_id = item.get("resource_id")
                email = item.get("email")
                phone = item.get("phone")
                e_hash = item.get("email_hash")
                uid = item.get("customer_reference")
                has_pii = bool(email or phone or e_hash)
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "analytics_platform",
                    "resource_id": res_id,
                    "category": "ANALYTICS_PROFILE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, phone, e_hash, uid] if i],
                    "state": "PRESENT" if has_pii else "ANONYMIZED",
                    "pii_exposed": has_pii,
                    "details": "Service export analytics profile"
                })

            # backup_service - key may be 'archives' or 'restore_entries'
            backup_items = exports.get("backup_service", {}).get("archives") or exports.get("backup_service", {}).get("restore_entries", [])
            for item in backup_items:
                res_id = item.get("resource_id")
                email = item.get("customer_email")
                uid = item.get("customer_reference")
                allowed = item.get("restore_allowed", False)
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "backup_service",
                    "resource_id": res_id,
                    "category": "BACKUP_ARCHIVE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "ACTIVE" if allowed else "BLOCKED",
                    "pii_exposed": False,
                    "details": f"Service export backup archive restore_allowed={allowed}"
                })

            # export_service
            for item in exports.get("export_service", {}).get("exports", []):
                res_id = item.get("resource_id")
                # Try different email field names used across different evidence files
                email = item.get("customer_email") or item.get("owner_email")
                uid = item.get("customer_reference")
                status = item.get("status", "READY")
                # If no explicit status but resource_id exists, it's still present (available for download)
                # Files with owner_email present are always considered available
                is_present = status in ["READY", "AVAILABLE", "COMPLETED"] or bool(email)
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "export_service",
                    "resource_id": res_id,
                    "category": "USER_EXPORT",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "PRESENT" if is_present else "ABSENT",
                    "pii_exposed": True,
                    "details": f"Service export user export status={status}"
                })

            # integration_service
            for item in exports.get("integration_service", {}).get("connectors", []):
                res_id = item.get("resource_id")
                email = item.get("customer_email")
                uid = item.get("customer_reference")
                enabled = item.get("enabled", False)
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "integration_service",
                    "resource_id": res_id,
                    "category": "DATA_FLOW",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "ACTIVE" if enabled else "DISABLED",
                    "pii_exposed": bool(email),
                    "details": f"Service export connector enabled={enabled}"
                })

            # search_service - key may be 'queries' or 'index_queries'
            search_items = exports.get("search_service", {}).get("queries") or exports.get("search_service", {}).get("index_queries", [])
            for item in search_items:
                # Handle nested 'hits' structure: {"hits": {"documents": [...], "total": N}, "resource_id": ...}
                hits = item.get("hits", {})
                if isinstance(hits, dict):
                    total_hits = hits.get("total", 0)
                    documents = hits.get("documents", [])
                    res_id = item.get("resource_id")
                    # Extract email from first document if available
                    email = None
                    uid = None
                    if documents:
                        doc = documents[0]
                        email = doc.get("email")
                        uid = doc.get("customer_reference")
                        if not res_id:
                            res_id = doc.get("resource_id")
                    state = "PRESENT" if total_hits > 0 else "ABSENT"
                    if res_id:
                        records.append({
                            "file_id": file_id,
                            "captured_at": captured_at,
                            "system_id": "search_service",
                            "resource_id": res_id,
                            "category": "SEARCH_INDEX_ENTRY",
                            "subject_reference": uid,
                            "identifiers": [i for i in [email, uid] if i],
                            "state": state,
                            "pii_exposed": state == "PRESENT",
                            "details": f"Service export search index_query total_hits={total_hits}"
                        })
                else:
                    # Legacy flat format
                    res_id = item.get("resource_id")
                    email = item.get("email")
                    uid = item.get("customer_reference")
                    res = item.get("result", "")
                    records.append({
                        "file_id": file_id,
                        "captured_at": captured_at,
                        "system_id": "search_service",
                        "resource_id": res_id,
                        "category": "SEARCH_INDEX_ENTRY",
                        "subject_reference": uid,
                        "identifiers": [i for i in [email, uid] if i],
                        "state": "PRESENT" if res == "hit" else "ABSENT",
                        "pii_exposed": res == "hit",
                        "details": f"Service export search query result={res}"
                    })

            # security_service
            for item in exports.get("security_service", {}).get("audit_records", []):
                res_id = item.get("resource_id")
                uid = item.get("subject_reference")
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "security_service",
                    "resource_id": res_id,
                    "category": "SECURITY_AUDIT_LOG",
                    "subject_reference": uid,
                    "identifiers": [uid] if uid else [],
                    "state": "PRESENT",
                    "pii_exposed": False,
                    "details": "Service export security audit record"
                })

            # support_platform
            for item in exports.get("support_platform", {}).get("tickets", []):
                res_id = item.get("resource_id")
                email = item.get("requester_email")
                phone = item.get("requester_phone")
                name = item.get("requester_name")
                uid = item.get("customer_reference")
                has_pii = bool(email or phone or name)
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "support_platform",
                    "resource_id": res_id,
                    "category": "SUPPORT_MESSAGE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, phone, name, uid] if i],
                    "state": "PRESENT" if has_pii else "REDACTED",
                    "pii_exposed": has_pii,
                    "details": "Service export support ticket"
                })

        # Bundle format C: Flat "records" or "items"
        elif "records" in data or "items" in data or "jobs" in data:
            items = data.get("records") or data.get("items") or data.get("jobs") or []
            origin = data.get("origin", "")
            source = data.get("source", "") or data.get("collection", "")
            for rec in items:
                res_id = rec.get("resource_id") or rec.get("job_id") or rec.get("export_id")
                if not res_id:
                    continue
                sys_id = rec.get("system") or origin
                subject = rec.get("subject_reference") or rec.get("user_id") or rec.get("customer_reference") or rec.get("owner")
                result = rec.get("result") or rec.get("status")
                cat = rec.get("record_type", "USER_PROFILE")

                # Gather all possible identifiers from this record
                all_idents = []
                for id_field in ["owner_email", "customer_email", "requester_email",
                                 "email", "owner_phone", "customer_phone", "phone",
                                 "customer_reference", "user_id", "subject_reference"]:
                    v = rec.get(id_field)
                    if v and str(v).lower() not in ("null", "none", ""):
                        all_idents.append(str(v))

                # Determine system_id from source or collection if not set
                if not sys_id:
                    if "export" in source.lower() or "export" in res_id.lower():
                        sys_id = "export_service"
                        cat = "USER_EXPORT"
                    elif "support" in source.lower():
                        sys_id = "support_platform"
                        cat = "SUPPORT_MESSAGE"

                state = "PRESENT"
                if result in ["NOT_FOUND", "DELETED", "ABSENT"]:
                    state = "ABSENT"
                elif result in ["FOUND", "ACTIVE", "PRESENT", "READY", "COMPLETED"]:
                    state = "PRESENT"
                elif result == "ANONYMIZED":
                    state = "ANONYMIZED"
                elif result == "REDACTED":
                    state = "REDACTED"
                elif result == "DISABLED":
                    state = "DISABLED"
                elif result == "BLOCKED":
                    state = "BLOCKED"
                elif result is None and all_idents:
                    # Has identifiers but no explicit status = PRESENT
                    state = "PRESENT"

                # Combine subject with all_idents
                combined_idents = list(dict.fromkeys([subject] + all_idents if subject else all_idents))

                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "category": cat,
                    "subject_reference": subject or (all_idents[0] if all_idents else None),
                    "identifiers": combined_idents,
                    "state": state,
                    "pii_exposed": state in ("PRESENT",),
                    "details": f"Record item result={result}"
                })

    return records
