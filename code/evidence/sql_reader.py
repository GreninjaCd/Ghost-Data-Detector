import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any


def parse_sql_evidence(file_path: Path, file_id: str, captured_at: str) -> List[Dict[str, Any]]:
    """
    Executes a .sql snapshot in SQLite in-memory and extracts normalized records.
    """
    records = []
    conn = sqlite3.connect(":memory:")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sql_text = f.read()
        conn.executescript(sql_text)
    except Exception as e:
        print(f"Error executing {file_path}: {e}")
        return records

    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    for table in tables:
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [c[1] for c in cursor.fetchall()]

        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()

        for row in rows:
            row_dict = dict(zip(cols, row))
            res_id = row_dict.get("resource_id")
            if not res_id:
                continue

            # 1. Customer Profiles / Accounts
            if "customer_profiles" in table:
                # If failover replica has row, check account_status
                status = row_dict.get("account_status", "ACTIVE")
                email = row_dict.get("email")
                phone = row_dict.get("phone")
                name = row_dict.get("full_name")
                uid = row_dict.get("user_id") or row_dict.get("customer_reference")

                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "account_service",
                    "resource_id": res_id,
                    "category": "USER_PROFILE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, phone, name, uid] if i],
                    "state": "PRESENT" if status == "ACTIVE" else "ABSENT",
                    "pii_exposed": bool(email or phone or name),
                    "table": table,
                    "details": f"Profile in {table} with status {status}"
                })

            # 2. Search Index Documents
            elif "search_documents" in table or table == "customer_search_documents":
                email = row_dict.get("email")
                name = row_dict.get("display_name")
                uid = row_dict.get("customer_reference")
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "search_service",
                    "resource_id": res_id,
                    "category": "SEARCH_INDEX_ENTRY",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, name, uid] if i],
                    "state": "PRESENT",
                    "pii_exposed": bool(email or name),
                    "table": table,
                    "details": f"Search document in {table}"
                })

            # 3. Analytics Profiles
            elif table == "customer_analytics_profiles":
                email = row_dict.get("email")
                phone = row_dict.get("phone")
                e_hash = row_dict.get("email_hash")
                uid = row_dict.get("customer_reference")
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
                    "table": table,
                    "details": f"Analytics profile in {table}"
                })

            # 4. Connector Subscriptions / Data Flows
            elif table == "connector_subscriptions":
                email = row_dict.get("customer_email")
                uid = row_dict.get("customer_reference")
                enabled = row_dict.get("enabled")
                is_active = str(enabled).lower() in ["1", "true", "enabled"]
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "integration_service",
                    "resource_id": res_id,
                    "category": "DATA_FLOW",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "ACTIVE" if is_active else "DISABLED",
                    "pii_exposed": bool(email),
                    "table": table,
                    "details": f"Connector in {table} enabled={enabled}"
                })

            # 5. Backup Restore Entries
            elif table == "backup_restore_entries":
                email = row_dict.get("customer_email")
                uid = row_dict.get("customer_reference")
                restore_allowed = row_dict.get("restore_allowed")
                is_restorable = str(restore_allowed).lower() in ["1", "true"]
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "backup_service",
                    "resource_id": res_id,
                    "category": "BACKUP_ARCHIVE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, uid] if i],
                    "state": "ACTIVE" if is_restorable else "BLOCKED",
                    "pii_exposed": False,
                    "table": table,
                    "details": f"Backup restore policy in {table} restore_allowed={restore_allowed}"
                })

            # 6. Customer Exports
            elif table == "customer_exports":
                email = row_dict.get("owner_email")
                phone = row_dict.get("owner_phone")
                uid = row_dict.get("customer_reference")
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "export_service",
                    "resource_id": res_id,
                    "category": "USER_EXPORT",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, phone, uid] if i],
                    "state": "PRESENT",
                    "pii_exposed": True,
                    "table": table,
                    "details": f"Customer export record in {table}"
                })

            # 7. Support Records
            elif table == "support_records":
                email = row_dict.get("requester_email")
                phone = row_dict.get("requester_phone")
                name = row_dict.get("requester_name")
                uid = row_dict.get("customer_reference")
                records.append({
                    "file_id": file_id,
                    "captured_at": captured_at,
                    "system_id": "support_platform",
                    "resource_id": res_id,
                    "category": "SUPPORT_MESSAGE",
                    "subject_reference": uid,
                    "identifiers": [i for i in [email, phone, name, uid] if i],
                    "state": "PRESENT",
                    "pii_exposed": True,
                    "table": table,
                    "details": f"Support record in {table}"
                })

            # 8. Security Audit Records
            elif table == "security_audit_records":
                uid = row_dict.get("subject_reference")
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
                    "table": table,
                    "details": f"Security audit record in {table}"
                })

            # 9. Generic Multi-replica tables with record_json
            elif "customer_data" in table and "record_json" in row_dict:
                raw_json = row_dict.get("record_json")
                origin_sys = row_dict.get("origin_system", "")
                if raw_json:
                    try:
                        data = json.loads(raw_json)
                        uid = data.get("customer_reference") or data.get("user_id")
                        email = data.get("email") or data.get("customer_email") or data.get("owner_email")
                        phone = data.get("phone") or data.get("owner_phone")
                        name = data.get("full_name") or data.get("display_name")
                        e_hash = data.get("email_hash")

                        state = "PRESENT"
                        category = "USER_PROFILE"
                        has_pii = bool(email or phone or name or e_hash)

                        if origin_sys == "analytics_platform":
                            category = "ANALYTICS_PROFILE"
                            state = "PRESENT" if has_pii else "ANONYMIZED"
                        elif origin_sys == "search_service":
                            category = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif origin_sys == "backup_service":
                            category = "BACKUP_ARCHIVE"
                            allowed = data.get("restore_allowed", True)
                            state = "ACTIVE" if allowed else "BLOCKED"
                        elif origin_sys == "integration_service":
                            category = "DATA_FLOW"
                            enabled = data.get("enabled", True)
                            state = "ACTIVE" if enabled else "DISABLED"
                        elif origin_sys == "export_service":
                            category = "USER_EXPORT"
                            state = "PRESENT"
                        elif origin_sys == "support_platform":
                            category = "SUPPORT_MESSAGE"
                            state = "PRESENT"
                        elif origin_sys == "security_service":
                            category = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif origin_sys == "account_service":
                            category = "USER_PROFILE"
                            status = data.get("account_status", "ACTIVE")
                            state = "PRESENT" if status == "ACTIVE" else "ABSENT"

                        records.append({
                            "file_id": file_id,
                            "captured_at": captured_at,
                            "system_id": origin_sys or "account_service",
                            "resource_id": res_id,
                            "category": category,
                            "subject_reference": uid,
                            "identifiers": [i for i in [email, phone, name, uid, e_hash] if i],
                            "state": state,
                            "pii_exposed": has_pii,
                            "table": table,
                            "details": f"Replica row in {table} ({origin_sys})"
                        })
                    except Exception:
                        pass

    conn.close()
    return records
