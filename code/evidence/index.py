from pathlib import Path
from typing import List, Dict, Any, Optional
from code.config import REPO_ROOT, EVIDENCE_DIR
from code.loaders import load_evidence_files
from code.identity import UserProfile
from code.evidence.sql_reader import parse_sql_evidence
from code.evidence.record_reader import parse_record_evidence
from code.evidence.log_reader import parse_log_evidence
from code.evidence.vision import load_vision_facts


class EvidenceIndex:
    def __init__(self):
        self.manifest: Dict[str, Dict[str, str]] = load_evidence_files()
        self.all_records: List[Dict[str, Any]] = []
        self._build_index()

    def _build_index(self):
        vision_facts = load_vision_facts()

        for file_id, meta in self.manifest.items():
            rel_path = meta["file_path"]
            full_path = REPO_ROOT / "dataset" / rel_path
            captured_at = meta["captured_at"]

            if not full_path.exists():
                continue

            ext = full_path.suffix.lower()

            # 1. SQL snapshots
            if ext == ".sql":
                recs = parse_sql_evidence(full_path, file_id, captured_at)
                self.all_records.extend(recs)

            # 2. JSON and TXT records
            elif ext in [".json", ".txt"]:
                recs = parse_record_evidence(full_path, file_id, captured_at)
                self.all_records.extend(recs)

            # 3. Log files
            elif ext == ".log":
                recs = parse_log_evidence(full_path, file_id, captured_at)
                self.all_records.extend(recs)

            # 4. Images & PDFs
            elif ext in [".png", ".pdf"]:
                facts = vision_facts.get(file_id, [])
                for f in facts:
                    rec = dict(f)
                    rec["file_id"] = file_id
                    rec["captured_at"] = captured_at
                    self.all_records.append(rec)

    def get_records_for_user(self, profile: UserProfile, audit_at: str) -> List[Dict[str, Any]]:
        """
        Retrieves all evidence records relevant to a user captured at or before audit_at.
        """
        matched = []
        uid = profile.user_id
        emails_lower = {e.lower() for e in profile.emails}
        phones = set(profile.phones)
        names_lower = {n.lower() for n in profile.names}
        hashes_lower = {h.lower() for h in profile.hashes}

        for rec in self.all_records:
            # Enforce temporal cutoff
            if rec["captured_at"] > audit_at:
                continue

            # Check match
            is_match = False

            # Check subject reference
            subj = str(rec.get("subject_reference") or "").strip()
            if subj:
                if subj == uid or subj.lower() in emails_lower or subj in phones:
                    is_match = True

            # Check identifiers list
            if not is_match:
                for ident in rec.get("identifiers", []):
                    if not ident:
                        continue
                    str_ident = str(ident).strip()
                    lower_ident = str_ident.lower()
                    if str_ident == uid or lower_ident in emails_lower or str_ident in phones or lower_ident in hashes_lower or lower_ident in names_lower:
                        is_match = True
                        break

            # Check resource_id (e.g. tombstone_17 matching user_17)
            if not is_match:
                res_id = rec.get("resource_id", "")
                if res_id == f"tombstone_{uid.replace('user_', '')}":
                    is_match = True

            if is_match:
                matched.append(rec)

        return matched
