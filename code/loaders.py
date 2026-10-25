import csv
from typing import Dict, List, Any
from code.config import (
    DELETION_REQUESTS_PATH,
    SAMPLE_REQUESTS_PATH,
    SAMPLE_OUTPUT_PATH,
    USER_IDENTITIES_PATH,
    USER_AUDIT_LOG_PATH,
    SYSTEM_ACTIVITY_PATH,
    DELETION_RULES_PATH,
    EVIDENCE_FILES_PATH,
)


def _read_csv(file_path: Any) -> List[Dict[str, str]]:
    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def load_deletion_requests(file_path: Any = DELETION_REQUESTS_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_sample_requests(file_path: Any = SAMPLE_REQUESTS_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_sample_output(file_path: Any = SAMPLE_OUTPUT_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_user_identities(file_path: Any = USER_IDENTITIES_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_user_audit_log(file_path: Any = USER_AUDIT_LOG_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_system_activity(file_path: Any = SYSTEM_ACTIVITY_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_deletion_rules(file_path: Any = DELETION_RULES_PATH) -> List[Dict[str, str]]:
    return _read_csv(file_path)


def load_evidence_files(file_path: Any = EVIDENCE_FILES_PATH) -> Dict[str, Dict[str, str]]:
    rows = _read_csv(file_path)
    return {r["file_id"]: r for r in rows}
