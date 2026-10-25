import os
from pathlib import Path

# Paths
CODE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CODE_DIR.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
CACHE_DIR = REPO_ROOT / ".cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Dataset file paths
DELETION_REQUESTS_PATH = DATASET_DIR / "deletion_requests.csv"
SAMPLE_REQUESTS_PATH = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_PATH = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_PATH = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_PATH = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_PATH = DATASET_DIR / "system_activity.csv"
DELETION_RULES_PATH = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_PATH = DATASET_DIR / "evidence_files.csv"
OUTPUT_PATH = REPO_ROOT / "output.csv"

# Model settings
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Phase and Operation Ordering according to problem_statement.md §6.4
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]

FINDING_OPERATIONS = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]

REMEDIATION_OPERATIONS = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]

VERIFICATION_OPERATIONS = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

PHASE_ORDER = {phase: i for i, phase in enumerate(PHASES)}

OPERATION_ORDER = {}
for i, op in enumerate(FINDING_OPERATIONS):
    OPERATION_ORDER[op] = i
for i, op in enumerate(REMEDIATION_OPERATIONS):
    OPERATION_ORDER[op] = i
for i, op in enumerate(VERIFICATION_OPERATIONS):
    OPERATION_ORDER[op] = i
