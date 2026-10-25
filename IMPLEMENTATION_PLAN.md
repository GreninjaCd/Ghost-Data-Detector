# Implementation Plan: Ghost Data Still Exists (Deletion-Audit Agent)

## 1. Executive Summary & Challenge Contract

This document outlines the architecture, data pipeline, and phase-by-phase implementation plan for building the AI-powered deletion-audit agent for **HackerRank Orchestrate (October 2026)**.

The objective is to audit 518 data deletion requests in `dataset/deletion_requests.csv` and output `output.csv` at the repository root with the schema:
```text
case_id,deletion_status,steps_json
```

Each case must evaluate to one of:
- `NOT_APPLICABLE` with `steps_json = []` (for non-deletion requests such as data exports, corrections, or information requests).
- `COMPLETE` with evidence-backed verification steps proving the compliant state at `audit_at`.
- `INCOMPLETE` with participant-visible findings, an ordered remediation plan, and post-remediation verification checks.

---

## 2. Key Technical Discoveries & Hard Constraints

1. **Windows UTF-8 Encoding**:
   - Python on Windows defaults to `cp1252`, causing `UnicodeDecodeError` on international text (e.g. `case_546`).
   - **Requirement**: All file I/O must explicitly use `encoding="utf-8"`.

2. **Case ID Natural Numeric Sorting**:
   - In plain string sorting, `'case_100' < 'case_33'`. The evaluation set runs from `case_33` to `case_550`.
   - **Requirement**: `output.csv` must be sorted numerically by case number (`key=lambda x: int(x.split('_')[1])`) matching the natural order in `deletion_requests.csv`.

3. **Deterministic Evidence Parsing (79 of 94 files)**:
   - 24 `.sql` snapshot files: SQLite-compatible; run in in-memory SQLite to detect replication drift (e.g., primary deleted, failover/read replica retained).
   - 26 `.log` files: Structured key-value logs (`service=`, `event=`, `resource_id=`, `lookup_key=`, `matched_value=`).
   - 29 `.json` / `.txt` files: Clean JSON snapshot bundles and pipe-delimited shift handover reports.
   - **Zero token cost**: Parsed deterministically via Python standard library.

4. **Multimodal Extraction for 15 Visual Files**:
   - 11 `.png` system screenshots and 4 `.pdf` documents contain critical records (such as support ticket attachments and legal retention registers).
   - **Requirement**: Extracted via Gemini Multimodal once and cached in `.cache/vision_facts.json` for deterministic, zero-cost development reruns.

5. **SHA-256 Hash Reproducibility**:
   - Verified: `email_hash` is standard UTF-8 SHA-256 (`hashlib.sha256(email.encode('utf-8')).hexdigest()`).

6. **100% Identity Resolution Rate**:
   - Every request email (current or historical) maps unambiguously to an internal `user_id` across both sample (32) and evaluation (518) requests via `user_identities.csv` and `user_audit_log.csv`.

7. **Strict Step Ordering & Schema**:
   - Step numbers start at `1` consecutively across the case.
   - Phases: `FINDING` $\to$ `REMEDIATION` $\to$ `VERIFICATION`.
   - Operations follow the exact order in `problem_statement.md` §6.4:
     - Findings: `REPORT_REMAINING_RECORD` $\to$ `REPORT_EXPOSED_PII` $\to$ `REPORT_ACTIVE_DATA_FLOW` $\to$ `REPORT_RESTORE_RISK`.
     - Remediation: `DISABLE_DATA_FLOW` $\to$ `BLOCK_RESTORE` $\to$ `DELETE_RECORD` $\to$ `REDACT_RECORD` $\to$ `ANONYMIZE_RECORD`.
     - Verification: `VERIFY_RECORD_ABSENT` $\to$ `VERIFY_RECORD_PRESENT` $\to$ `VERIFY_RECORD_REDACTED` $\to$ `VERIFY_RECORD_ANONYMIZED` $\to$ `VERIFY_DATA_FLOW_DISABLED` $\to$ `VERIFY_RESTORE_BLOCKED`.
   - Secondary sort: `system_id` ascending, then `resource_id` ascending.
   - `evidence_id`: cited in `FINDING` and `COMPLETE` verification; empty string `""` in remediation and incomplete verification.

---

## 3. Architecture & Code Layout

```
hackerrank-orchestrate-october26/
├── output.csv                         # Final 518-row prediction file
├── log.txt                            # Turn-by-turn agent audit log
├── README.md                          # Repository setup & execution instructions
├── IMPLEMENTATION_PLAN.md             # This document
├── code/
│   ├── main.py                        # Top-level pipeline orchestrator
│   ├── config.py                      # Paths, model names, environment variables
│   ├── loaders.py                     # UTF-8 loaders for dataset CSVs
│   ├── identity.py                    # IdentityGraph: current/historical emails, phones, hashes
│   ├── intent.py                      # Request classifier (Gemini Flash + cache)
│   ├── evidence/
│   │   ├── __init__.py
│   │   ├── index.py                   # Unified evidence query index
│   │   ├── sql_reader.py              # SQLite snapshot runner & replication drift detector
│   │   ├── log_reader.py              # Key-value structured log parser
│   │   ├── record_reader.py           # JSON bundle & TXT handover parser
│   │   └── vision.py                  # Gemini Multimodal extractor & disk cache
│   ├── state.py                       # Point-in-time resource state reconstruction at audit_at
│   ├── policy.py                      # Deletion rules engine (15 rules)
│   ├── planner.py                     # Findings, remediation, and verification generator
│   ├── serialize.py                   # Consecutive step numbering, JSON validation, CSV output
│   ├── prompts/
│   │   ├── classify_intent.md         # Prompt template for request classification
│   │   └── vision_extract.md          # Prompt template for multimodal extraction
│   └── evaluation/
│       ├── main.py                    # Evaluator against sample_output.csv
│       ├── custom_cases.py            # Synthetic edge case test generator
│       ├── evaluation_report.md       # Required evaluation report for submission
│       └── usage_report.md            # Required token count and cost analysis report
└── dataset/                           # Challenge data & evidence files
```

---

## 4. Phase-by-Phase Roadmap

### Stage 1: Foundations & Core Data Structures
1. **`code/config.py`**:
   - Define paths for dataset, evidence, cache, and output files.
   - Configure Gemini Flash model settings and API key handling via `GEMINI_API_KEY`.
2. **`code/loaders.py`**:
   - Implement robust CSV readers specifying `encoding="utf-8"`.
   - Load `deletion_requests.csv`, `sample_deletion_requests.csv`, `sample_output.csv`, `user_identities.csv`, `user_audit_log.csv`, `system_activity.csv`, `deletion_rules.csv`, and `evidence_files.csv`.
3. **`code/identity.py`**:
   - Construct `IdentityGraph` mapping:
     - `email_to_user`: maps current email, historical emails (from `user_audit_log.csv`), and normalized variations to `user_id`.
     - `user_profiles`: stores `user_id`, canonical name, set of all emails, set of all phone numbers, set of all email hashes (stored + freshly derived UTF-8 SHA-256).
4. **`code/serialize.py`**:
   - Implement validator for step schema (`step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
   - Implement sorting routine following phase, operation precedence, `system_id`, and `resource_id`.
   - Emit valid CSV with proper JSON string quoting.

### Stage 2: Evidence Indexing & Multimodal Extraction
1. **`code/evidence/sql_reader.py`**:
   - Load each `.sql` file into an in-memory SQLite database.
   - Query primary vs replica tables (such as `customer_profiles_failover_replica`, `customer_data_read_replica`, `customer_data_regional_replicas`).
   - Extract records with status, identifiers, and capture timestamps.
2. **`code/evidence/record_reader.py`**:
   - Parse all `.json` snapshot bundles (`customer_data_snapshot_bundle_*.json`, `connector_configurations_*.json`, `customer_export_manifest_*.json`, etc.).
   - Parse pipe-delimited shift handover logs (`customer_account_handover_20261001.txt`).
3. **`code/evidence/log_reader.py`**:
   - Parse the 26 `.log` observability trace files.
   - Extract lines containing `profile_lookup_completed`, `index_query_completed`, `message_pii_scan`, `connector_config_read_completed`, `restore_policy_read_completed`, and `audit_record_read_completed`.
4. **`code/evidence/vision.py`**:
   - Extract records, tables, identifiers, and timestamps from the 11 PNGs and 4 PDFs using Gemini Vision.
   - Save parsed outputs to `.cache/vision_facts.json` for deterministic offline execution.
5. **`code/evidence/index.py`**:
   - Consolidate all evidence items into a unified lookup index searchable by `user_id`, `email`, `phone`, `hash`, and `resource_id`.

### Stage 3: Request Intent & State Reconstruction
1. **`code/intent.py`**:
   - Classify `request_text` to verify whether deletion is authorized.
   - Classify requests for access/export ("download my data"), corrections ("misspelled"), or marketing opt-outs ("stop promotional emails, keep account active") as `NOT_APPLICABLE`.
   - Disk-cache classifications in `.cache/intent_cache.json`.
2. **`code/state.py`**:
   - Enforce temporal cutoff: Discard any evidence or activity dated after `audit_at`.
   - For each resource associated with the subject's identifiers:
     - Determine whether the primary record is ABSENT or PRESENT.
     - Detect replication drift where secondary replicas still hold the record.
     - Check account tombstones: verify if direct identifiers (name, email, phone, hash) are stripped.
     - Check active sync data flows (`DATA_FLOW` active vs disabled).
     - Check backup restore risks (`BACKUP_ARCHIVE` restorable vs blocked).
     - Check retained compliance records (security audit logs, legal retention records).

### Stage 4: Policy & Remediation Planner
1. **`code/policy.py`**:
   - Map 15 rules from `deletion_rules.csv` to actions:
     - `USER_PROFILE`, `SECONDARY_IDENTIFIER`, `SEARCH_INDEX_ENTRY`, `CACHE_ENTRY`, `SUPPORT_ATTACHMENT`, `USER_EXPORT`, `MARKETING_PROFILE` $\to$ `DELETE`.
     - `SUPPORT_MESSAGE`, `EMAIL_DELIVERY_LOG`, `ACCOUNT_TOMBSTONE` $\to$ `REDACT`.
     - `ANALYTICS_PROFILE`, `PRODUCT_TELEMETRY` $\to$ `ANONYMIZE`.
     - `SECURITY_AUDIT_LOG`, `LEGAL_HOLD_RECORD`, `BACKUP_ARCHIVE` $\to$ `RETAIN`.
2. **`code/planner.py`**:
   - If non-deletion: return `status = NOT_APPLICABLE`, `steps = []`.
   - If all requirements satisfied: return `status = COMPLETE`, emit verification steps citing proving `evidence_id`.
   - If violations exist: return `status = INCOMPLETE`:
     - Emit findings citing participant-visible `evidence_id`.
     - Emit ordered remediation steps (`evidence_id = ""`), placing data flow disablement and restore blocking before record remediation.
     - Emit post-remediation verification checks (`evidence_id = ""`).

### Stage 5: Sample Evaluation & Calibration
1. **`code/evaluation/main.py`**:
   - Run pipeline on 32 sample cases in `dataset/sample_deletion_requests.csv`.
   - Compare outputs against `dataset/sample_output.csv`:
     - Case status accuracy.
     - Step-level field accuracy (`system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
     - Step ordering sequence accuracy.
   - Produce diff reports to eliminate any discrepancies.

### Stage 6: Custom Evaluation Cases & Reports
1. **`code/evaluation/custom_cases.py`**:
   - Create at least 3 custom evaluation cases testing boundary conditions:
     - Edge Case 1: Multilingual non-deletion request with negative phrasing.
     - Edge Case 2: Historical email change where ghost data persists in a read replica.
     - Edge Case 3: Evidence timestamp cutoff where later evidence cannot be cited.
2. **`code/evaluation/evaluation_report.md`**:
   - Document sample benchmark results, custom cases, error analysis, and improvements.
3. **`code/evaluation/usage_report.md`**:
   - Document Gemini API call counts, token usage (prompt, candidate, total), per-request averages, and cost estimations.

### Stage 7: Full Dataset Production Run
1. Run `python code/main.py`.
2. Process all 518 cases from `dataset/deletion_requests.csv`.
3. Generate root `output.csv`.
4. Validate `output.csv`:
   - Exact row count: 519 lines (1 header + 518 data rows).
   - Natural numeric sort order: `case_33` to `case_550`.
   - Valid JSON arrays and consecutive step numbering.
   - Valid evidence citations matching manifest `evidence_files.csv`.

### Stage 8: Packaging & Submission
1. Package `code.zip`:
   ```powershell
   Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
   ```
2. Verify exclusion of `dataset/`, `.venv/`, `.git/`, and `__pycache__`.
3. Confirm `log.txt` contains complete session history in compliance with `AGENTS.md`.

---

## 5. Deliverables Checklist

- [ ] `output.csv` (at repository root, 518 rows, sorted numerically).
- [ ] `code/evaluation/evaluation_report.md` (accuracy benchmarks, custom cases, failure analysis).
- [ ] `code/evaluation/usage_report.md` (token metrics and cost summary).
- [ ] `log.txt` (root audit transcript for submission as `chat_transcript`).
- [ ] `code.zip` (containing runnable code, README, and evaluation reports).
