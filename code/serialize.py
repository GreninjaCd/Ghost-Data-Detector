import json
import csv
from typing import List, Dict, Any
from pathlib import Path
from code.config import (
    PHASE_ORDER,
    OPERATION_ORDER,
    FINDING_OPERATIONS,
    REMEDIATION_OPERATIONS,
    VERIFICATION_OPERATIONS,
)

ALL_OPERATIONS = set(FINDING_OPERATIONS + REMEDIATION_OPERATIONS + VERIFICATION_OPERATIONS)


def validate_step(step: Dict[str, Any], case_id: str = ""):
    required_fields = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
    for f in required_fields:
        if f not in step:
            raise ValueError(f"Case {case_id}: step missing required field '{f}': {step}")

    phase = step["phase"]
    if phase not in PHASE_ORDER:
        raise ValueError(f"Case {case_id}: invalid phase '{phase}' in step: {step}")

    op = step["operation"]
    if op not in ALL_OPERATIONS:
        raise ValueError(f"Case {case_id}: invalid operation '{op}' in step: {step}")

    # Evidence rules:
    # Remediation and incomplete verification must have evidence_id == ""
    if phase == "REMEDIATION" and step["evidence_id"] != "":
        raise ValueError(f"Case {case_id}: remediation step must have empty evidence_id, got '{step['evidence_id']}'")


def sort_and_number_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sorts steps by:
    1. Phase: FINDING -> REMEDIATION -> VERIFICATION
    2. Operation order from problem_statement.md
    3. system_id ascending
    4. resource_id ascending
    Then consecutively re-numbers step_no starting from 1.
    """
    def sort_key(s):
        phase_idx = PHASE_ORDER.get(s["phase"], 99)
        op_idx = OPERATION_ORDER.get(s["operation"], 99)
        sys_id = s.get("system_id", "")
        res_id = s.get("resource_id", "")
        return (phase_idx, op_idx, sys_id, res_id)

    sorted_steps = sorted(steps, key=sort_key)
    numbered_steps = []
    for i, s in enumerate(sorted_steps, 1):
        step_copy = {
            "step_no": i,
            "phase": s["phase"],
            "system_id": s["system_id"],
            "resource_id": s["resource_id"],
            "operation": s["operation"],
            "state": s["state"],
            "evidence_id": s.get("evidence_id", ""),
        }
        numbered_steps.append(step_copy)
    return numbered_steps


def serialize_output_rows(case_records: List[Dict[str, Any]], output_path: Path):
    """
    Writes output.csv with rows sorted naturally by numeric case_id.
    """
    # Sort numerically by case_id (e.g. case_01 -> 1, case_33 -> 33)
    def case_num(cid: str) -> int:
        parts = cid.split("_")
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

    sorted_records = sorted(case_records, key=lambda r: case_num(r["case_id"]))

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])

        for record in sorted_records:
            cid = record["case_id"]
            status = record["deletion_status"]
            steps = record.get("steps", [])

            if status == "NOT_APPLICABLE":
                steps_json = "[]"
            else:
                validated_steps = sort_and_number_steps(steps)
                for st in validated_steps:
                    validate_step(st, cid)
                steps_json = json.dumps(validated_steps, separators=(",", ":"))

            writer.writerow([cid, status, steps_json])
