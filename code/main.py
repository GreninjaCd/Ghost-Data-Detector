"""
main.py: Top-level pipeline orchestrator for the Ghost Data deletion audit agent.

Usage:
    python -X utf8 code/main.py

Reads:  dataset/deletion_requests.csv
Writes: output.csv (at repo root)
"""
import sys
import os
import time

# Ensure repo root is in path for package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code.loaders import load_deletion_requests
from code.planner import plan_case
from code.serialize import serialize_output_rows
from code.config import OUTPUT_PATH, DELETION_REQUESTS_PATH


def main():
    print("=== Ghost Data Deletion Audit Agent ===")
    print(f"Loading cases from: {DELETION_REQUESTS_PATH}")

    cases = load_deletion_requests()
    print(f"Loaded {len(cases)} cases")

    results = []
    start_time = time.time()

    for i, case in enumerate(cases):
        case_id = case.get("case_id", f"case_{i}")
        if (i + 1) % 50 == 0 or i == 0:
            elapsed = time.time() - start_time
            print(f"  Processing case {i+1}/{len(cases)} ({case_id}) — {elapsed:.1f}s elapsed")

        try:
            result = plan_case(case)
            results.append(result)
        except Exception as e:
            print(f"  ERROR on {case_id}: {e}", file=sys.stderr)
            # Fallback: emit INCOMPLETE with empty steps
            results.append({
                "case_id": case_id,
                "deletion_status": "INCOMPLETE",
                "steps": []
            })

    elapsed = time.time() - start_time
    print(f"\nProcessed {len(results)} cases in {elapsed:.1f}s")

    print(f"Writing output to: {OUTPUT_PATH}")
    serialize_output_rows(results, OUTPUT_PATH)

    # Verify output
    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    print(f"Output file has {len(lines)} lines (1 header + {len(lines)-1} data rows)")

    status_counts = {}
    for r in results:
        s = r["deletion_status"]
        status_counts[s] = status_counts.get(s, 0) + 1
    for s, cnt in sorted(status_counts.items()):
        print(f"  {s}: {cnt}")

    print("\nDone!")


if __name__ == "__main__":
    main()
