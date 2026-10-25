"""
evaluation/main.py: Evaluator for sample cases.

Runs the pipeline against sample_deletion_requests.csv and compares
against sample_output.csv for accuracy benchmarking.

Usage:
    python -X utf8 code/evaluation/main.py
"""
import sys
import os
import json
import csv
import time

# Ensure repo root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code.loaders import load_sample_requests, load_sample_output
from code.planner import plan_case
from code.serialize import sort_and_number_steps


def parse_steps_json(steps_json_str: str):
    """Parse steps_json string from CSV."""
    try:
        return json.loads(steps_json_str)
    except Exception:
        return []


def compare_steps(predicted: list, expected: list) -> dict:
    """
    Compares predicted vs expected steps.
    Returns accuracy metrics.
    """
    if not expected and not predicted:
        return {"step_match": True, "precision": 1.0, "recall": 1.0, "f1": 1.0, "sequence_match": True}

    if not expected:
        return {"step_match": False, "precision": 0.0, "recall": 0.0, "f1": 0.0, "sequence_match": False}

    if not predicted:
        return {"step_match": False, "precision": 0.0, "recall": 0.0, "f1": 0.0, "sequence_match": False}

    # For each step, compare key fields: system_id, resource_id, operation, state
    def step_sig(s):
        return (
            s.get("system_id", ""),
            s.get("resource_id", ""),
            s.get("operation", ""),
            s.get("state", ""),
        )

    pred_sigs = [step_sig(s) for s in predicted]
    exp_sigs = [step_sig(s) for s in expected]

    # Unordered match
    pred_set = set(pred_sigs)
    exp_set = set(exp_sigs)
    tp = len(pred_set & exp_set)
    precision = tp / len(pred_set) if pred_set else 0.0
    recall = tp / len(exp_set) if exp_set else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Sequence match: same ordered sequence of (operation, system_id, resource_id)
    def seq_sig(s):
        return (s.get("operation", ""), s.get("system_id", ""), s.get("resource_id", ""))

    pred_seq = [seq_sig(s) for s in predicted]
    exp_seq = [seq_sig(s) for s in expected]
    sequence_match = pred_seq == exp_seq

    step_match = pred_set == exp_set

    return {
        "step_match": step_match,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "sequence_match": sequence_match,
    }


def evaluate_samples(verbose: bool = True) -> dict:
    """
    Run the pipeline on all sample cases and compare against expected output.
    Returns a summary dict with accuracy metrics.
    """
    sample_cases = load_sample_requests()
    sample_expected = load_sample_output()
    expected_by_id = {r["case_id"]: r for r in sample_expected}

    print(f"Evaluating {len(sample_cases)} sample cases...")
    
    status_correct = 0
    step_precision_sum = 0.0
    step_recall_sum = 0.0
    step_f1_sum = 0.0
    sequence_matches = 0
    results = []

    start_time = time.time()

    for i, case in enumerate(sample_cases):
        case_id = case.get("case_id", "")
        
        try:
            result = plan_case(case)
        except Exception as e:
            print(f"  ERROR on {case_id}: {e}", file=sys.stderr)
            result = {"case_id": case_id, "deletion_status": "INCOMPLETE", "steps": []}

        predicted_status = result["deletion_status"]
        predicted_steps = result.get("steps", [])
        if predicted_steps:
            predicted_steps = sort_and_number_steps(predicted_steps)

        expected = expected_by_id.get(case_id, {})
        expected_status = expected.get("deletion_status", "")
        expected_steps = parse_steps_json(expected.get("steps_json", "[]"))

        # Compare
        status_ok = predicted_status == expected_status
        step_metrics = compare_steps(predicted_steps, expected_steps)

        if status_ok:
            status_correct += 1
        step_precision_sum += step_metrics["precision"]
        step_recall_sum += step_metrics["recall"]
        step_f1_sum += step_metrics["f1"]
        if step_metrics["sequence_match"]:
            sequence_matches += 1

        row = {
            "case_id": case_id,
            "expected_status": expected_status,
            "predicted_status": predicted_status,
            "status_ok": status_ok,
            "step_precision": round(step_metrics["precision"], 3),
            "step_recall": round(step_metrics["recall"], 3),
            "step_f1": round(step_metrics["f1"], 3),
            "sequence_match": step_metrics["sequence_match"],
            "predicted_steps": predicted_steps,
            "expected_steps": expected_steps,
        }
        results.append(row)

        if verbose:
            status_icon = "✓" if status_ok else "✗"
            print(
                f"  [{status_icon}] {case_id}: {predicted_status} (expected: {expected_status})"
                f" | F1={step_metrics['f1']:.2f} | Seq={step_metrics['sequence_match']}"
            )

    n = len(sample_cases)
    elapsed = time.time() - start_time
    summary = {
        "total_cases": n,
        "status_accuracy": round(status_correct / n, 4) if n > 0 else 0,
        "avg_step_precision": round(step_precision_sum / n, 4) if n > 0 else 0,
        "avg_step_recall": round(step_recall_sum / n, 4) if n > 0 else 0,
        "avg_step_f1": round(step_f1_sum / n, 4) if n > 0 else 0,
        "sequence_accuracy": round(sequence_matches / n, 4) if n > 0 else 0,
        "elapsed_seconds": round(elapsed, 1),
    }

    print("\n=== Sample Evaluation Summary ===")
    print(f"  Cases evaluated:    {n}")
    print(f"  Status accuracy:    {summary['status_accuracy']:.1%}")
    print(f"  Avg step precision: {summary['avg_step_precision']:.1%}")
    print(f"  Avg step recall:    {summary['avg_step_recall']:.1%}")
    print(f"  Avg step F1:        {summary['avg_step_f1']:.1%}")
    print(f"  Sequence accuracy:  {summary['sequence_accuracy']:.1%}")
    print(f"  Elapsed:            {summary['elapsed_seconds']}s")

    # Print failures
    failures = [r for r in results if not r["status_ok"]]
    if failures:
        print(f"\n  FAILED CASES ({len(failures)}):")
        for r in failures:
            print(f"    {r['case_id']}: predicted={r['predicted_status']}, expected={r['expected_status']}")

    return {"summary": summary, "results": results}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate deletion audit agent on sample cases")
    parser.add_argument("--quiet", action="store_true", help="Less verbose output")
    args = parser.parse_args()

    result = evaluate_samples(verbose=not args.quiet)
    
    # Save detailed results to a JSON for later analysis
    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        ".cache", "evaluation_results.json"
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result["summary"], f, indent=2)
    print(f"\nSummary saved to: {out_path}")
    
    return result


if __name__ == "__main__":
    main()
