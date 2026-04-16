"""Evaluation endpoints: run pipeline, return metrics."""

import json
import csv
from pathlib import Path

from fastapi import APIRouter, Depends

from ..security import get_current_admin
from ..scoring import compute_risk_score

router = APIRouter(prefix="/evaluation", tags=["evaluation"])

BASE = Path(__file__).resolve().parent.parent.parent.parent
DATASETS_DIR = BASE / "datasets"
EVAL_DIR = BASE / "evaluation"
METRICS_PATH = EVAL_DIR / "metrics.json"


@router.get("/metrics")
def get_metrics(admin=Depends(get_current_admin)):
    if METRICS_PATH.exists():
        return json.loads(METRICS_PATH.read_text())
    return {"error": "No evaluation run yet. POST /evaluation/run or run evaluation/evaluate.py"}


@router.post("/run")
def run_evaluation(admin=Depends(get_current_admin)):
    """Run evaluation pipeline against scam_urls.csv (heuristic-only, deterministic)."""
    csv_path = DATASETS_DIR / "scam_urls.csv"
    if not csv_path.exists():
        return {"error": f"Dataset not found: {csv_path}"}

    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        return {"error": "Dataset is empty"}

    y_true = []
    y_pred = []
    details = []

    for row in rows:
        url = row.get("url", "").strip()
        label = row.get("label", "").strip().lower()
        if not url or not label:
            continue

        result = compute_risk_score(url, skip_intel=True)
        pred = result["verdict"]
        y_true.append(label)
        y_pred.append(pred)
        details.append({
            "url": url[:100],
            "true": label,
            "predicted": pred,
            "score": result["score"],
            "correct": label == pred,
        })

    # Compute metrics
    labels = sorted(set(y_true + y_pred))
    metrics_per_class = {}
    for lbl in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p == lbl)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lbl and p == lbl)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p != lbl)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        metrics_per_class[lbl] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "support": sum(1 for t in y_true if t == lbl),
        }

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = round(correct / len(y_true), 3) if y_true else 0

    # Macro averages
    avg_p = round(sum(m["precision"] for m in metrics_per_class.values()) / max(len(metrics_per_class), 1), 3)
    avg_r = round(sum(m["recall"] for m in metrics_per_class.values()) / max(len(metrics_per_class), 1), 3)
    avg_f1 = round(sum(m["f1"] for m in metrics_per_class.values()) / max(len(metrics_per_class), 1), 3)

    from datetime import date
    output = {
        "accuracy": accuracy,
        "precision": avg_p,
        "recall": avg_r,
        "f1": avg_f1,
        "per_class": metrics_per_class,
        "dataset_size": len(y_true),
        "correct": correct,
        "last_evaluated": str(date.today()),
        "details": details[:20],  # Sample for display
    }

    # Save
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(output, indent=2))

    return output
