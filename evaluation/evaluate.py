"""
SIT Evaluation Pipeline
───────────────────────
Runs heuristic scoring against datasets/scam_urls.csv
and optionally trains an NLP model on scam_messages.csv.

Usage:
    cd backend
    .venv/Scripts/python -m evaluation.evaluate
  OR
    Run via API: POST /evaluation/run
"""

import csv
import json
import sys
from pathlib import Path

# Add backend to path so we can import app modules
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

DATASETS = ROOT / "datasets"
METRICS_OUT = ROOT / "evaluation" / "metrics.json"


def evaluate_urls():
    from app.scoring import compute_risk_score

    csv_path = DATASETS / "scam_urls.csv"
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    y_true, y_pred = [], []

    for row in rows:
        url = row["url"].strip()
        label = row["label"].strip().lower()
        result = compute_risk_score(url, skip_intel=True)
        y_true.append(label)
        y_pred.append(result["verdict"])

    labels = sorted(set(y_true + y_pred))
    per_class = {}
    for lbl in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p == lbl)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lbl and p == lbl)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lbl and p != lbl)
        prec = tp / (tp + fp) if (tp + fp) else 0
        rec = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
        per_class[lbl] = {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3), "support": sum(1 for t in y_true if t == lbl)}

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    accuracy = round(correct / len(y_true), 3) if y_true else 0
    avg_p = round(sum(m["precision"] for m in per_class.values()) / len(per_class), 3)
    avg_r = round(sum(m["recall"] for m in per_class.values()) / len(per_class), 3)
    avg_f1 = round(sum(m["f1"] for m in per_class.values()) / len(per_class), 3)

    from datetime import date
    output = {
        "accuracy": accuracy, "precision": avg_p, "recall": avg_r, "f1": avg_f1,
        "per_class": per_class, "dataset_size": len(y_true), "correct": correct,
        "last_evaluated": str(date.today()),
    }

    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    METRICS_OUT.write_text(json.dumps(output, indent=2))
    print(f"Evaluation complete: {correct}/{len(y_true)} correct ({accuracy*100:.1f}%)")
    print(f"Precision: {avg_p}  Recall: {avg_r}  F1: {avg_f1}")
    for lbl, m in per_class.items():
        print(f"  {lbl:12s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  n={m['support']}")
    print(f"Saved to {METRICS_OUT}")
    return output


def train_nlp_model():
    """Train logistic regression on scam_messages.csv (optional)."""
    csv_path = DATASETS / "scam_messages.csv"
    if not csv_path.exists():
        print("Messages dataset not found."); return

    try:
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
        import pickle
    except ImportError:
        print("sklearn/pandas not installed. Skipping NLP training."); return

    df = pd.read_csv(csv_path)
    X, y = df["message"], df["label"]

    vec = TfidfVectorizer(max_features=500, stop_words="english")
    X_tfidf = vec.fit_transform(X)

    model = LogisticRegression(max_iter=1000)
    scores = cross_val_score(model, X_tfidf, y, cv=min(3, len(df)))
    model.fit(X_tfidf, y)

    model_path = DATASETS / "nlp_model.pkl"
    vec_path = DATASETS / "nlp_vectorizer.pkl"
    with open(model_path, "wb") as f: pickle.dump(model, f)
    with open(vec_path, "wb") as f: pickle.dump(vec, f)

    print(f"NLP model trained. CV accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})")
    print(f"Saved to {model_path}")


if __name__ == "__main__":
    print("=" * 50)
    print("SIT Evaluation Pipeline")
    print("=" * 50)
    evaluate_urls()
    print()
    train_nlp_model()
