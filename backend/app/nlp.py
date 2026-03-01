"""
NLP Scam Message Detection
───────────────────────────
Rule-based analysis + optional ML (logistic regression) loaded from pickle.
"""

import os
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger("sit.nlp")

# ── Keyword categories ──
URGENCY = [
    "urgent", "immediately", "now", "expire", "hurry", "limited time",
    "act fast", "don't wait", "asap", "deadline", "right away",
]
ACTION = [
    "click", "verify", "confirm", "update", "login", "sign in",
    "tap here", "open", "download", "install", "activate",
]
THREAT = [
    "account", "bank", "payment", "credit card", "password", "ssn",
    "social security", "identity", "suspended", "locked", "unauthorized",
]
REWARD = [
    "prize", "winner", "congratulations", "free", "gift", "bonus",
    "reward", "jackpot", "lottery", "cash", "million",
]
PRESSURE = [
    "or else", "will be closed", "within 24", "within 48",
    "last chance", "final notice", "legal action", "authorities",
]

# ── Optional ML model ──
DATASETS_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"
MODEL_PATH = DATASETS_DIR / "nlp_model.pkl"
VECTORIZER_PATH = DATASETS_DIR / "nlp_vectorizer.pkl"
_ml_model = None
_ml_vectorizer = None
_ml_loaded = False


def _load_ml():
    global _ml_model, _ml_vectorizer, _ml_loaded
    if _ml_loaded:
        return _ml_model is not None
    _ml_loaded = True
    try:
        if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                _ml_model = pickle.load(f)
            with open(VECTORIZER_PATH, "rb") as f:
                _ml_vectorizer = pickle.load(f)
            logger.info("NLP ML model loaded from %s", MODEL_PATH)
            return True
    except Exception as e:
        logger.warning("Could not load ML model: %s", e)
    return False


def _hits(text: str, patterns: List[str]) -> List[str]:
    tl = text.lower()
    return [p for p in patterns if p in tl]


def analyze_message(text: str) -> Dict[str, Any]:
    """Analyze message text for scam indicators."""
    breakdown: list = []
    triggers: list = []

    urg = _hits(text, URGENCY)
    if urg:
        pts = min(len(urg) * 4, 12)
        breakdown.append({"source": "nlp", "rule": "Urgency language", "points": pts, "detail": ", ".join(urg[:4])})
        triggers.extend(urg)

    act = _hits(text, ACTION)
    if act:
        pts = min(len(act) * 3, 10)
        breakdown.append({"source": "nlp", "rule": "Call-to-action", "points": pts, "detail": ", ".join(act[:4])})
        triggers.extend(act)

    thr = _hits(text, THREAT)
    if thr:
        pts = min(len(thr) * 4, 12)
        breakdown.append({"source": "nlp", "rule": "Threat indicators", "points": pts, "detail": ", ".join(thr[:4])})
        triggers.extend(thr)

    rew = _hits(text, REWARD)
    if rew:
        pts = min(len(rew) * 4, 12)
        breakdown.append({"source": "nlp", "rule": "Reward / bait", "points": pts, "detail": ", ".join(rew[:4])})
        triggers.extend(rew)

    prs = _hits(text, PRESSURE)
    if prs:
        pts = min(len(prs) * 5, 10)
        breakdown.append({"source": "nlp", "rule": "Pressure tactics", "points": pts, "detail": ", ".join(prs[:3])})
        triggers.extend(prs)

    words = text.split()
    caps = [w for w in words if w.isupper() and len(w) > 2]
    if len(caps) >= 3:
        breakdown.append({"source": "nlp", "rule": "Excessive caps", "points": 5, "detail": f"{len(caps)} ALL-CAPS words"})

    if text.count("!") >= 3:
        breakdown.append({"source": "nlp", "rule": "Excessive punctuation", "points": 3, "detail": f"{text.count('!')} exclamation marks"})

    score = sum(b["points"] for b in breakdown)
    score = min(score, 100)

    # Optional ML boost
    ml_label = None
    ml_confidence = None
    if _load_ml() and _ml_model and _ml_vectorizer:
        try:
            X = _ml_vectorizer.transform([text])
            pred = _ml_model.predict(X)[0]
            prob = max(_ml_model.predict_proba(X)[0])
            ml_label = str(pred)
            ml_confidence = round(prob, 3)
            if pred == "scam" and prob > 0.7:
                breakdown.append({"source": "nlp_ml", "rule": "ML classifier", "points": 10, "detail": f"scam ({prob:.0%})"})
                score = min(score + 10, 100)
        except Exception:
            pass

    label = "scam" if score >= 50 else "suspicious" if score >= 20 else "safe"

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        "triggers": triggers,
        "ml_label": ml_label,
        "ml_confidence": ml_confidence,
    }
