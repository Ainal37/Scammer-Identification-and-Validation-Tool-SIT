"""Tests for get_recommended_actions() in pdf_report module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pdf_report import get_recommended_actions, _score_to_category


def test_score_to_category():
    assert _score_to_category(0) == "safe"
    assert _score_to_category(25) == "safe"
    assert _score_to_category(26) == "caution"
    assert _score_to_category(50) == "caution"
    assert _score_to_category(51) == "suspicious"
    assert _score_to_category(75) == "suspicious"
    assert _score_to_category(76) == "scam"
    assert _score_to_category(100) == "scam"
    assert _score_to_category(-5) == "safe"
    assert _score_to_category(200) == "scam"


def test_safe_score_0():
    result = get_recommended_actions(0, "safe", "https://example.com")
    assert result["title"] == "Recommended actions"
    assert len(result["bullets"]) >= 3
    assert "low-risk" in result["note"].lower()
    assert any("stay alert" in b.lower() for b in result["bullets"])


def test_caution_score_30():
    result = get_recommended_actions(30, "suspicious", "https://example.com")
    assert result["title"] == "Recommended actions"
    assert len(result["bullets"]) >= 3
    assert any("official" in b.lower() for b in result["bullets"])
    assert "warning signs" in result["note"].lower()


def test_suspicious_score_60():
    result = get_recommended_actions(60, "suspicious", "https://phish.example.com")
    assert result["title"] == "Recommended actions"
    assert len(result["bullets"]) >= 3
    assert any("password" in b.lower() or "otp" in b.lower() for b in result["bullets"])
    assert "red flags" in result["note"].lower()


def test_scam_score_90():
    result = get_recommended_actions(90, "scam", "https://evil.example.com")
    assert result["title"] == "Recommended actions"
    assert len(result["bullets"]) >= 4
    assert any("do not open" in b.lower() for b in result["bullets"])
    assert "high confidence" in result["note"].lower()


def test_verdict_score_mismatch():
    """Verdict says SCAM but score is only 30 (CAUTION range) -> extra bullet."""
    result = get_recommended_actions(30, "scam", "https://example.com")
    assert any("conflicts" in b.lower() for b in result["bullets"])
    assert "warning signs" in result["note"].lower()


def test_no_mismatch_bullet_when_aligned():
    """No mismatch bullet when verdict and score agree."""
    result = get_recommended_actions(90, "scam", "https://evil.example.com")
    assert not any("conflicts" in b.lower() for b in result["bullets"])


def test_returns_dict_keys():
    for score in (0, 30, 60, 90):
        result = get_recommended_actions(score, "safe")
        assert "title" in result
        assert "bullets" in result
        assert "note" in result
        assert isinstance(result["bullets"], list)
        assert isinstance(result["note"], str)


if __name__ == "__main__":
    tests = [
        test_score_to_category,
        test_safe_score_0,
        test_caution_score_30,
        test_suspicious_score_60,
        test_scam_score_90,
        test_verdict_score_mismatch,
        test_no_mismatch_bullet_when_aligned,
        test_returns_dict_keys,
    ]
    passed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed.")
