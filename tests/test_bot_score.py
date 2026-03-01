r"""
SIT Bot – Score display tests
─────────────────────────────
Run: cd backend && .venv\Scripts\python.exe -m pytest ../tests/test_bot_score.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend" / "bot"))

import bot


def test_score_meter_0():
    """0%: all empty blocks."""
    m = bot._score_meter(0)
    assert m == "\u2B1C" * 10
    assert len(m) == 10


def test_score_meter_25():
    """25%: ~2-3 filled (green)."""
    m = bot._score_meter(25)
    assert m.count("\U0001F7E9") >= 2
    assert m.count("\u2B1C") >= 7


def test_score_meter_50():
    """50%: 5 filled (all green)."""
    m = bot._score_meter(50)
    assert m.count("\U0001F7E9") == 5
    assert m.count("\u2B1C") == 5


def test_score_meter_75():
    """75%: 8 filled (green + yellow + some red)."""
    m = bot._score_meter(75)
    filled = 10 - m.count("\u2B1C")
    assert filled == 8


def test_score_meter_100():
    """100%: all 10 filled (green, yellow, red)."""
    m = bot._score_meter(100)
    assert m.count("\u2B1C") == 0
    assert len(m) == 10


def test_score_meter_51():
    """51%: 6 filled = 5 green + 1 yellow (per spec example)."""
    m = bot._score_meter(51)
    assert m.count("\U0001F7E9") == 5  # green
    assert m.count("\U0001F7E8") == 1  # yellow
    assert m.count("\u2B1C") == 4      # empty


def test_score_display_format():
    """Score display includes 'Score: X/100' and meter."""
    d = bot._score_display(51)
    assert "Score: 51/100" in d
    assert "\n" in d
    assert len(d.split("\n")) == 2
