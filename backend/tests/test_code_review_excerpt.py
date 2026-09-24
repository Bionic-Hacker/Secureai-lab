"""Unit tests for the code-review excerpt window (no database needed)."""

from app.api.v1.endpoints.code_review import _MAX_EXCERPT_LINE_CHARS, _build_excerpt

TEXT = "\n".join(f"line {n}" for n in range(1, 21))  # 20 lines


def test_window_is_centered_on_the_flagged_line():
    start, lines = _build_excerpt(TEXT, 10, 3)
    assert start == 7
    assert lines == [f"line {n}" for n in range(7, 14)]


def test_window_is_clamped_at_the_top_of_the_file():
    start, lines = _build_excerpt(TEXT, 2, 5)
    assert start == 1
    assert lines[0] == "line 1" and lines[-1] == "line 7"


def test_window_is_clamped_at_the_end_of_the_file():
    start, lines = _build_excerpt(TEXT, 20, 5)
    assert start == 15
    assert lines[-1] == "line 20"


def test_out_of_range_line_number_is_clamped_not_rejected():
    start, lines = _build_excerpt(TEXT, 999, 2)
    assert lines[-1] == "line 20"


def test_empty_file_returns_no_lines():
    assert _build_excerpt("", 5, 3) == (1, [])


def test_very_long_lines_are_truncated():
    _, lines = _build_excerpt("x" * 5000, 1, 0)
    assert len(lines[0]) <= _MAX_EXCERPT_LINE_CHARS + 2
    assert lines[0].endswith("…")
