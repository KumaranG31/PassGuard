"""
test_password_analyzer.py - automated tests for PassGuard

Run from the project folder with:   python -m pytest -v

All passwords used here are FICTIONAL test data.
"""

import io
from pathlib import Path

import pandas as pd
import pytest
from reportlab import rl_config

from password_analyzer import (
    STRENGTH_LEVELS,
    analyze_password,
    calculate_entropy,
    compare_assessments,
    result_to_flat_row,
)
from policy_simulator import PasswordPolicy, evaluate_policy, policy_vs_strength
from report_generator import build_report_filename, generate_pdf_report

APP_PATH = Path(__file__).parent / "app.py"

STRONG_PW = "Tr7#bQm9$Zw2!vPx"          # fictional, 16 chars, random-looking
FAKE_REPORT_PW = "Zx9#fakeSecretQ!"     # fictional, used to prove it never reaches the PDF


# ----------------------------------------------------------------------------- #
# Feature 1 - analyzer
# ----------------------------------------------------------------------------- #

def test_empty_input_returns_valid_result():
    result = analyze_password("")
    assert isinstance(result, dict)
    assert result["is_empty"] is True
    assert result["score"] == 0
    assert result["strength"] == "Weak"
    assert result["weakness_codes"] == ["EMPTY"]


def test_non_string_input_raises_type_error():
    with pytest.raises(TypeError):
        analyze_password(12345)


def test_very_short_password_is_weak():
    result = analyze_password("aB3$")
    assert result["strength"] == "Weak"
    assert "LENGTH_VERY_SHORT" in result["weakness_codes"]
    assert result["score"] <= 39


def test_common_password_detected_and_capped():
    result = analyze_password("password")
    assert result["common_match"] == "exact"
    assert "COMMON_PASSWORD" in result["weakness_codes"]
    assert result["score"] <= 5


def test_common_password_variant_detected():
    result = analyze_password("P@ssw0rd!")
    assert result["common_match"] == "variant"
    assert result["strength"] == "Weak"


def test_sequence_detected():
    assert analyze_password("xxabc9Q#mZ")["has_sequence"] is True
    assert analyze_password("Zk4#321mPq")["has_sequence"] is True


def test_keyboard_pattern_detected():
    assert analyze_password("Zk#qwer9Pm")["has_keyboard_pattern"] is True


def test_repeated_characters_detected():
    result = analyze_password("Zk#9aaaPm2")
    assert result["has_repeated_chars"] is True
    assert "REPEATED_CHARS" in result["weakness_codes"]


def test_repeated_block_detected():
    assert analyze_password("Kx9#abab")["has_repeated_block"] is True


def test_year_pattern_detected():
    assert analyze_password("Zk#2024Pm9q")["has_date_pattern"] is True


def test_longer_fictional_password_scores_high():
    result = analyze_password(STRONG_PW)
    assert result["strength"] == "Very Strong"
    assert result["score"] >= 80
    assert result["weaknesses"] == []
    assert result["length"] == 16


def test_entropy_formula():
    # 8 lowercase letters: N = 26 -> H = 8 * log2(26)
    result = analyze_password("kqmzvbxw")
    assert result["charset_size"] == 26
    assert result["entropy_bits"] == pytest.approx(8 * 4.70044, abs=0.01)
    assert calculate_entropy(0, 26) == 0.0
    assert calculate_entropy(10, 1) == 0.0


def test_result_types_and_ranges():
    result = analyze_password("Hello#World9x")
    assert isinstance(result["score"], int) and 0 <= result["score"] <= 100
    assert result["strength"] in STRENGTH_LEVELS
    assert isinstance(result["entropy_bits"], float)
    assert isinstance(result["weaknesses"], list)
    assert isinstance(result["recommendations"], list)
    assert 0 <= result["character_types"] <= 4


@pytest.mark.parametrize("pw", [FAKE_REPORT_PW, "Kp3mRt8x", "letmein", STRONG_PW])
def test_result_never_contains_the_password(pw):
    result = analyze_password(pw)
    assert pw not in str(result)
    assert pw not in str(result_to_flat_row(result))


def test_flat_row_works_in_dataframe():
    df = pd.DataFrame([result_to_flat_row(analyze_password(STRONG_PW))])
    assert df.shape[0] == 1
    assert "heuristic_score" in df.columns
    assert STRONG_PW not in df.to_csv(index=False)


# ----------------------------------------------------------------------------- #
# Feature 2 - improvement comparison
# ----------------------------------------------------------------------------- #

def test_improvement_comparison():
    before = analyze_password("qwerty123")
    after = analyze_password(STRONG_PW)
    comparison = compare_assessments(before, after)

    assert comparison["score_change"] == after["score"] - before["score"]
    assert comparison["score_change"] > 0
    assert comparison["length_change"] == 16 - 9
    assert comparison["entropy_change"] > 0
    assert comparison["initial_strength"] == "Weak"
    assert comparison["latest_strength"] == "Very Strong"
    assert len(comparison["resolved_weaknesses"]) > 0
    assert comparison["remaining_weaknesses"] == []
    assert comparison["new_weaknesses"] == []
    assert "guarantee" in comparison["summary"].lower()


def test_comparison_tracks_remaining_and_new_weaknesses():
    before = analyze_password("abcdefgh")          # sequence + no upper/digit/symbol ...
    after = analyze_password("abcdefgh1111")       # still sequence, new repeated chars
    comparison = compare_assessments(before, after)
    assert any("sequence" in w.lower() for w in comparison["remaining_weaknesses"])
    assert any("repeated" in w.lower() for w in comparison["new_weaknesses"])


# ----------------------------------------------------------------------------- #
# Feature 3 - policy simulator
# ----------------------------------------------------------------------------- #

def test_password_satisfying_policy():
    policy = PasswordPolicy(min_length=8, require_uppercase=True, require_lowercase=True,
                            require_digit=True, require_special=True)
    result = evaluate_policy("Ab3$efgh", policy)
    assert result["passed"] is True
    assert result["passed_rules"] == result["total_rules"] == 5
    assert all(rule["satisfied"] for rule in result["rules"])


def test_password_failing_policy_reports_each_rule():
    policy = PasswordPolicy(min_length=12, require_uppercase=True, require_lowercase=True,
                            require_digit=True, require_special=True)
    result = evaluate_policy("abcdef", policy)
    assert result["passed"] is False
    status = {rule["rule"]: rule["status"] for rule in result["rules"]}
    assert status["Minimum length"] == "FAIL"
    assert status["Uppercase letter"] == "FAIL"
    assert status["Digit"] == "FAIL"
    assert status["Special character"] == "FAIL"
    assert status["Lowercase letter"] == "PASS"


def test_disabled_rules_are_not_evaluated():
    result = evaluate_policy("abcdefgh", PasswordPolicy(8, False, False, False, False))
    assert result["total_rules"] == 1 and result["passed"] is True


def test_invalid_policy_values_rejected():
    with pytest.raises(ValueError):
        PasswordPolicy(min_length=0)
    with pytest.raises(ValueError):
        PasswordPolicy(min_length=500)


def test_policy_compliance_is_not_strength():
    policy = PasswordPolicy(8, True, True, True, True)
    password = "Password1!"                         # fictional, meets typical rules
    policy_result = evaluate_policy(password, policy)
    analysis = analyze_password(password)
    assert policy_result["passed"] is True
    assert analysis["strength"] == "Weak"           # compliant but predictable
    verdict = policy_vs_strength(policy_result, analysis)
    assert verdict["level"] == "warning"


# ----------------------------------------------------------------------------- #
# Feature 4 - PDF report
# ----------------------------------------------------------------------------- #

def test_pdf_generation_does_not_contain_password():
    # Disable compression so the raw bytes are searchable for the privacy check
    old_values = (rl_config.pageCompression, rl_config.useA85)
    rl_config.pageCompression, rl_config.useA85 = 0, 0
    try:
        analysis = analyze_password(FAKE_REPORT_PW)
        policy_result = evaluate_policy(FAKE_REPORT_PW, PasswordPolicy())
        comparison = compare_assessments(analyze_password("qwerty123"), analysis)
        pdf = generate_pdf_report(analysis, policy_result, comparison)
    finally:
        rl_config.pageCompression, rl_config.useA85 = old_values

    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    assert b"PassGuard Security Audit Report" in pdf          # proves the text is searchable
    assert FAKE_REPORT_PW.encode() not in pdf
    assert b"fakeSecret" not in pdf


def test_pdf_with_only_analysis_and_filename_is_safe():
    pdf = generate_pdf_report(analyze_password(STRONG_PW))
    assert pdf.startswith(b"%PDF") and len(pdf) > 1000
    name = build_report_filename()
    assert name.startswith("PassGuard_Report_") and name.endswith(".pdf")


def test_pdf_rejects_empty_analysis():
    with pytest.raises(ValueError):
        generate_pdf_report(analyze_password(""))


# ----------------------------------------------------------------------------- #
# Streamlit app - must not crash when nothing has been analysed yet
# ----------------------------------------------------------------------------- #

def test_app_pages_do_not_crash_without_analysis():
    pytest.importorskip("streamlit.testing.v1")
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP_PATH), default_timeout=60).run()
    assert not at.exception
    for page in ("Improvement Analytics", "Policy Simulator", "Security Report", "Password Analyzer"):
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, f"{page} raised an exception"
