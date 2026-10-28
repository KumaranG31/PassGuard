"""
app.py - PassGuard Streamlit dashboard
======================================

Run with:   python -m streamlit run app.py

Pages (sidebar):
    1. Password Analyzer
    2. Improvement Analytics
    3. Policy Simulator
    4. Security Report

PRIVACY DESIGN
--------------
* Passwords are typed into masked inputs and passed straight to the analysis functions.
* Only the NON-SENSITIVE analysis dictionaries are kept in st.session_state.
* The analyzer / improvement pages use forms with clear_on_submit=True, so the text box
  is emptied after each check.
* Nothing is written to disk or logged. No database, no login.
"""

import pandas as pd
import streamlit as st
import matplotlib

matplotlib.use("Agg")  # non-interactive backend, safe for servers
import matplotlib.pyplot as plt  # noqa: E402

from password_analyzer import (  # noqa: E402
    ENTROPY_NOTE,
    SCORE_NOTE,
    analyze_password,
    compare_assessments,
    result_to_flat_row,
)
from policy_simulator import (  # noqa: E402
    PRESET_POLICIES,
    PasswordPolicy,
    evaluate_policy,
    policy_vs_strength,
)
from report_generator import build_report_filename, generate_pdf_report  # noqa: E402

st.set_page_config(page_title="PassGuard", page_icon="🛡️", layout="wide")

STRENGTH_COLORS = {
    "Weak": "#c62828",
    "Moderate": "#ef6c00",
    "Strong": "#2e7d32",
    "Very Strong": "#00695c",
}
POLICY_DEFAULTS = {"pol_min_length": 8, "pol_upper": True, "pol_lower": True,
                   "pol_digit": True, "pol_special": True}
PAGES = ["Password Analyzer", "Improvement Analytics", "Policy Simulator", "Security Report"]

CSS = """
<style>
.pg-banner {background: linear-gradient(90deg, #0b2545 0%, #13315c 60%, #1f6feb 100%);
            padding: 18px 24px; border-radius: 10px; color: white; margin-bottom: 12px;}
.pg-banner h1 {color: white; margin: 0; font-size: 1.9rem;}
.pg-banner p {color: #cfe0ff; margin: 4px 0 0 0; font-size: 0.95rem;}
.pg-badge {display: inline-block; padding: 6px 16px; border-radius: 20px; color: white;
           font-weight: 700; font-size: 1.1rem;}
</style>
"""


# --------------------------------------------------------------------------- #
# Session state helpers
# --------------------------------------------------------------------------- #

def init_state():
    """Create all session keys once. None means 'nothing analysed yet'."""
    defaults = {
        "latest_analysis": None,        # most recent analysis (any page) - used by the report
        "latest_policy_result": None,   # policy result that belongs to latest_analysis (or None)
        "baseline_analysis": None,      # Improvement Analytics: initial assessment
        "revised_analysis": None,       # Improvement Analytics: revised assessment
        # Policy settings survive page changes (Streamlit deletes widget keys of hidden pages)
        "policy_saved": dict(POLICY_DEFAULTS),
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def set_latest(analysis, policy_result=None):
    """Remember the latest assessment. A new assessment invalidates the old policy result."""
    st.session_state.latest_analysis = analysis
    st.session_state.latest_policy_result = policy_result


def reset_comparison():
    st.session_state.baseline_analysis = None
    st.session_state.revised_analysis = None


def clear_everything():
    for key in ("latest_analysis", "latest_policy_result", "baseline_analysis", "revised_analysis"):
        st.session_state[key] = None


def apply_preset():
    """Callback for the preset selector (changes the policy widget values)."""
    name = st.session_state.get("preset_choice")
    preset = PRESET_POLICIES.get(name)
    if preset:
        st.session_state.pol_min_length = preset.min_length
        st.session_state.pol_upper = preset.require_uppercase
        st.session_state.pol_lower = preset.require_lowercase
        st.session_state.pol_digit = preset.require_digit
        st.session_state.pol_special = preset.require_special


# --------------------------------------------------------------------------- #
# Reusable UI pieces
# --------------------------------------------------------------------------- #

def page_header(title, subtitle):
    st.markdown(f'<div class="pg-banner"><h1>🛡️ PassGuard</h1><p>{title} - {subtitle}</p></div>',
                unsafe_allow_html=True)
    st.info("🔒 **Privacy notice:** use FICTIONAL passwords only. Never enter a password you use "
            "for a real account. PassGuard does not save, log or export the password itself.")


def strength_badge(strength):
    color = STRENGTH_COLORS.get(strength, "#555555")
    st.markdown(f'<span class="pg-badge" style="background:{color}">{strength}</span>',
                unsafe_allow_html=True)


def yes_no(flag):
    return "✅ Yes" if flag else "❌ No"


def show_analysis(analysis, heading="Assessment"):
    """Display one analysis dictionary (metrics, checks, weaknesses, recommendations, chart)."""
    st.subheader(heading)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.caption("Strength classification")
        strength_badge(analysis["strength"])
    col2.metric("Heuristic score", f"{analysis['score']} / 100")
    col3.metric("Length", f"{analysis['length']} chars")
    col4.metric("Theoretical entropy", f"{analysis['entropy_bits']} bits")
    st.progress(min(max(analysis["score"], 0), 100) / 100)
    st.caption("⚠️ " + SCORE_NOTE)
    if analysis.get("score_cap_reason"):
        st.caption("ℹ️ " + analysis["score_cap_reason"])

    left, right = st.columns(2)
    with left:
        st.markdown("**Character types**")
        st.write(f"Lowercase: {yes_no(analysis['has_lowercase'])}")
        st.write(f"Uppercase: {yes_no(analysis['has_uppercase'])}")
        st.write(f"Digits: {yes_no(analysis['has_digit'])}")
        st.write(f"Symbols: {yes_no(analysis['has_symbol'])}")
        st.write(f"Assumed character-set size N = **{analysis['charset_size']}**")
    with right:
        st.markdown("**Pattern checks** (✅ = problem detected)")
        match = analysis["common_match"]
        st.write(f"Common password match: {'✅ ' + match if match else '❌ none'}")
        st.write(f"Sequence (abc/123): {yes_no(analysis['has_sequence'])}")
        st.write(f"Keyboard pattern: {yes_no(analysis['has_keyboard_pattern'])}")
        st.write(f"Repeated characters: {yes_no(analysis['has_repeated_chars'])}")
        st.write(f"Repeated block: {yes_no(analysis['has_repeated_block'])}")
        st.write(f"Year pattern: {yes_no(analysis['has_date_pattern'])}")

    zx = analysis.get("zxcvbn")
    if zx:
        st.write(f"**zxcvbn cross-check:** score {zx['score']} / 4 "
                 f"(about 10^{zx['guesses_log10']} guesses). zxcvbn is an independent, "
                 "widely used guessability estimator.")
    else:
        st.caption("zxcvbn cross-check not available (optional package not installed).")

    st.markdown("**Detected weaknesses**")
    if analysis["weaknesses"]:
        for item in analysis["weaknesses"]:
            st.write(f"⚠️ {item}")
    else:
        st.success("No weaknesses detected by PassGuard's checks (this does not prove security).")

    st.markdown("**Recommendations**")
    for item in analysis["recommendations"]:
        st.write(f"➡️ {item}")

    with st.expander("How the score and entropy are calculated"):
        st.write(ENTROPY_NOTE)
        st.write("Score = Entropy points (max 50) + Length (max 20) + Variety (max 20) + "
                 "Uniqueness (max 10) - Pattern penalties, then capped for short or "
                 "predictable passwords.")
        fig = fig_score_breakdown(analysis)
        st.pyplot(fig)
        plt.close(fig)


# --------------------------------------------------------------------------- #
# Charts (Matplotlib)
# --------------------------------------------------------------------------- #

def fig_score_breakdown(analysis):
    items = analysis["score_breakdown"]
    labels = list(items.keys())
    values = list(items.values())
    fig, ax = plt.subplots(figsize=(7, 3.2))
    colors = ["#c62828" if v < 0 else "#1f6feb" for v in values]
    bars = ax.barh(labels, values, color=colors)
    ax.axvline(0, color="black", linewidth=0.8)
    ax.invert_yaxis()
    ax.set_xlabel("Points contributed to the heuristic score")
    ax.set_title("Score breakdown")
    for bar, value in zip(bars, values):
        ax.annotate(f"{value:+.1f}", (value, bar.get_y() + bar.get_height() / 2),
                    xytext=(4 if value >= 0 else -4, 0), textcoords="offset points",
                    ha="left" if value >= 0 else "right", va="center", fontsize=9)
    ax.margins(x=0.15)
    fig.tight_layout()
    return fig


def fig_comparison(comparison):
    """Three small bar charts: heuristic score, entropy and length (initial vs latest)."""
    metrics = [
        ("Heuristic score (0-100)", comparison["initial_score"], comparison["latest_score"]),
        ("Theoretical entropy (bits)", comparison["initial_entropy"], comparison["latest_entropy"]),
        ("Length (characters)", comparison["initial_length"], comparison["latest_length"]),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.6))
    for ax, (title, before, after) in zip(axes, metrics):
        bars = ax.bar(["Initial", "Latest"], [before, after], color=["#8a94a6", "#1f6feb"])
        ax.set_title(title, fontsize=11)
        ax.set_ylim(0, max(before, after, 1) * 1.25)
        for bar, value in zip(bars, (before, after)):
            ax.annotate(f"{value}", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=10)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("Initial vs latest assessment (heuristic values, not a security guarantee)",
                 fontsize=11)
    fig.tight_layout()
    return fig


# --------------------------------------------------------------------------- #
# Page 1 - Password Analyzer
# --------------------------------------------------------------------------- #

def page_analyzer():
    page_header("Password Analyzer", "evaluate a fictional password")

    # clear_on_submit empties the text box after the check
    with st.form("analyzer_form", clear_on_submit=True):
        password = st.text_input("Enter a fictional password", type="password",
                                 help="Masked by default. Do not use a real password.")
        submitted = st.form_submit_button("Analyze password")

    if submitted:
        if not password:
            st.error("Please enter a password before analyzing.")
        else:
            set_latest(analyze_password(password))
        password = None  # drop our reference immediately

    analysis = st.session_state.latest_analysis
    if analysis is None:
        st.info("No analysis yet. Enter a fictional password above and press **Analyze password**.")
        return

    show_analysis(analysis, "Latest assessment")
    st.button("📌 Use this as the starting point in Improvement Analytics",
              on_click=_set_baseline_from_latest)
    if st.session_state.baseline_analysis is not None and st.session_state.revised_analysis is None:
        st.caption("Starting point saved. Open **Improvement Analytics** to check a revised password.")


def _set_baseline_from_latest():
    st.session_state.baseline_analysis = st.session_state.latest_analysis
    st.session_state.revised_analysis = None


# --------------------------------------------------------------------------- #
# Page 2 - Improvement Analytics
# --------------------------------------------------------------------------- #

def page_improvement():
    page_header("Improvement Analytics", "compare an initial and a revised password")
    st.write("1. Check an **initial** fictional password.  2. Change it and check the **revised** "
             "one.  3. Compare the two assessments. Only the assessment results are kept "
             "(temporarily, in this browser session) - never the passwords.")

    baseline = st.session_state.baseline_analysis
    revised = st.session_state.revised_analysis

    if baseline is None:
        st.subheader("Step 1 - Initial password")
        with st.form("baseline_form", clear_on_submit=True):
            password = st.text_input("Initial fictional password", type="password")
            submitted = st.form_submit_button("Save initial assessment")
        if submitted:
            if not password:
                st.error("Please enter an initial password.")
            else:
                st.session_state.baseline_analysis = analyze_password(password)
                st.session_state.revised_analysis = None
                password = None
                st.rerun()
        st.info("No initial assessment yet.")
        return

    st.success(f"Initial assessment saved: **{baseline['strength']}** "
               f"(score {baseline['score']}, {baseline['length']} characters).")

    st.subheader("Step 2 - Revised password")
    with st.form("revised_form", clear_on_submit=True):
        password = st.text_input("Revised fictional password", type="password")
        submitted = st.form_submit_button("Check revised password")
    if submitted:
        if not password:
            st.error("Please enter a revised password.")
        else:
            st.session_state.revised_analysis = analyze_password(password)
            set_latest(st.session_state.revised_analysis)
            password = None
            st.rerun()

    st.button("🔄 Reset comparison / set a new starting point", on_click=reset_comparison)

    revised = st.session_state.revised_analysis
    if revised is None:
        st.info("Enter a revised password to see the comparison.")
        return

    comparison = compare_assessments(baseline, revised)
    st.subheader("Step 3 - Comparison")

    c1, c2, c3 = st.columns(3)
    c1.metric("Strength", comparison["latest_strength"],
              help=f"Initial: {comparison['initial_strength']}")
    c1.caption(f"Initial: {comparison['initial_strength']}  ->  Latest: {comparison['latest_strength']}")
    c2.metric("Heuristic score", f"{comparison['latest_score']} / 100",
              delta=f"{comparison['score_change']:+d}")
    c3.metric("Estimated entropy", f"{comparison['latest_entropy']} bits",
              delta=f"{comparison['entropy_change']:+.2f}")
    c4, c5, c6 = st.columns(3)
    c4.metric("Length", comparison["latest_length"], delta=f"{comparison['length_change']:+d}")
    c5.metric("Character types (of 4)", comparison["latest_character_types"],
              delta=f"{comparison['character_types_change']:+d}")
    c6.metric("Initial score", f"{comparison['initial_score']} / 100")

    if comparison["score_change"] > 0:
        st.success(comparison["summary"])
    elif comparison["score_change"] < 0:
        st.warning(comparison["summary"])
    else:
        st.info(comparison["summary"])

    w1, w2, w3, w4 = st.columns(4)
    for col, title, items, icon in (
        (w1, "Detected initially", comparison["initial_weaknesses"], "⚠️"),
        (w2, "No longer detected", comparison["resolved_weaknesses"], "✅"),
        (w3, "Still present", comparison["remaining_weaknesses"], "⏳"),
        (w4, "Newly detected", comparison["new_weaknesses"], "🆕"),
    ):
        with col:
            st.markdown(f"**{title}**")
            if items:
                for item in items:
                    st.write(f"{icon} {item}")
            else:
                st.caption("None")

    fig = fig_comparison(comparison)
    st.pyplot(fig)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# Page 3 - Policy Simulator
# --------------------------------------------------------------------------- #

def page_policy():
    page_header("Policy Simulator", "test a password against configurable rules")
    st.write("Change the rules and see immediately which requirements are met. "
             "**Policy compliance is not the same as password strength.**")

    # Restore the saved settings if the widgets were removed while another page was open
    for key, saved_value in st.session_state.policy_saved.items():
        if key not in st.session_state:
            st.session_state[key] = saved_value

    left, right = st.columns([1, 1.4])
    with left:
        st.subheader("Policy rules")
        st.selectbox("Load a preset", list(PRESET_POLICIES.keys()), index=None,
                     placeholder="Choose a preset (optional)", key="preset_choice",
                     on_change=apply_preset)
        st.slider("Minimum length", 1, 64, key="pol_min_length")
        st.checkbox("Require uppercase letters", key="pol_upper")
        st.checkbox("Require lowercase letters", key="pol_lower")
        st.checkbox("Require digits", key="pol_digit")
        st.checkbox("Require special characters", key="pol_special")

    st.session_state.policy_saved = {key: st.session_state[key] for key in POLICY_DEFAULTS}

    policy = PasswordPolicy(
        min_length=int(st.session_state.pol_min_length),
        require_uppercase=bool(st.session_state.pol_upper),
        require_lowercase=bool(st.session_state.pol_lower),
        require_digit=bool(st.session_state.pol_digit),
        require_special=bool(st.session_state.pol_special),
    )

    with right:
        st.subheader("Test a password")
        password = st.text_input("Fictional password to test", type="password")
        if not password:
            st.info("Enter a fictional password to test it against the policy. "
                    "Nothing is evaluated until you type something.")
            return

        result = evaluate_policy(password, policy)
        analysis = analyze_password(password)
        set_latest(analysis, result)   # so the Security Report can include the policy section
        password = None

        if result["passed"]:
            st.success(f"✅ PASS - all {result['total_rules']} rules satisfied")
        else:
            st.error(f"❌ FAIL - {result['passed_rules']} of {result['total_rules']} rules satisfied")

        for rule in result["rules"]:
            icon = "✅" if rule["satisfied"] else "❌"
            st.write(f"{icon} **{rule['rule']}** - {rule['requirement']} ({rule['detail']})")

        st.markdown("---")
        st.markdown("**Policy compliance vs. password strength**")
        c1, c2 = st.columns(2)
        c1.metric("Policy result", "PASS" if result["passed"] else "FAIL")
        c2.metric("Heuristic strength", analysis["strength"], help=f"Score {analysis['score']} / 100")
        verdict = policy_vs_strength(result, analysis)
        getattr(st, verdict["level"])(verdict["message"])


# --------------------------------------------------------------------------- #
# Page 4 - Security Report
# --------------------------------------------------------------------------- #

def page_report():
    page_header("Security Report", "download a PDF audit report")
    analysis = st.session_state.latest_analysis
    if analysis is None:
        st.info("No assessment available yet. Analyze a fictional password on the "
                "**Password Analyzer** page (or test one in the **Policy Simulator**) first.")
        return

    policy_result = st.session_state.latest_policy_result
    st.subheader("Report contents")
    c1, c2, c3 = st.columns(3)
    c1.metric("Strength", analysis["strength"])
    c2.metric("Heuristic score", f"{analysis['score']} / 100")
    c3.metric("Entropy estimate", f"{analysis['entropy_bits']} bits")
    st.write(f"Weaknesses detected: **{len(analysis['weaknesses'])}**")
    st.write("Policy compliance section: "
             + ("✅ included" if policy_result else "➖ not available (use the Policy Simulator)"))

    comparison = None
    baseline, revised = st.session_state.baseline_analysis, st.session_state.revised_analysis
    if baseline is not None and revised is not None:
        if st.checkbox("Include the improvement comparison", value=False):
            comparison = compare_assessments(baseline, revised)

    if analysis["is_empty"]:
        st.error("The stored assessment is empty and cannot be exported.")
        return

    try:
        pdf_bytes = generate_pdf_report(analysis, policy_result, comparison)
    except Exception as error:  # show a friendly message instead of a stack trace
        st.error(f"Could not generate the PDF report: {error}")
        return

    d1, d2 = st.columns(2)
    d1.download_button("⬇️ Download PDF report", data=pdf_bytes,
                       file_name=build_report_filename(), mime="application/pdf")
    csv_bytes = pd.DataFrame([result_to_flat_row(analysis)]).to_csv(index=False).encode("utf-8")
    d2.download_button("⬇️ Download assessment as CSV (non-sensitive fields only)", data=csv_bytes,
                       file_name=build_report_filename().replace(".pdf", ".csv"), mime="text/csv")
    st.caption("The report and CSV never contain the password. Filenames contain only a timestamp.")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    init_state()
    st.markdown(CSS, unsafe_allow_html=True)

    with st.sidebar:
        st.title("🛡️ PassGuard")
        st.caption("Intelligent Password Security Auditor and Policy Analysis System")
        page = st.radio("Navigation", PAGES)
        st.warning("Use fictional passwords only. Never type a password from a real account.")
        st.button("🗑️ Clear all session data", on_click=clear_everything)
        st.caption("Educational tool. Heuristic results are not a security guarantee.")

    if page == "Password Analyzer":
        page_analyzer()
    elif page == "Improvement Analytics":
        page_improvement()
    elif page == "Policy Simulator":
        page_policy()
    else:
        page_report()


main()
