# PassGuard - Intelligent Password Security Auditor and Policy Analysis System

PassGuard evaluates a **fictional** password, explains its weaknesses, estimates its *theoretical* entropy,
tracks improvement between two passwords, simulates password policies and exports a PDF report.
**It never stores, logs, prints or exports the password itself.**

> ⚠️ Use fictional passwords only. Never type a password from a real account into any tool you do not fully control.
> The 0-100 score is a **heuristic**, and entropy is a **theoretical estimate** (`H = L x log2(N)`) that assumes
> random, independent characters. Neither guarantees real-world security.

## Project structure

```
PassGuard/
├── app.py                      Streamlit dashboard (4 pages)
├── password_analyzer.py        Core analysis engine (no Streamlit dependency)
├── policy_simulator.py         Configurable password policy checks
├── report_generator.py         PDF report (ReportLab)
├── PassGuard.ipynb             Documentation + test cases + charts (already executed)
├── test_password_analyzer.py   Automated tests (pytest)
├── requirements.txt
├── README.md
├── PROJECT_DOCUMENTATION.md    Academic write-up + viva questions
├── .streamlit/config.toml      Light theme, usage statistics off
└── data/
    └── common_passwords.txt    Small starter list of very common passwords
```

Design decisions: the structure from the brief was kept as-is. Three small extras were added: the test file,
`PROJECT_DOCUMENTATION.md`, and `.streamlit/config.toml` (theme). **No SQLite database is used** - nothing needs to be
stored, and avoiding it removes any chance of persisting sensitive data. **No machine learning is used** - the analysis is rule-based.

## Setup on Windows (PowerShell in VS Code)

```powershell
# 1. Go to the folder that contains PassGuard (adjust the path)
cd $HOME\Desktop\PassGuard

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
#    If PowerShell blocks the script, run this once and activate again:
#    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. (Optional but recommended) independent guessability cross-check
python -m pip install zxcvbn
```

If you are creating the files by hand instead of unzipping: make the folders `PassGuard` and `PassGuard\data`,
then create each file with the exact filename shown above and paste its contents.

## Run the app

```powershell
python -m streamlit run app.py
```

Your browser opens at http://localhost:8501. Stop the server with `Ctrl + C`.

## Run the notebook

1. In VS Code open `PassGuard.ipynb` (install the **Jupyter** extension if asked).
2. Click **Select Kernel** (top right) and choose the `venv` Python.
3. Click **Run All**. The notebook must sit in the same folder as the `.py` files.

Or from the terminal: `python -m jupyter nbconvert --to notebook --execute PassGuard.ipynb --output PassGuard_run.ipynb`
(requires `python -m pip install nbconvert`).

## Run the automated tests

```powershell
python -m pytest -v
```

## Demo script (about 5 minutes, fictional passwords)

| Step | Page | Do this | Point to make |
|---|---|---|---|
| 1 | Password Analyzer | Analyze `letmein` | Common password -> score capped, Weak |
| 2 | Password Analyzer | Analyze `Summer2024!` | Meets typical rules but detected as common-word + year pattern |
| 3 | Password Analyzer | Click "Use this as the starting point" | Only results are kept, not the password |
| 4 | Improvement Analytics | Check `Tr7#bQm9$Zw2!vPx` | Score/entropy/length deltas, weaknesses resolved, chart |
| 5 | Policy Simulator | Test `Password1!` with the default rules (or the "Basic" preset), then the "Strict" preset | PASS can still be Weak (compliance is not strength); Strict then rejects it for length |
| 6 | Policy Simulator | Test `purple maple rides bicycles` with the "Length-focused" preset | A good passphrase can fail composition rules |
| 7 | Security Report | Download the PDF and CSV | Neither contains the password |

## Test plan

| # | Case | Expected result | Automated test |
|---|---|---|---|
| 1 | Empty input | Valid result, `is_empty`, score 0, Weak; UI shows an error | `test_empty_input_returns_valid_result` |
| 2 | Very short password | Weak, `LENGTH_VERY_SHORT` | `test_very_short_password_is_weak` |
| 3 | Common password | Exact match, score <= 5 | `test_common_password_detected_and_capped` |
| 4 | Common + substitutions | Variant detected, Weak | `test_common_password_variant_detected` |
| 5 | Sequences / keyboard patterns | Flags raised | `test_sequence_detected`, `test_keyboard_pattern_detected` |
| 6 | Repeated characters / blocks / years | Flags raised | `test_repeated_*`, `test_year_pattern_detected` |
| 7 | Longer fictional password | Very Strong, no weaknesses | `test_longer_fictional_password_scores_high` |
| 8 | Entropy formula | `L x log2(N)` | `test_entropy_formula` |
| 9 | Password satisfying a policy | PASS, all rules satisfied | `test_password_satisfying_policy` |
| 10 | Password failing a policy | FAIL, per-rule status | `test_password_failing_policy_reports_each_rule` |
| 11 | Improvement comparison | Deltas, resolved/remaining/new weaknesses | `test_improvement_comparison`, `test_comparison_tracks_...` |
| 12 | PDF without the password | PDF bytes contain no password | `test_pdf_generation_does_not_contain_password` |
| 13 | Result never holds the password | Not in the dict or CSV row | `test_result_never_contains_the_password` |
| 14 | App with no analysis yet | No page crashes | `test_app_pages_do_not_crash_without_analysis` |

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` (or reportlab, pandas...) | The virtual environment is not active or packages are not installed. Run `.\venv\Scripts\Activate.ps1`, then `python -m pip install -r requirements.txt`. |
| `ModuleNotFoundError: No module named 'password_analyzer'` | You are in the wrong folder. `cd` into `PassGuard` (the folder that contains `app.py`) before running anything. In the notebook, keep it in that same folder. |
| `streamlit` is not recognised | Always use `python -m streamlit run app.py` (not just `streamlit run`). |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. |
| `Port 8501 is already in use` | `python -m streamlit run app.py --server.port 8502` |
| Browser does not open | Open http://localhost:8501 manually. |
| Notebook says "No kernel selected" / import errors | Select the `venv` interpreter as the kernel; run `python -m pip install ipykernel`. |
| `python` not recognised | Reinstall Python from python.org and tick "Add Python to PATH", or try `py` instead of `python`. |
| Charts or app look stale after editing code | In the browser press `R` (rerun) or stop and restart Streamlit. |

## Privacy notes (what is and is not kept)

* The analyzer and improvement pages use forms that **clear the password box after each check**.
* `st.session_state` keeps only analysis dictionaries (numbers, flags, text such as "No digits").
* The PDF filename is `PassGuard_Report_<timestamp>.pdf`; the PDF metadata contains only the title and "PassGuard".
* While you type on the Policy Simulator page, the masked text box value necessarily lives in Streamlit's in-memory widget state
  for that browser session (needed for live re-evaluation). It is never written to disk, logged or exported.
