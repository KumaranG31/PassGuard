# PassGuard - Project Documentation

## 1. Project description (short)

PassGuard is a Python and Streamlit application that audits a user-entered *fictional* password. It detects weaknesses
(short length, missing character types, common passwords, sequences, repeated characters), estimates theoretical entropy
with `H = L x log2(N)`, assigns a heuristic strength score, and recommends improvements. It also compares an initial and a
revised password, simulates configurable password policies, and exports a PDF report. The password itself is never stored,
logged or exported.

## 2. Planned functionalities

1. Password length and character-class analysis (lowercase, uppercase, digits, symbols).
2. Common-password detection (exact match, look-alike substitutions, contained common words).
3. Pattern detection: sequences, keyboard patterns, repeated characters/blocks, years.
4. Theoretical entropy estimate and a heuristic 0-100 score with Weak / Moderate / Strong / Very Strong labels.
5. Specific weaknesses and actionable recommendations.
6. Improvement analytics: initial vs revised assessment (score, entropy, length, character types, weaknesses resolved / remaining / new) with a chart.
7. Password policy simulator with per-rule PASS/FAIL and an explicit "policy compliance vs strength" explanation.
8. Downloadable PDF security audit report and a non-sensitive CSV export.
9. Optional independent cross-check using the `zxcvbn` guessability estimator.
10. Automated tests and an executed Jupyter notebook documenting the work.

## 3. Problem statement

Users often choose short or predictable passwords and receive little explanation of why they are weak. Organisations enforce
composition rules that predictable passwords (e.g. `Password1!`) still satisfy, so compliance is mistaken for security.
There is a need for a simple, privacy-preserving tool that explains weaknesses and improvement - without collecting the passwords.

## 4. Objectives

* Analyse passwords for length, diversity, common matches and predictable patterns.
* Estimate theoretical entropy and explain its assumptions honestly.
* Provide a transparent heuristic score and recommendations.
* Show measurable (but cautiously interpreted) improvement between two passwords.
* Demonstrate the difference between policy compliance and strength.
* Generate a privacy-preserving PDF report.
* Verify the implementation with automated tests.

## 5. Methodology

1. **Requirement analysis** - four features, strict privacy rules (no storage, no login, fictional data only).
2. **Design** - separate the logic from the UI: `password_analyzer.py` (analysis), `policy_simulator.py` (rules),
   `report_generator.py` (PDF) and `app.py` (Streamlit). The logic modules never import Streamlit, so they are testable and reusable in the notebook.
3. **Implementation** - rule-based detectors (regular expressions, string comparison against a list) feeding a documented heuristic score.
4. **Privacy engineering** - analysis returns a dictionary of derived facts only; forms clear the input after submission; only dictionaries are kept in `st.session_state`.
5. **Verification** - 29 pytest tests (including Streamlit `AppTest` smoke tests), an executed notebook with fictional test cases and charts.

### Module interaction

```
app.py ──► password_analyzer.analyze_password(pw) ──► result dict (no password)
   │                                 │
   │                                 ├──► compare_assessments(initial, latest)
   │                                 └──► result_to_flat_row(result)  (CSV)
   ├──► policy_simulator.evaluate_policy(pw, PasswordPolicy)  ──► rule results
   │         └── uses password_analyzer.character_categories()
   └──► report_generator.generate_pdf_report(result, policy_result, comparison) ──► PDF bytes
```

### How the heuristic score works

`score = entropy points (<=50) + length (<=20) + variety (<=20) + uniqueness (<=10) - pattern penalties`, then **caps**:
exact common password -> max 5; variant of a common password -> max 39; fewer than 8 characters -> max 39; fewer than 12 -> max 59;
fewer than 14 -> max 79 (never "Very Strong"); any predictable pattern -> max 79. Labels: <40 Weak, 40-59 Moderate, 60-79 Strong, >=80 Very Strong.
The weights are design choices, not empirically validated.

## 6. Role of each library

| Library | Role |
|---|---|
| Python (`math`, `re`, `string`, `dataclasses`, `pathlib`) | Entropy maths, regex pattern detection, character classes, `PasswordPolicy` dataclass, file paths |
| Streamlit | Web UI, sidebar navigation, forms, metrics, downloads, `session_state` |
| Pandas | Flat result rows, DataFrames in the notebook, CSV export |
| NumPy | Numeric helpers in the notebook (log2 check, bar positions) |
| Matplotlib | Score breakdown chart, initial-vs-latest comparison chart, notebook visualisations |
| ReportLab | Builds the PDF report in memory (Platypus tables and paragraphs) |
| Jupyter / ipykernel | Executable documentation (`PassGuard.ipynb`) |
| pytest | Automated tests |
| zxcvbn (optional) | Independent guessability estimator used as a cross-check |

SQLite is **not** used because there is no data that needs persisting. No machine-learning model is used.

## 7. Software and hardware requirements

**Software:** Windows 10/11, Python 3.10+ (developed and tested on 3.12), VS Code with the Python and Jupyter extensions,
a modern web browser, and the packages in `requirements.txt`.
**Hardware:** any modern laptop (minimum 4 GB RAM, ~500 MB free disk). No GPU or internet is needed after installation.

## 8. Expected results

* Common, short or patterned passwords are classified Weak with specific explanations.
* Long, unpredictable passwords and passphrases are classified Strong or Very Strong.
* Improvement analytics shows score/entropy/length changes and which weaknesses disappeared, remained or appeared.
* The policy simulator shows a password can PASS a policy and still be Weak, and a good passphrase can FAIL a rigid policy.
* The PDF and CSV contain no password.

## 9. Limitations

* The common-password list is a ~120-entry educational list, not a breach database; it cannot tell whether a password was leaked.
* The score is a hand-designed heuristic; weights and thresholds are not validated.
* Entropy assumes independent, uniformly random characters; human passwords are less random, so the number can overstate strength.
* No dictionary-word segmentation: some word-based passwords (e.g. two words plus a number) can be over-rated; the zxcvbn cross-check helps but is not perfect.
* While typing, the masked text box value exists in the Streamlit session's memory (unavoidable for live checking); it is not persisted.
* Not a professional security audit, and not for real credentials.

## 10. Future enhancements

* Larger public password list, optional privacy-preserving (k-anonymity) breach check.
* Word/name segmentation and leetspeak-aware dictionary matching.
* Secure password/passphrase generator.
* Evaluate alternative scoring schemes against a labelled dataset (this would be the point at which ML could be justified).
* Multi-language UI and accessibility improvements.

---

## 11. Likely viva questions and concise answers

**1. What does PassGuard do?**
It analyses a fictional password, lists weaknesses, estimates theoretical entropy, gives a heuristic score and recommendations, compares two passwords, simulates policies and exports a PDF - without storing the password.

**2. What is entropy and what formula do you use?**
Entropy measures unpredictability in bits. I use `H = L x log2(N)`, with L = length and N = assumed character-set size (26 lowercase + 26 uppercase + 10 digits + 33 symbols for the classes present).

**3. What assumptions does that formula make?**
That each character is chosen independently and uniformly at random. Humans do not do that, so for human-made passwords the real guessability is usually much lower than `H`.

**4. Why is `Summer2024!` flagged although it has a high entropy value?**
Because it is a common word plus a year plus a symbol - a very common pattern attackers try early. PassGuard detects the common-word core and caps the score. This shows entropy alone is misleading.

**5. Is your score scientifically validated?**
No. It is a transparent heuristic I designed (entropy, length, variety, uniqueness, penalties, caps). It is labelled as a heuristic everywhere and does not guarantee security.

**6. How do you detect sequences like `abc` or `321`?**
I lowercase the password and scan neighbouring ASCII alphanumeric characters; three or more with a constant difference of +1 or -1 in a row count as a sequence.

**7. How do you detect keyboard patterns?**
I check whether any 4 consecutive keys of the rows `qwertyuiop`, `asdfghjkl`, `zxcvbnm` (forwards or backwards) appear in the password.

**8. How do you detect `P@ssw0rd!` as a common password?**
I lowercase it, undo common substitutions (`@`->a, `0`->o, `3`->e, `$`->s, `5`->s, `7`->t, `4`->a, `1`->i/l), strip leading/trailing digits and symbols, and compare against the common list.

**9. How do you make sure the password is not stored?**
The analyzer returns only derived values; forms clear the box after submission; `st.session_state` keeps only result dictionaries; there is no database, file write or logging; tests assert the password is absent from the result, the CSV row and the PDF bytes.

**10. Why did you not use SQLite?**
There is nothing that must persist. Avoiding a database removes a risk of storing sensitive data and keeps the project simple.

**11. Is there machine learning in the project?**
No. It is rule-based. ML would only make sense with a labelled dataset and a proper evaluation, which is listed as future work.

**12. What is the difference between policy compliance and password strength?**
Compliance means satisfying fixed rules (length, character types). Strength is about unpredictability. `Password1!` complies with many policies but is Weak; a long lowercase passphrase can fail the rules but be strong.

**13. Why do you cap the score for short passwords?**
Length is the most important factor. Without caps, an 8-character random password with all character types could score too high compared with recommendations of 12+ characters.

**14. What does `zxcvbn` add?**
It is an independent, widely used guessability estimator that models dictionaries, patterns and keyboard walks. PassGuard shows its 0-4 score as a cross-check. It is optional; the app works without it.

**15. What are the main limitations?**
Small common-password list, unvalidated heuristic weights, entropy assumptions, no breach check, and over-rating of some word-based passwords.

**16. How does Improvement Analytics work without storing passwords?**
After each check I keep only the result dictionary in the session. `compare_assessments()` compares the dictionaries (scores, entropy, weakness codes), so the passwords are not needed.

**17. Can a higher score mean a safer password?**
Not necessarily. A higher heuristic score only means fewer detected weaknesses by my rules. The password also has to be unique per account, not leaked, and protected with MFA.

**18. How is the PDF generated?**
ReportLab's Platypus API builds paragraphs and tables in an in-memory buffer from the result dictionaries; the bytes are passed to a Streamlit download button. The filename contains only a timestamp.

**19. How did you test the project?**
29 pytest tests: empty/short/common passwords, patterns, entropy, policy pass/fail, comparison, PDF privacy, and Streamlit `AppTest` smoke tests for all pages with no analysis. The notebook was also executed top to bottom.

**20. What would you improve first?**
A larger password list with a privacy-preserving breach check and word segmentation, then evaluate the scoring against a labelled dataset.
