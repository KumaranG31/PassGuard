"""
password_analyzer.py - PassGuard core analysis engine
=====================================================

This module contains ALL the password-evaluation logic. It has no dependency on
Streamlit, so it can be used from the web app (app.py), the notebook
(PassGuard.ipynb) and the automated tests (test_password_analyzer.py).

PRIVACY DESIGN
--------------
* The password is only used as a function argument.
* The returned analysis dictionary NEVER contains the password (or a hash of it).
  It only contains derived, non-sensitive facts (length, entropy, flags, ...).
* Nothing is written to disk, logged, or printed here.

IMPORTANT HONESTY NOTES
-----------------------
* The 0-100 score is a HEURISTIC invented for this project. It is not a
  validated security measurement.
* Entropy here is THEORETICAL: H = L x log2(N). It assumes every character was
  chosen independently and uniformly at random from a character set of size N.
  Human-chosen passwords are NOT random, so real guessability is usually lower.
* Character variety alone does not make a password secure. Length, unpredictability
  and uniqueness (one password per account) matter more.
"""

from __future__ import annotations

import math
import re
import string
from pathlib import Path

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

BASE_DIR = Path(__file__).resolve().parent
COMMON_PASSWORDS_FILE = BASE_DIR / "data" / "common_passwords.txt"

# Used only if data/common_passwords.txt is missing, so the app never crashes.
_FALLBACK_COMMON = frozenset(
    {"123456", "password", "qwerty", "admin", "letmein", "welcome", "iloveyou"}
)

# Assumed size of each character pool (used for the entropy formula).
LOWERCASE_POOL = 26
UPPERCASE_POOL = 26
DIGIT_POOL = 10
SYMBOL_POOL = 33  # 32 ASCII punctuation characters + space (any other character is
#                   also treated as belonging to this "symbol/other" pool)

STRENGTH_LEVELS = ["Weak", "Moderate", "Strong", "Very Strong"]

ENTROPY_NOTE = (
    "Entropy is a THEORETICAL estimate using H = L x log2(N), where L is the password "
    "length and N is the assumed character-set size. It assumes every character is chosen "
    "independently and uniformly at random. Human-created passwords are usually far more "
    "predictable, so real-world guessability can be much lower than this number."
)

SCORE_NOTE = (
    "The score is a heuristic created for this educational project. It is not a validated "
    "security measurement and a higher score does not guarantee real-world security."
)

# Penalty points subtracted from the score for each detected pattern weakness.
PENALTIES = {
    "COMMON_VARIANT": 30,
    "COMMON_SUBSTRING": 20,
    "SEQUENCE": 15,
    "KEYBOARD_PATTERN": 15,
    "REPEATED_CHARS": 15,
    "REPEATED_BLOCK": 15,
    "DATE_PATTERN": 10,
}

# code -> (short description of the weakness, recommendation to fix it)
WEAKNESS_CATALOG = {
    "EMPTY": (
        "Password is empty",
        "Enter a password to analyze.",
    ),
    "LENGTH_VERY_SHORT": (
        "Very short (fewer than 8 characters)",
        "Use at least 12 characters. Length is the most effective way to improve a password.",
    ),
    "LENGTH_BELOW_RECOMMENDED": (
        "Shorter than the commonly recommended 12 characters",
        "Lengthen it to 12-16+ characters, for example a passphrase of several unrelated words.",
    ),
    "NO_UPPERCASE": (
        "No uppercase letters",
        "Mixing in uppercase letters can help, but prefer making the password longer.",
    ),
    "NO_LOWERCASE": (
        "No lowercase letters",
        "Mixing in lowercase letters can help, but prefer making the password longer.",
    ),
    "NO_DIGIT": (
        "No digits",
        "Consider adding digits in unpredictable positions (not just at the end).",
    ),
    "NO_SYMBOL": (
        "No symbols or special characters",
        "Consider adding symbols, or separate random words with symbols.",
    ),
    "COMMON_PASSWORD": (
        "Matches a very common password",
        "Never use a common password. Choose something unique that is not on public lists.",
    ),
    "COMMON_VARIANT": (
        "Looks like a common password with simple changes (e.g. 'a'->'@', digits/symbols added)",
        "Attackers try these substitutions first. Avoid decorating a common word with digits or symbols.",
    ),
    "COMMON_SUBSTRING": (
        "Contains a common password or word",
        "Avoid including common words such as 'password', 'admin' or 'welcome' inside your password.",
    ),
    "SEQUENCE": (
        "Contains a predictable sequence (such as abc, 123 or 321)",
        "Remove ascending/descending runs of letters or digits.",
    ),
    "KEYBOARD_PATTERN": (
        "Contains a keyboard pattern (such as qwer or asdf)",
        "Avoid walking across the keyboard; such patterns are in every cracking dictionary.",
    ),
    "REPEATED_CHARS": (
        "Contains the same character repeated 3 or more times in a row",
        "Avoid runs such as 'aaa' or '111'.",
    ),
    "REPEATED_BLOCK": (
        "Contains a repeated block (such as abab or 123123)",
        "Avoid repeating the same chunk of characters.",
    ),
    "DATE_PATTERN": (
        "Contains a year (1900-2099), which is a very common pattern",
        "Avoid birth years and recent years; they are among the first guesses attackers make.",
    ),
}

# Keyboard rows used to detect "walking" patterns.
_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]

# Common look-alike substitutions ("leetspeak") normalised before dictionary checks.
_LEET_MAP = str.maketrans({"@": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "4": "a"})

# Optional: the zxcvbn guessability estimator. The project works without it.
try:  # pragma: no cover - depends on whether the package is installed
    from zxcvbn import zxcvbn as _zxcvbn
except Exception:  # ImportError or any problem inside the package
    _zxcvbn = None


# --------------------------------------------------------------------------- #
# Common-password list
# --------------------------------------------------------------------------- #

def load_common_passwords(path: Path | str = COMMON_PASSWORDS_FILE) -> frozenset:
    """Load the common-password list (lowercase). Falls back to a tiny built-in set."""
    try:
        with open(path, encoding="utf-8") as handle:
            words = {
                line.strip().lower()
                for line in handle
                if line.strip() and not line.startswith("#")
            }
    except OSError:
        return _FALLBACK_COMMON
    return frozenset(words) if words else _FALLBACK_COMMON


COMMON_PASSWORDS = load_common_passwords()


# --------------------------------------------------------------------------- #
# Character analysis and entropy
# --------------------------------------------------------------------------- #

def character_categories(password: str) -> dict:
    """Return which character classes are present. Shared with policy_simulator.py."""
    return {
        "lowercase": any(c in string.ascii_lowercase for c in password),
        "uppercase": any(c in string.ascii_uppercase for c in password),
        "digit": any(c in string.digits for c in password),
        # anything that is not an ASCII letter or digit counts as a symbol/other
        "symbol": any(c not in string.ascii_letters + string.digits for c in password),
    }


def charset_size(categories: dict) -> int:
    """Assumed character-set size N for the entropy formula."""
    size = 0
    if categories["lowercase"]:
        size += LOWERCASE_POOL
    if categories["uppercase"]:
        size += UPPERCASE_POOL
    if categories["digit"]:
        size += DIGIT_POOL
    if categories["symbol"]:
        size += SYMBOL_POOL
    return size


def calculate_entropy(length: int, pool_size: int) -> float:
    """Theoretical entropy in bits: H = L x log2(N)."""
    if length <= 0 or pool_size <= 1:
        return 0.0
    return length * math.log2(pool_size)


# --------------------------------------------------------------------------- #
# Weakness detectors (each returns a simple bool / label)
# --------------------------------------------------------------------------- #

def _leet_variants(password: str) -> set:
    """Lowercase + undo common substitutions. '1' could be 'i' or 'l', so try both."""
    base = password.lower().translate(_LEET_MAP)
    return {base.replace("1", "i"), base.replace("1", "l")}


def _strip_decoration(text: str) -> str:
    """Remove leading/trailing characters that are not lowercase letters (digits, symbols)."""
    return re.sub(r"^[^a-z]+|[^a-z]+$", "", text)


def detect_common_match(password: str, common: frozenset = COMMON_PASSWORDS):
    """
    Returns "exact", "variant", "substring" or None.

    exact     - the password (ignoring case) is on the common list
    variant   - after undoing substitutions and stripping leading/trailing
                digits/symbols it is on the list (e.g. 'P@ssw0rd!')
    substring - it contains a common alphabetic word of 5+ letters
    """
    if password.lower() in common:
        return "exact"

    variants = _leet_variants(password)

    # Candidate "cores": the password with leading/trailing digits/symbols removed,
    # tried both before and after undoing substitutions (so 'Summer2024!' and
    # 'P@ssw0rd!' are both recognised).
    candidates = set(variants)
    for norm in list(variants):
        candidates.add(_strip_decoration(norm))
    stripped_first = _strip_decoration(password.lower())
    candidates.add(stripped_first)
    candidates.update(_leet_variants(stripped_first))

    for cand in candidates:
        if cand in common and len(cand) >= 4:
            return "variant"
    if any(cand in common for cand in variants):
        return "variant"

    words = [w for w in common if len(w) >= 5 and w.isalpha()]
    for norm in variants:
        if any(word in norm for word in words):
            return "substring"
    return None


def has_sequence(password: str, min_len: int = 3) -> bool:
    """True if there is an ascending/descending run of letters or digits (abc, 321)."""
    text = password.lower()
    run, last_diff = 1, None
    for a, b in zip(text, text[1:]):
        both_alnum = a.isalnum() and b.isalnum() and a.isascii() and b.isascii()
        diff = ord(b) - ord(a)
        if both_alnum and diff in (1, -1):
            run = run + 1 if diff == last_diff else 2
            last_diff = diff
        else:
            run, last_diff = 1, None
        if run >= min_len:
            return True
    return False


def has_keyboard_pattern(password: str, min_len: int = 4) -> bool:
    """True if 4+ neighbouring keys of a keyboard letter row appear in order (qwer, rewq)."""
    text = password.lower()
    for row in _KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for i in range(len(line) - min_len + 1):
                if line[i:i + min_len] in text:
                    return True
    return False


def has_repeated_chars(password: str, min_run: int = 3) -> bool:
    """True if one character repeats min_run or more times in a row (aaa)."""
    return re.search(r"(.)\1{%d,}" % (min_run - 1), password, flags=re.DOTALL) is not None


def has_repeated_block(password: str) -> bool:
    """True if a block of 2+ different characters repeats back-to-back (abab, 123123)."""
    for match in re.finditer(r"(.{2,}?)\1", password, flags=re.DOTALL):
        if len(set(match.group(1))) > 1:
            return True
    return False


def has_date_pattern(password: str) -> bool:
    """True if a 4-digit year from 1900-2099 appears (not part of a longer digit run)."""
    return re.search(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)", password) is not None


# --------------------------------------------------------------------------- #
# Optional cross-check with zxcvbn
# --------------------------------------------------------------------------- #

def _zxcvbn_check(password: str):
    """Return a small dict from zxcvbn, or None if it is not installed / fails."""
    if _zxcvbn is None:
        return None
    try:
        # zxcvbn becomes very slow on long inputs, so only the first 72 chars are used
        result = _zxcvbn(password[:72])
        return {
            "score": int(result["score"]),                     # 0 (worst) .. 4 (best)
            "guesses_log10": round(float(result["guesses_log10"]), 2),
        }
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def _strength_from_score(score: int) -> str:
    if score < 40:
        return STRENGTH_LEVELS[0]
    if score < 60:
        return STRENGTH_LEVELS[1]
    if score < 80:
        return STRENGTH_LEVELS[2]
    return STRENGTH_LEVELS[3]


def _compute_score(length, type_count, entropy, unique_ratio, codes, common_match):
    """
    Heuristic score out of 100.

      Entropy (max 50)   : min(H, 100) / 100 x 50
      Length (max 20)    : min(length, 16) / 16 x 20
      Variety (max 20)   : 5 points per character class present
      Uniqueness (max 10): 10 x (unique characters / length)
      Penalties          : subtracted for patterns (see PENALTIES)

    Then caps are applied so short or predictable passwords cannot score highly.
    Returns (score, breakdown_dict, cap_reason_or_None).
    """
    entropy_pts = min(entropy, 100.0) / 100.0 * 50.0
    length_pts = min(length, 16) / 16.0 * 20.0
    variety_pts = type_count * 5.0
    unique_pts = unique_ratio * 10.0
    penalty_pts = -float(sum(PENALTIES[c] for c in codes if c in PENALTIES))

    breakdown = {
        "Entropy (max 50)": round(entropy_pts, 1),
        "Length (max 20)": round(length_pts, 1),
        "Variety (max 20)": round(variety_pts, 1),
        "Uniqueness (max 10)": round(unique_pts, 1),
        "Pattern penalties": round(penalty_pts, 1),
    }

    raw = entropy_pts + length_pts + variety_pts + unique_pts + penalty_pts
    score = max(0.0, min(100.0, raw))

    # Caps (the lowest applicable cap wins)
    caps = []
    if common_match == "exact":
        caps.append((5, "Score capped at 5 because the password is on the common-password list."))
    if common_match == "variant":
        caps.append((39, "Score capped at 39 because the password is a simple variant of a common password."))
    if length < 8:
        caps.append((39, "Score capped at 39 because the password has fewer than 8 characters."))
    elif length < 12:
        caps.append((59, "Score capped at 59 because the password has fewer than 12 characters."))
    elif length < 14:
        caps.append((79, "Score capped at 79 because the password has fewer than 14 characters."))
    pattern_flags = {"COMMON_SUBSTRING", "SEQUENCE", "KEYBOARD_PATTERN",
                     "REPEATED_CHARS", "REPEATED_BLOCK", "DATE_PATTERN"}
    if pattern_flags.intersection(codes):
        caps.append((79, "Score capped at 79 because predictable patterns were detected."))

    cap_reason = None
    if caps:
        cap_value, reason = min(caps, key=lambda item: item[0])
        if score > cap_value:
            score, cap_reason = float(cap_value), reason

    return int(round(score)), breakdown, cap_reason


# --------------------------------------------------------------------------- #
# Main public function
# --------------------------------------------------------------------------- #

def analyze_password(password: str, common_passwords=None) -> dict:
    """
    Analyse a password and return a dictionary of NON-SENSITIVE results.

    The password itself is never included in the returned dictionary.
    Raises TypeError if `password` is not a string. An empty string returns a valid
    result with is_empty=True, score 0 and strength "Weak".
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    common = COMMON_PASSWORDS if common_passwords is None else frozenset(
        p.strip().lower() for p in common_passwords
    )

    length = len(password)
    categories = character_categories(password)
    type_count = sum(categories.values())
    pool = charset_size(categories)
    entropy = calculate_entropy(length, pool)
    unique_count = len(set(password))
    unique_ratio = (unique_count / length) if length else 0.0

    # ---- detect weaknesses ------------------------------------------------ #
    codes: list[str] = []
    common_match = None
    flags = {
        "has_sequence": False,
        "has_keyboard_pattern": False,
        "has_repeated_chars": False,
        "has_repeated_block": False,
        "has_date_pattern": False,
    }

    if length == 0:
        codes.append("EMPTY")
    else:
        if length < 8:
            codes.append("LENGTH_VERY_SHORT")
        elif length < 12:
            codes.append("LENGTH_BELOW_RECOMMENDED")

        if not categories["uppercase"]:
            codes.append("NO_UPPERCASE")
        if not categories["lowercase"]:
            codes.append("NO_LOWERCASE")
        if not categories["digit"]:
            codes.append("NO_DIGIT")
        if not categories["symbol"]:
            codes.append("NO_SYMBOL")

        common_match = detect_common_match(password, common)
        if common_match == "exact":
            codes.append("COMMON_PASSWORD")
        elif common_match == "variant":
            codes.append("COMMON_VARIANT")
        elif common_match == "substring":
            codes.append("COMMON_SUBSTRING")

        flags["has_sequence"] = has_sequence(password)
        flags["has_keyboard_pattern"] = has_keyboard_pattern(password)
        flags["has_repeated_chars"] = has_repeated_chars(password)
        flags["has_repeated_block"] = has_repeated_block(password)
        flags["has_date_pattern"] = has_date_pattern(password)

        if flags["has_sequence"]:
            codes.append("SEQUENCE")
        if flags["has_keyboard_pattern"]:
            codes.append("KEYBOARD_PATTERN")
        if flags["has_repeated_chars"]:
            codes.append("REPEATED_CHARS")
        if flags["has_repeated_block"]:
            codes.append("REPEATED_BLOCK")
        if flags["has_date_pattern"]:
            codes.append("DATE_PATTERN")

    # ---- score and strength ---------------------------------------------- #
    if length == 0:
        score, breakdown, cap_reason = 0, {"Entropy (max 50)": 0.0, "Length (max 20)": 0.0,
                                           "Variety (max 20)": 0.0, "Uniqueness (max 10)": 0.0,
                                           "Pattern penalties": 0.0}, None
    else:
        score, breakdown, cap_reason = _compute_score(
            length, type_count, entropy, unique_ratio, codes, common_match
        )
    strength = _strength_from_score(score)

    # ---- human-readable weaknesses and recommendations -------------------- #
    weaknesses = [WEAKNESS_CATALOG[c][0] for c in codes]
    recommendations = [WEAKNESS_CATALOG[c][1] for c in codes]
    if length > 0:
        recommendations.append(
            "Use a unique password for every account, store it in a password manager, "
            "and enable multi-factor authentication where available."
        )

    return {
        "is_empty": length == 0,
        "length": length,
        "has_lowercase": categories["lowercase"],
        "has_uppercase": categories["uppercase"],
        "has_digit": categories["digit"],
        "has_symbol": categories["symbol"],
        "character_types": type_count,          # 0-4: how many classes are present
        "charset_size": pool,
        "unique_characters": unique_count,
        "unique_ratio": round(unique_ratio, 3),
        "entropy_bits": round(entropy, 2),
        "common_match": common_match,
        **flags,
        "score": score,
        "strength": strength,
        "score_breakdown": breakdown,
        "score_cap_reason": cap_reason,
        "weakness_codes": codes,
        "weaknesses": weaknesses,
        "recommendations": recommendations,
        "zxcvbn": _zxcvbn_check(password) if length else None,
    }


# --------------------------------------------------------------------------- #
# Comparison and export helpers
# --------------------------------------------------------------------------- #

def compare_assessments(initial: dict, latest: dict) -> dict:
    """
    Compare two analysis dictionaries (produced by analyze_password).
    Works only with derived results - the passwords are not needed or stored.
    """
    init_codes = list(initial["weakness_codes"])
    new_codes = list(latest["weakness_codes"])

    resolved = [c for c in init_codes if c not in new_codes]
    remaining = [c for c in init_codes if c in new_codes]
    introduced = [c for c in new_codes if c not in init_codes]

    def titles(codes):
        return [WEAKNESS_CATALOG[c][0] for c in codes]

    score_change = latest["score"] - initial["score"]
    if score_change > 0:
        summary = (f"The heuristic score increased by {score_change} points "
                   f"({initial['strength']} -> {latest['strength']}).")
    elif score_change < 0:
        summary = (f"The heuristic score decreased by {abs(score_change)} points "
                   f"({initial['strength']} -> {latest['strength']}).")
    else:
        summary = "The heuristic score did not change."
    summary += (" A higher heuristic score does not guarantee better real-world security; "
                "the revised password must also be unique and unpredictable.")

    return {
        "initial_strength": initial["strength"],
        "latest_strength": latest["strength"],
        "initial_score": initial["score"],
        "latest_score": latest["score"],
        "score_change": score_change,
        "initial_entropy": initial["entropy_bits"],
        "latest_entropy": latest["entropy_bits"],
        "entropy_change": round(latest["entropy_bits"] - initial["entropy_bits"], 2),
        "initial_length": initial["length"],
        "latest_length": latest["length"],
        "length_change": latest["length"] - initial["length"],
        "initial_character_types": initial["character_types"],
        "latest_character_types": latest["character_types"],
        "character_types_change": latest["character_types"] - initial["character_types"],
        "initial_weaknesses": titles(init_codes),
        "resolved_weaknesses": titles(resolved),
        "remaining_weaknesses": titles(remaining),
        "new_weaknesses": titles(introduced),
        "summary": summary,
    }


def result_to_flat_row(analysis: dict) -> dict:
    """Flatten an analysis into one non-sensitive row (used for CSV export / DataFrames)."""
    zx = analysis.get("zxcvbn")
    return {
        "strength": analysis["strength"],
        "heuristic_score": analysis["score"],
        "length": analysis["length"],
        "character_types": analysis["character_types"],
        "has_lowercase": analysis["has_lowercase"],
        "has_uppercase": analysis["has_uppercase"],
        "has_digit": analysis["has_digit"],
        "has_symbol": analysis["has_symbol"],
        "charset_size": analysis["charset_size"],
        "entropy_bits": analysis["entropy_bits"],
        "common_match": analysis["common_match"] or "none",
        "has_sequence": analysis["has_sequence"],
        "has_keyboard_pattern": analysis["has_keyboard_pattern"],
        "has_repeated_chars": analysis["has_repeated_chars"],
        "has_repeated_block": analysis["has_repeated_block"],
        "has_date_pattern": analysis["has_date_pattern"],
        "weakness_count": len(analysis["weakness_codes"]),
        "weaknesses": "; ".join(analysis["weaknesses"]),
        "zxcvbn_score_0_to_4": zx["score"] if zx else "n/a",
    }
