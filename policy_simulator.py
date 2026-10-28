"""
policy_simulator.py - PassGuard password-policy simulator
=========================================================

Checks a password against a configurable policy (minimum length, uppercase,
lowercase, digit, special character).

KEY IDEA FOR THE VIVA
---------------------
POLICY COMPLIANCE is not the same as PASSWORD STRENGTH.
"Password1!" satisfies many typical policies, yet it is extremely predictable.
That is why this module also provides `policy_vs_strength()`, which explains the
difference using the analysis produced by password_analyzer.py.

PRIVACY: the evaluation result contains only rule names, PASS/FAIL flags and the
password length. The password itself is never stored in the result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from password_analyzer import character_categories

MIN_ALLOWED_LENGTH = 1
MAX_ALLOWED_LENGTH = 128


@dataclass(frozen=True)
class PasswordPolicy:
    """A set of password requirements."""

    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True

    def __post_init__(self):
        if not isinstance(self.min_length, int) or isinstance(self.min_length, bool):
            raise ValueError("min_length must be an integer")
        if not MIN_ALLOWED_LENGTH <= self.min_length <= MAX_ALLOWED_LENGTH:
            raise ValueError(
                f"min_length must be between {MIN_ALLOWED_LENGTH} and {MAX_ALLOWED_LENGTH}"
            )

    def to_dict(self) -> dict:
        return asdict(self)


# Ready-made policies for quick demonstrations.
PRESET_POLICIES = {
    "Basic (8 chars, upper + lower + digit)": PasswordPolicy(8, True, True, True, False),
    "Strict (12 chars, all character types)": PasswordPolicy(12, True, True, True, True),
    "Length-focused (16 chars, no composition rules)": PasswordPolicy(16, False, False, False, False),
}


def evaluate_policy(password: str, policy: PasswordPolicy) -> dict:
    """
    Check `password` against `policy`.

    Returns:
        {
          "passed": bool,                 # overall PASS / FAIL
          "passed_rules": int,
          "total_rules": int,
          "rules": [ {"rule", "requirement", "satisfied", "status", "detail"}, ... ],
          "policy": dict                  # the policy that was used
        }
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not isinstance(policy, PasswordPolicy):
        raise TypeError("policy must be a PasswordPolicy")

    categories = character_categories(password)
    rules = []

    def add_rule(name, requirement, satisfied, detail):
        rules.append({
            "rule": name,
            "requirement": requirement,
            "satisfied": bool(satisfied),
            "status": "PASS" if satisfied else "FAIL",
            "detail": detail,
        })

    # The length rule is always active.
    add_rule(
        "Minimum length",
        f"At least {policy.min_length} characters",
        len(password) >= policy.min_length,
        f"Current length: {len(password)}",
    )
    if policy.require_uppercase:
        add_rule("Uppercase letter", "At least one A-Z", categories["uppercase"],
                 "Found" if categories["uppercase"] else "None found")
    if policy.require_lowercase:
        add_rule("Lowercase letter", "At least one a-z", categories["lowercase"],
                 "Found" if categories["lowercase"] else "None found")
    if policy.require_digit:
        add_rule("Digit", "At least one 0-9", categories["digit"],
                 "Found" if categories["digit"] else "None found")
    if policy.require_special:
        add_rule("Special character", "At least one non-alphanumeric character",
                 categories["symbol"], "Found" if categories["symbol"] else "None found")

    passed_rules = sum(1 for r in rules if r["satisfied"])
    return {
        "passed": passed_rules == len(rules),
        "passed_rules": passed_rules,
        "total_rules": len(rules),
        "rules": rules,
        "policy": policy.to_dict(),
    }


def policy_vs_strength(policy_result: dict, analysis: dict) -> dict:
    """
    Explain how policy compliance and password strength relate.
    Returns {"level": "success" | "info" | "warning" | "error", "message": str}.
    """
    passed = policy_result["passed"]
    strength = analysis["strength"]
    strong_enough = strength in ("Strong", "Very Strong")
    has_patterns = bool(analysis["weakness_codes"]) and any(
        code in analysis["weakness_codes"]
        for code in ("COMMON_PASSWORD", "COMMON_VARIANT", "COMMON_SUBSTRING", "SEQUENCE",
                     "KEYBOARD_PATTERN", "REPEATED_CHARS", "REPEATED_BLOCK", "DATE_PATTERN")
    )

    if passed and not strong_enough:
        return {
            "level": "warning",
            "message": (f"The password COMPLIES with the policy but is rated '{strength}'. "
                        "Meeting composition rules does not make a password unpredictable."),
        }
    if passed and has_patterns:
        return {
            "level": "warning",
            "message": ("The password complies with the policy and scores well, but predictable "
                        "patterns were detected. Compliance is not a guarantee of security."),
        }
    if passed:
        return {
            "level": "success",
            "message": (f"The password complies with the policy and is rated '{strength}' by the "
                        "heuristic. Compliance and strength are still separate questions."),
        }
    if strong_enough:
        return {
            "level": "info",
            "message": (f"The password is rated '{strength}' but does NOT meet this policy. "
                        "Policies are rigid rules; they can reject good passwords (e.g. a long "
                        "passphrase without digits)."),
        }
    return {
        "level": "error",
        "message": f"The password fails the policy and is rated '{strength}'.",
    }
