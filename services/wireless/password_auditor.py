"""
Password Security & Shannon Entropy Auditor.
"""

import math
import re
from typing import Dict, Any, List


def calculate_entropy(password: str) -> float:
    """Calculates Shannon entropy in bits for a given string."""
    if not password:
        return 0.0
    entropy = 0.0
    length = len(password)
    for char in set(password):
        p_x = float(password.count(char)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return round(entropy * length, 2)


def audit_password_strength(password: str) -> Dict[str, Any]:
    """
    Evaluates password complexity, entropy, patterns, and vulnerability.
    """
    if not password or password in ("Not Found / Open", ""):
        return {
            "score": 0,
            "rating": "NO_PASSWORD",
            "entropy": 0.0,
            "feedback": ["No password configured or network is completely open!"]
        }

    score = 0
    feedback: List[str] = []

    # Length check
    if len(password) < 8:
        feedback.append("Password is under 8 characters (Fails WPA/WPA2 minimum).")
    elif len(password) >= 14:
        score += 3
        feedback.append("Strong length (>= 14 chars).")
    elif len(password) >= 10:
        score += 2
    else:
        score += 1

    # Complexity checks
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    char_types = sum([has_lower, has_upper, has_digit, has_symbol])
    score += char_types

    # Common pattern penalties
    common_patterns = [
        "123456", "password", "admin", "qwerty", "wifi", "internet",
        "vodafone", "we123456", "etisalat", "orange"
    ]
    for pattern in common_patterns:
        if pattern in password.lower():
            score = max(0, score - 3)
            feedback.append(f"Contains common dictionary pattern: '{pattern}'")
            break

    entropy = calculate_entropy(password)

    if score >= 6 and entropy >= 60:
        rating = "VERY STRONG 🛡️"
    elif score >= 4 and entropy >= 45:
        rating = "STRONG ✅"
    elif score >= 3:
        rating = "MODERATE ⚠️"
    else:
        rating = "WEAK ❌"

    return {
        "score": min(score, 7),
        "rating": rating,
        "entropy": entropy,
        "length": len(password),
        "feedback": feedback
    }
