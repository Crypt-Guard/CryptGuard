#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeyGuard Password Generator core.

Implements a cryptographically secure password generator with quality
checks and entropy calculation. Designed to be UI-agnostic.
"""
from __future__ import annotations

import math
import secrets
import string
from typing import Dict

# ---- Defaults / knobs (kept small & isolated) --------------------------------
ENTROPY_CACHE_MAX = 100  # fallback; if project Config exposes ENTROPY_CACHE_SIZE we'll use it
MIN_TOTAL_BITS = 50.0    # warn users when entropy is below this

# Character sets available to the UI
CHARSETS: Dict[str, str] = {
    "numbers": string.digits,                                    # 10 chars
    "letters": string.ascii_letters,                             # 52 chars
    "alphanumeric": string.ascii_letters + string.digits,        # 62 chars
    "full": string.ascii_letters + string.digits + string.punctuation,  # 94 chars
}

# Mapping for radio-options -> key in CHARSETS
OPT_TO_KEY = {
    1: "numbers",
    2: "letters",
    3: "alphanumeric",
    4: "full",
}


class PasswordGenerator:
    """Stateless, secure password generator with a tiny entropy cache."""

    _entropy_cache: Dict[tuple[int, int], float] = {}

    @staticmethod
    def generate(length: int, charset: str) -> str:
        """Generate a password using `secrets` and reject weak patterns."""
        if length < 1:
            raise ValueError("Comprimento deve ser pelo menos 1")
        if not charset:
            raise ValueError("Conjunto de caracteres vazio")

        # Normalize charset (remove duplicates, keep deterministic order)
        charset = ''.join(sorted(set(charset)))

        while True:
            pwd = ''.join(secrets.choice(charset) for _ in range(length))
            if PasswordGenerator._check_quality(pwd, charset):
                return pwd

    # ----- Quality gates ------------------------------------------------------
    @staticmethod
    def _check_quality(password: str, charset: str) -> bool:
        """(Heuristics) Reject very common/obvious patterns and enforce diversity."""
        if PasswordGenerator._has_patterns(password):
            return False

        if len(password) >= 8:
            char_types = {
                'lower': string.ascii_lowercase,
                'upper': string.ascii_uppercase,
                'digit': string.digits,
                'special': string.punctuation,
            }
            present_types = []
            for _, type_chars in char_types.items():
                if any(c in type_chars for c in charset):        # available in charset
                    if any(c in type_chars for c in password):   # actually present
                        present_types.append(type_chars)

            available_types = sum(1 for _, chars in char_types.items()
                                  if any(c in chars for c in charset))
            if available_types >= 2 and len(present_types) < 2:
                return False

        return True

    @staticmethod
    def _has_patterns(password: str) -> bool:
        """Detects keyboard sequences, triples, and monotonic sequences."""
        pwd_lower = password.lower()
        # Keyboard sequences
        sequences = [
            "qwerty", "asdfgh", "zxcvbn", "123456", "654321",
            "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
        for seq in sequences:
            if seq in pwd_lower or seq[::-1] in pwd_lower:
                return True

        # Triples like aaa, 111, !!!
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True

        # Numeric / alphabetic monotonic sequences (length-3 check)
        for i in range(len(password) - 2):
            chars = password[i:i+3]
            if chars.isdigit():
                nums = [int(c) for c in chars]
                if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                    return True
                if nums[1] == nums[0] - 1 and nums[2] == nums[1] - 1:
                    return True
            if chars.isalpha():
                ords = [ord(c.lower()) for c in chars]
                if ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1:
                    return True
                if ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1:
                    return True
        return False

    # ----- Entropy ------------------------------------------------------------
    @staticmethod
    def calculate_entropy(password: str, charset: str) -> float:
        """E = L * log2(N), cached by (len(password), len(set(charset)))."""
        if not password or not charset:
            return 0.0
        cache_key = (len(password), len(set(charset)))
        if cache_key in PasswordGenerator._entropy_cache:
            return PasswordGenerator._entropy_cache[cache_key]

        charset_size = len(set(charset))
        entropy = len(password) * math.log2(charset_size)

        # Cache management (avoid unbounded growth)
        try:
            from ..config import Config  # type: ignore
            max_entries = getattr(Config, "ENTROPY_CACHE_SIZE", ENTROPY_CACHE_MAX)
        except Exception:
            max_entries = ENTROPY_CACHE_MAX
        if len(PasswordGenerator._entropy_cache) > max_entries:
            PasswordGenerator._entropy_cache.clear()
        PasswordGenerator._entropy_cache[cache_key] = entropy
        return entropy

