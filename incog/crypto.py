"""Keyed pseudonyms and per-patient date shifts (HMAC-SHA256 with RAKSHA_SECRET)."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac

from .config import POLICY, SECRET

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32


def _mac(label: bytes, key: str) -> bytes:
    return hmac.new(SECRET, label + b"|" + key.encode("utf-8"), hashlib.sha256).digest()


def pseudonym(patient_key: str) -> str:
    n = int.from_bytes(_mac(b"psn", patient_key)[:5], "big")
    return "PSN-" + "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))


def date_shift_days(patient_key: str) -> int:
    m = int(POLICY.get("date_shift_max_days", 180))
    v = int.from_bytes(_mac(b"shift", patient_key)[:4], "big") % (2 * m) - m
    return v if v != 0 else 1


def shift_date(value: dt.date, patient_key: str) -> dt.date:
    return value + dt.timedelta(days=date_shift_days(patient_key))
