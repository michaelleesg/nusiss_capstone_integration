# ner/regex_patterns.py
# Wrapper that loads the deep regexes and provides one unified API (find_all).
# ner/regex_patterns.py
# Wrapper that loads the deep regexes and provides one unified API (find_all).

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from typing import List, Tuple

# Locate and import the deep file WITHOUT importing from this package (avoid cycles)
ROOT = Path(__file__).resolve().parent.parent
DEEP = (
    ROOT / "capstone_report/individual/cybersage-ner-evidence-with-artifacts/ner/regex_patterns.py"
)
if not DEEP.exists():
    raise FileNotFoundError(f"Expected regex_patterns at {DEEP}")

spec = importlib.util.spec_from_file_location("deep_regex_patterns", DEEP)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

# --- Core patterns from deep (must exist there) ---
CVE_PATTERN = getattr(mod, "CVE_PATTERN")
DOMAIN_PATTERN = getattr(mod, "DOMAIN_PATTERN")

# Optional IP (fallback to a safe IPv4 regex if deep doesn’t define it)
IP_PATTERN = getattr(
    mod,
    "IP_PATTERN",
    re.compile(
        r"(?:\bIP[: ]+)?\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b"
    ),
)

# Lists: fallback to sensible defaults if deep doesn’t define them
MALWARE_LIST = getattr(
    mod, "MALWARE_LIST", ["Emotet", "Zeus", "TrickBot", "QakBot", "Dridex", "Ryuk", "LockBit"]
)
THREAT_ACTOR_LIST = getattr(
    mod, "THREAT_ACTOR_LIST", ["APT28", "APT29", "Lazarus", "Sandworm", "FIN7"]
)

# Patterns: if deep didn’t define them, compile from the lists
MALWARE_PATTERN = getattr(
    mod,
    "MALWARE_PATTERN",
    re.compile(r"\b(" + "|".join(map(re.escape, MALWARE_LIST)) + r")\b", re.IGNORECASE),
)
THREAT_ACTOR_PATTERN = getattr(
    mod,
    "THREAT_ACTOR_PATTERN",
    re.compile(r"\b(" + "|".join(map(re.escape, THREAT_ACTOR_LIST)) + r")\b", re.IGNORECASE),
)

# Public labels used across the project
LABELS = getattr(mod, "LABELS", ("CVE", "IP", "DOMAIN", "MALWARE", "THREAT_ACTOR"))

# Trim helpers to make spans match gold more reliably
_TRIM_LEFT = "([{'\""
_TRIM_RIGHT = ")]}',.;:"


def _emit(label: str, m: re.Match) -> Tuple[int, int, str]:
    # All patterns must capture the entity in group 1
    s, e = m.span(1)
    return (s, e, label)


def _trim(text: str, s: int, e: int) -> Tuple[int, int]:
    while s < e and text[s] in _TRIM_LEFT:
        s += 1
    while e > s and text[e - 1] in _TRIM_RIGHT:
        e -= 1
    return s, e


def _dedupe_keep_longest(spans: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
    by_label = {}
    for s, e, lbl in spans:
        by_label.setdefault(lbl, []).append((s, e))
    final: List[Tuple[int, int, str]] = []
    for lbl, lst in by_label.items():
        lst.sort(key=lambda t: (t[0], -(t[1] - t[0])))
        kept: List[Tuple[int, int]] = []
        for s, e in lst:
            replace_idx = None
            for i, (ks, ke) in enumerate(kept):
                if not (e <= ks or s >= ke):
                    # Overlap -> keep the longer span
                    if (e - s) > (ke - ks):
                        replace_idx = i
                    break
            if replace_idx is not None:
                kept[replace_idx] = (s, e)
            elif not any(not (e <= ks or s >= ke) for ks, ke in kept):
                kept.append((s, e))
        for s, e in kept:
            final.append((s, e, lbl))
    final.sort(key=lambda t: (t[0], t[1], t[2]))
    return final


def find_all(text: str) -> List[Tuple[int, int, str]]:
    """
    Return a list of (start, end, label) spans for:
      - CVE, IP, DOMAIN (regex)
      - MALWARE, THREAT_ACTOR (dictionary-backed regex)
    Post-process: trim punctuation and dedupe overlaps (keep longest per label).
    """
    spans: List[Tuple[int, int, str]] = []
    for m in CVE_PATTERN.finditer(text):
        spans.append(_emit("CVE", m))
    for m in IP_PATTERN.finditer(text):
        spans.append(_emit("IP", m))
    for m in DOMAIN_PATTERN.finditer(text):
        spans.append(_emit("DOMAIN", m))
    for m in MALWARE_PATTERN.finditer(text):
        spans.append(_emit("MALWARE", m))
    for m in THREAT_ACTOR_PATTERN.finditer(text):
        spans.append(_emit("THREAT_ACTOR", m))

    trimmed = []
    for s, e, lbl in spans:
        s2, e2 = _trim(text, s, e)
        if e2 > s2:
            trimmed.append((s2, e2, lbl))

    return _dedupe_keep_longest(trimmed)


__all__ = [
    "CVE_PATTERN",
    "IP_PATTERN",
    "DOMAIN_PATTERN",
    "MALWARE_PATTERN",
    "THREAT_ACTOR_PATTERN",
    "MALWARE_LIST",
    "THREAT_ACTOR_LIST",
    "LABELS",
    "find_all",
]
