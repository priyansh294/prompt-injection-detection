"""
Rule-Based Detection Engine Module
Implements FR-03 (Rule-Based Detection) and Module 3 per SRS v1.0:
- Detects the 8 core attack categories:
  1. Instruction Override
  2. Prompt Extraction
  3. Role Manipulation
  4. Restriction Bypass
  5. Data Exfiltration
  6. Tool Manipulation
  7. Context Manipulation
  8. Instruction Injection
- Context-aware analysis to reduce false positives on educational and cybersecurity discussions.
- Calculates rule-based risk score (0-100) and structured indicators.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

from config.settings import DEFAULT_RULES_PATH, ATTACK_CATEGORIES


# Contextual cues indicating educational, research, or audit discussion
BENIGN_CONTEXT_PATTERNS = [
    re.compile(r'\b(why\s+do\s+attackers|how\s+do\s+attackers|studied\s+how|analyz(e|ed|ing)|investigat(e|ed|ing))\b', re.IGNORECASE),
    re.compile(r'\b(for\s+example|example\s+of|such\s+as|demonstrat(e|ed|ing)|lecture|tutorial)\b', re.IGNORECASE),
    re.compile(r'\b(penetration\s+test(ing)?|red\s+team|vulnerability\s+report|security\s+audit|owasp)\b', re.IGNORECASE),
    re.compile(r'\b(defense\s+against|mitigat(e|ion)|prevent(ing)?|protect\s+against|guardrail)\b', re.IGNORECASE),
    re.compile(r'\b(research\s+paper|academic|literature|thesis|experiment)\b', re.IGNORECASE),
    re.compile(r'\b(asked\s+whether|curious\s+if|inquiring\s+about|discuss(ing|ion))\b', re.IGNORECASE),
]

# Patterns detecting if text is quoted (e.g. "ignore previous instructions")
QUOTED_TEXT_PATTERN = re.compile(r'["\'`]([^"\'`]{5,})["\'`]')

# Severity to numerical base score mapping
SEVERITY_SCORE_MAP = {
    "High": 85.0,
    "Medium": 55.0,
    "Low": 30.0,
}


@dataclass
class RuleMatch:
    rule_name: str
    category: str
    severity: str
    matched_text: str
    score: float
    is_educational_context: bool = False
    context_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": "Rule",
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "indicator": f"Rule '{self.rule_name}' ({self.category}, {self.severity}): matched '{self.matched_text}'"
                         + (f" [Context: {self.context_note}]" if self.context_note else ""),
            "score": round(self.score, 2),
            "matched_text": self.matched_text,
            "is_educational_context": self.is_educational_context,
            "context_note": self.context_note,
        }


@dataclass
class RuleDetectionResult:
    rule_score: float
    matched_rules: List[RuleMatch] = field(default_factory=list)
    detected_categories: List[str] = field(default_factory=list)
    has_high_severity: bool = False
    is_safe: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_score": self.rule_score,
            "matched_rules": [r.to_dict() for r in self.matched_rules],
            "detected_categories": self.detected_categories,
            "has_high_severity": self.has_high_severity,
            "is_safe": self.is_safe,
        }


class RuleEngine:
    def __init__(self, rules_path: Optional[Path] = None, rules_list: Optional[List[Dict[str, Any]]] = None):
        """
        Initializes rule engine from provided list, or loads from config/default_rules.json.
        """
        self.rules_path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self._compiled_rules: List[Dict[str, Any]] = []

        if rules_list is not None:
            self.rules = rules_list
        else:
            self.load_rules()

        self._compile_rules()

    def load_rules(self) -> None:
        """Loads rules from default JSON file."""
        if self.rules_path.exists():
            with open(self.rules_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
        else:
            self.rules = []

    def _compile_rules(self) -> None:
        self._compiled_rules = []
        for r in self.rules:
            if not r.get("enabled", True):
                continue
            try:
                compiled = re.compile(r["rule_pattern"], re.IGNORECASE)
                self._compiled_rules.append({
                    "rule_name": r["rule_name"],
                    "category": r["category"],
                    "severity": r.get("severity", "High"),
                    "regex": compiled
                })
            except re.error:
                continue

    def detect(self, text: str, deobfuscated_text: Optional[str] = None) -> RuleDetectionResult:
        """
        Scans input text (and deobfuscated text if provided) against compiled rules.
        Applies context attenuation if text is found in educational/research context.
        """
        if not text:
            return RuleDetectionResult(rule_score=0.0, is_safe=True)

        target_texts = [text]
        if deobfuscated_text and deobfuscated_text.strip() != text.strip():
            target_texts.append(deobfuscated_text)

        # Check if the surrounding text has strong benign context (e.g. textbook, research, educational)
        is_benign_context, context_reason = self._is_educational_or_benign_context(text)

        matches: List[RuleMatch] = []
        seen_rules: Set[str] = set()
        categories: Set[str] = set()

        for cur_text in target_texts:
            # Check quotes to see which regions are quoted
            quotes_in_text = set(QUOTED_TEXT_PATTERN.findall(cur_text))

            for rule in self._compiled_rules:
                if rule["rule_name"] in seen_rules:
                    continue

                found = rule["regex"].search(cur_text)
                if found:
                    seen_rules.add(rule["rule_name"])
                    categories.add(rule["category"])
                    matched_snippet = found.group(0)

                    # Determine if matched snippet is inside quotation marks
                    is_quoted = any(matched_snippet in q for q in quotes_in_text)

                    base_score = SEVERITY_SCORE_MAP.get(rule["severity"], 70.0)
                    adjusted_score = base_score
                    context_note = ""

                    # Context-Aware False-Positive Mitigation:
                    # If the match appears inside an educational discussion or inside quotation marks
                    if is_benign_context or is_quoted:
                        if is_benign_context and is_quoted:
                            context_note = f"Quoted inside educational context ({context_reason})"
                            # Significantly lower score to Suspicious / Review range
                            adjusted_score = min(base_score * 0.45, 40.0)
                        elif is_benign_context:
                            context_note = f"Educational/analytical framing detected ({context_reason})"
                            adjusted_score = min(base_score * 0.60, 50.0)
                        elif is_quoted:
                            context_note = "Quoted text string"
                            adjusted_score = min(base_score * 0.70, 55.0)

                    match_obj = RuleMatch(
                        rule_name=rule["rule_name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        matched_text=matched_snippet[:100],
                        score=adjusted_score,
                        is_educational_context=(is_benign_context or is_quoted),
                        context_note=context_note
                    )
                    matches.append(match_obj)

        if not matches:
            return RuleDetectionResult(
                rule_score=0.0,
                matched_rules=[],
                detected_categories=[],
                has_high_severity=False,
                is_safe=True
            )

        # Composite rule score calculation:
        # Take the maximum individual rule score, plus small incremental factor for multiple matches
        max_score = max(m.score for m in matches)
        additional_penalty = min((len(matches) - 1) * 5.0, 15.0) if len(matches) > 1 else 0.0
        final_rule_score = min(max_score + additional_penalty, 100.0)

        has_high = any(m.severity == "High" and not m.is_educational_context for m in matches)
        is_safe = final_rule_score < 30.0

        return RuleDetectionResult(
            rule_score=round(final_rule_score, 2),
            matched_rules=matches,
            detected_categories=sorted(list(categories)),
            has_high_severity=has_high,
            is_safe=is_safe
        )

    def _is_educational_or_benign_context(self, text: str) -> (bool, str):
        """Checks whether the text is framed as an inquiry, educational lesson, or audit report."""
        for pattern in BENIGN_CONTEXT_PATTERNS:
            match = pattern.search(text)
            if match:
                return True, match.group(0).lower()
        return False, ""
