"""
Text Preprocessing and Obfuscation Detection Module
Implements FR-02 (Text Preprocessing) and Obfuscation Detection per SRS v1.0:
- Unicode normalization (NFKC, zero-width characters)
- Whitespace normalization
- Suspicious character & encoding analysis (Base64, Hex, URL-encoding)
- Obfuscation pattern detection (Leetspeak, spaced characters, hyphens)
- Retention of original text alongside normalized and de-obfuscated representations
"""

import re
import unicodedata
import base64
import binascii
from urllib.parse import unquote
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


# Zero-width and hidden Unicode characters commonly used for injection evasion
ZERO_WIDTH_CHARS = {
    '\u200B': 'Zero-Width Space',
    '\u200C': 'Zero-Width Non-Joiner',
    '\u200D': 'Zero-Width Joiner',
    '\uFEFF': 'Zero-Width No-Break Space (BOM)',
    '\u200E': 'Left-to-Right Mark',
    '\u200F': 'Right-to-Left Mark',
    '\u202A': 'Left-to-Right Embedding',
    '\u202B': 'Right-to-Left Embedding',
    '\u202C': 'Pop Directional Formatting',
    '\u202D': 'Left-to-Right Override',
    '\u202E': 'Right-to-Left Override',
    '\u00AD': 'Soft Hyphen',
}

# Standard Leetspeak map for de-obfuscation
LEET_MAP = {
    '0': 'o',
    '1': 'i',
    '!': 'i',
    '|': 'l',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '7': 't',
    '+': 't',
    '8': 'b',
    '9': 'g',
}

# Base64 regex pattern (strings of length >= 16 with padding or base64 chars)
BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# Hex pattern (e.g., \x49\x67 or 49676e6f7265)
HEX_ESCAPE_REGEX = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')

# Spaced words pattern (e.g. "i g n o r e" or "d i s r e g a r d")
SPACED_CHARS_REGEX = re.compile(r'\b(?:[a-zA-Z][\s\-_]){3,}[a-zA-Z]\b')


@dataclass
class PreprocessedText:
    original_text: str
    normalized_text: str
    deobfuscated_text: str
    tokens: List[str]
    sentences: List[str]
    obfuscation_score: float
    obfuscation_indicators: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_text": self.original_text,
            "normalized_text": self.normalized_text,
            "deobfuscated_text": self.deobfuscated_text,
            "tokens": self.tokens,
            "sentences": self.sentences,
            "obfuscation_score": self.obfuscation_score,
            "obfuscation_indicators": self.obfuscation_indicators,
            "metadata": self.metadata,
        }


class TextPreprocessor:
    def __init__(self):
        pass

    def preprocess(self, text: Optional[str]) -> PreprocessedText:
        """
        Main entry point for preprocessing and obfuscation analysis.
        Handles None, empty strings, and malformed inputs safely.
        """
        if text is None:
            text = ""

        original_text = str(text)
        indicators: List[Dict[str, Any]] = []
        obfuscation_score = 0.0

        if not original_text.strip():
            return PreprocessedText(
                original_text=original_text,
                normalized_text="",
                deobfuscated_text="",
                tokens=[],
                sentences=[],
                obfuscation_score=0.0,
                obfuscation_indicators=[],
                metadata={"char_count": 0, "word_count": 0}
            )

        # 1. Unicode Normalization & Zero-width detection
        clean_unicode_text, zw_indicators, zw_score = self._detect_and_clean_zero_width(original_text)
        indicators.extend(zw_indicators)
        obfuscation_score += zw_score

        # NFKC Normalization converts compatibility characters to canonical equivalents
        nfkc_text = unicodedata.normalize("NFKC", clean_unicode_text)

        # 2. URL-decoding check
        url_decoded_text, url_indicators, url_score = self._check_url_encoding(nfkc_text)
        indicators.extend(url_indicators)
        obfuscation_score += url_score

        # 3. Base64 & Hex analysis
        base64_decoded_segments, b64_indicators, b64_score = self._check_base64_and_hex(url_decoded_text)
        indicators.extend(b64_indicators)
        obfuscation_score += b64_score

        # 4. Spaced/Hyphenated Character Detection
        unspaced_text, space_indicators, space_score = self._detect_spaced_characters(url_decoded_text)
        indicators.extend(space_indicators)
        obfuscation_score += space_score

        # 5. Leetspeak Translation
        leet_text, leet_indicators, leet_score = self._translate_leetspeak(unspaced_text)
        indicators.extend(leet_indicators)
        obfuscation_score += leet_score

        # Normalize whitespace
        normalized_text = self._normalize_whitespace(nfkc_text)
        
        # Deobfuscated composite text merges unspaced + leetspeak + decoded payloads
        deobfuscated_components = [self._normalize_whitespace(leet_text)]
        if base64_decoded_segments:
            deobfuscated_components.extend(base64_decoded_segments)
        deobfuscated_text = " ".join(deobfuscated_components).strip()

        # Tokenize and extract sentences
        tokens = self._tokenize(normalized_text)
        sentences = self._split_sentences(normalized_text)

        # Cap obfuscation score between 0 and 100
        final_obfuscation_score = min(round(obfuscation_score, 2), 100.0)

        metadata = {
            "char_count": len(original_text),
            "word_count": len(tokens),
            "sentence_count": len(sentences),
            "has_zero_width": bool(zw_indicators),
            "has_base64": any(ind["type"] == "base64" for ind in indicators),
            "has_leetspeak": bool(leet_indicators),
            "has_spaced_text": bool(space_indicators),
            "has_url_encoding": bool(url_indicators),
        }

        return PreprocessedText(
            original_text=original_text,
            normalized_text=normalized_text,
            deobfuscated_text=deobfuscated_text,
            tokens=tokens,
            sentences=sentences,
            obfuscation_score=final_obfuscation_score,
            obfuscation_indicators=indicators,
            metadata=metadata
        )

    def _detect_and_clean_zero_width(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        indicators = []
        score = 0.0
        cleaned_chars = []
        found_zw = []

        for ch in text:
            if ch in ZERO_WIDTH_CHARS:
                found_zw.append(ZERO_WIDTH_CHARS[ch])
            else:
                cleaned_chars.append(ch)

        if found_zw:
            score += min(len(found_zw) * 15.0, 60.0)
            indicators.append({
                "type": "zero_width_unicode",
                "indicator": f"Detected {len(found_zw)} invisible/zero-width character(s) ({', '.join(set(found_zw))})",
                "score": min(len(found_zw) * 15.0, 60.0)
            })

        return "".join(cleaned_chars), indicators, score

    def _normalize_whitespace(self, text: str) -> str:
        """Collapse multiple spaces, newlines, and tabs into a clean single string."""
        return re.sub(r'\s+', ' ', text).strip()

    def _check_url_encoding(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        indicators = []
        score = 0.0
        decoded = unquote(text)
        if "%" in text and decoded != text:
            # Check if decoding revealed prompt keywords
            if any(k in decoded.lower() for k in ["ignore", "prompt", "system", "bypass", "admin"]):
                score += 35.0
                indicators.append({
                    "type": "url_encoding",
                    "indicator": f"URL-encoded injection keywords revealed: {decoded[:80]}",
                    "score": 35.0
                })
        return decoded, indicators, score

    def _check_base64_and_hex(self, text: str) -> Tuple[List[str], List[Dict[str, Any]], float]:
        indicators = []
        score = 0.0
        decoded_payloads: List[str] = []

        # Check Hex Escapes
        for match in HEX_ESCAPE_REGEX.finditer(text):
            hex_str = match.group(0).replace('\\x', '')
            try:
                raw_bytes = bytes.fromhex(hex_str)
                decoded_str = raw_bytes.decode('utf-8', errors='ignore')
                if len(decoded_str.strip()) > 3 and any(c.isalnum() for c in decoded_str):
                    decoded_payloads.append(decoded_str)
                    score += 40.0
                    indicators.append({
                        "type": "hex_encoding",
                        "indicator": f"Hex-encoded text detected: '{decoded_str}'",
                        "score": 40.0
                    })
            except Exception:
                pass

        # Check Base64
        for match in BASE64_REGEX.finditer(text):
            b64_candidate = match.group(0)
            # Require minimum length to avoid matching random alphanumeric words
            if len(b64_candidate) >= 16:
                try:
                    raw_bytes = base64.b64decode(b64_candidate, validate=True)
                    decoded_str = raw_bytes.decode('utf-8', errors='ignore')
                    # Check if decoded string is readable text with letters and spaces
                    printable_ratio = sum(c.isprintable() for c in decoded_str) / max(len(decoded_str), 1)
                    if printable_ratio > 0.85 and len(decoded_str.strip()) > 5:
                        decoded_payloads.append(decoded_str)
                        added_score = 50.0
                        # Elevate if decoded string contains obvious attack words
                        if any(w in decoded_str.lower() for w in ["ignore", "prompt", "system", "password", "bypass"]):
                            added_score = 75.0
                        score += added_score
                        indicators.append({
                            "type": "base64",
                            "indicator": f"Base64 encoded payload detected: '{decoded_str[:60]}...'",
                            "score": added_score
                        })
                except Exception:
                    pass

        return decoded_payloads, indicators, score

    def _detect_spaced_characters(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Detect and collapse spaced text like 'i g n o r e' or 'd-i-s-r-e-g-a-r-d'."""
        indicators = []
        score = 0.0
        collapsed_text = text

        matches = list(SPACED_CHARS_REGEX.finditer(text))
        for m in matches:
            matched_segment = m.group(0)
            # Strip whitespace and delimiters
            collapsed_word = re.sub(r'[\s\-_]', '', matched_segment)
            if len(collapsed_word) >= 4:
                collapsed_text = collapsed_text.replace(matched_segment, collapsed_word)
                if collapsed_word.lower() in ["ignore", "disregard", "prompt", "bypass", "system", "override"]:
                    score += 45.0
                    indicators.append({
                        "type": "spaced_obfuscation",
                        "indicator": f"Spaced keyword obfuscation detected: '{matched_segment}' -> '{collapsed_word}'",
                        "score": 45.0
                    })

        return collapsed_text, indicators, score

    def _translate_leetspeak(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """
        Translates numbers and symbols in words to letters (e.g., '1gn0r3' -> 'ignore').
        """
        indicators = []
        score = 0.0
        words = text.split()
        translated_words = []
        detected_leet = []

        for word in words:
            # Check if word contains a mix of letters and digits/leet symbols
            has_alpha = any(c.isalpha() for c in word)
            has_leet_symbol = any(c in LEET_MAP for c in word)
            
            if has_alpha and has_leet_symbol and len(word) >= 4:
                translated = "".join(LEET_MAP.get(c, c) for c in word)
                if translated.lower() in ["ignore", "instructions", "prompt", "bypass", "secret", "reveal", "admin"]:
                    detected_leet.append(f"{word} -> {translated}")
                translated_words.append(translated)
            else:
                translated_words.append(word)

        if detected_leet:
            score += min(len(detected_leet) * 30.0, 60.0)
            indicators.append({
                "type": "leetspeak",
                "indicator": f"Leetspeak substitution detected: {', '.join(detected_leet)}",
                "score": min(len(detected_leet) * 30.0, 60.0)
            })

        return " ".join(translated_words), indicators, score

    def _tokenize(self, text: str) -> List[str]:
        """Basic alphanumeric tokenization."""
        return re.findall(r'\b\w+\b', text)

    def _split_sentences(self, text: str) -> List[str]:
        """Sentence boundary segmentation."""
        if not text.strip():
            return []
        sentences = re.split(r'(?<=[.!?])\s+', text)
        return [s.strip() for s in sentences if s.strip()]
