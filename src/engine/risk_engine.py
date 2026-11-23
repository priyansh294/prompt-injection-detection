"""
Composite Risk Assessment Engine Module
Implements FR-07 (Risk Scoring), FR-08 (Threat Classification),
FR-09 (Detection Explanation), and FR-14 (Security Recommendations) per SRS v1.0.

Formula:
  Risk Score = 0.30*R + 0.40*M + 0.20*S + 0.10*O
Where:
  R = Rule-based detection score (0–100)
  M = ML classification risk score (0–100)
  S = Semantic similarity score (0–100)
  O = Obfuscation indicator score (0–100)
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from config.settings import RISK_WEIGHTS, THRESHOLDS, ACTIONS
from src.preprocessing.text_preprocessor import TextPreprocessor, PreprocessedText
from src.detectors.rule_engine import RuleEngine, RuleDetectionResult
from src.detectors.ml_classifier import MLPromptClassifier


@dataclass
class RiskAssessmentReport:
    risk_score: float
    threat_level: str          # Low, Medium, High
    action: str                # Allow, Review, Block / Quarantine
    classification: str        # Safe, Suspicious, Malicious
    scores_breakdown: Dict[str, float]
    explanation: str
    recommendations: List[str]
    detection_details: List[Dict[str, Any]] = field(default_factory=list)
    preprocessing_metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "action": self.action,
            "classification": self.classification,
            "scores_breakdown": self.scores_breakdown,
            "explanation": self.explanation,
            "recommendations": self.recommendations,
            "detection_details": self.detection_details,
            "preprocessing_metadata": self.preprocessing_metadata,
            "execution_time_ms": self.execution_time_ms,
        }


class RiskAssessmentEngine:
    def __init__(
        self,
        preprocessor: Optional[TextPreprocessor] = None,
        rule_engine: Optional[RuleEngine] = None,
        ml_classifier: Optional[MLPromptClassifier] = None,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None,
        normalize_unconfigured_signals: bool = False
    ):
        self.preprocessor = preprocessor or TextPreprocessor()
        self.rule_engine = rule_engine or RuleEngine()
        self.ml_classifier = ml_classifier or MLPromptClassifier()
        self.weights = weights or dict(RISK_WEIGHTS)
        self.thresholds = thresholds or dict(THRESHOLDS)
        self.normalize_unconfigured_signals = normalize_unconfigured_signals

    def update_configuration(
        self,
        weights: Optional[Dict[str, float]] = None,
        thresholds: Optional[Dict[str, float]] = None
    ) -> None:
        """Dynamically update risk weights and thresholds."""
        if weights:
            self.weights.update(weights)
        if thresholds:
            self.thresholds.update(thresholds)

    def analyze(
        self,
        text: Optional[str],
        semantic_score: float = 0.0,
        input_type: str = "UserPrompt"
    ) -> RiskAssessmentReport:
        """
        Coordinates full multi-layer detection pipeline:
        1. Preprocessing & Obfuscation analysis (O)
        2. Rule-based detection (R)
        3. ML classification (M)
        4. Optional Semantic similarity (S)
        5. Composite risk calculation & threat categorization
        """
        start_time = time.perf_counter()

        # Handle empty/None input safely
        if text is None or not str(text).strip():
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return RiskAssessmentReport(
                risk_score=0.0,
                threat_level="Low",
                action=ACTIONS.get("LOW", "Allow"),
                classification="Safe",
                scores_breakdown={"rule": 0.0, "ml": 0.0, "semantic": 0.0, "obfuscation": 0.0},
                explanation="Input is empty or whitespace only. No threat detected.",
                recommendations=["Input validated as empty."],
                detection_details=[],
                preprocessing_metadata={"char_count": 0, "word_count": 0},
                execution_time_ms=elapsed_ms
            )

        # 1. Text Preprocessing & Obfuscation Analysis
        preproc: PreprocessedText = self.preprocessor.preprocess(text)
        obfuscation_score = preproc.obfuscation_score

        # 2. Rule-Based Detection
        rule_result: RuleDetectionResult = self.rule_engine.detect(
            text=preproc.normalized_text,
            deobfuscated_text=preproc.deobfuscated_text
        )
        rule_score = rule_result.rule_score

        # 3. Machine Learning Classification
        # Predict on normalized/deobfuscated text for maximum detection sensitivity
        ml_input = preproc.deobfuscated_text if preproc.deobfuscated_text else preproc.normalized_text
        ml_result = self.ml_classifier.predict(ml_input)
        ml_score = ml_result["ml_risk_score"]

        # 4. Semantic Similarity Score
        s_score = max(0.0, min(float(semantic_score), 100.0))

        # 5. Composite Risk Score Calculation
        w_rule = self.weights.get("rule_weight", 0.30)
        w_ml = self.weights.get("ml_weight", 0.40)
        w_sem = self.weights.get("semantic_weight", 0.20)
        w_obf = self.weights.get("obfuscation_weight", 0.10)

        # If semantic score is inactive and normalize is enabled, distribute weights
        if self.normalize_unconfigured_signals and s_score == 0.0 and w_sem > 0:
            active_sum = w_rule + w_ml + w_obf
            if active_sum > 0:
                raw_risk = (w_rule * rule_score + w_ml * ml_score + w_obf * obfuscation_score) / active_sum
            else:
                raw_risk = 0.0
        else:
            raw_risk = (
                (w_rule * rule_score) +
                (w_ml * ml_score) +
                (w_sem * s_score) +
                (w_obf * obfuscation_score)
            )

        final_risk_score = min(max(round(raw_risk, 2), 0.0), 100.0)

        # 6. Threat Level & Policy Action Classification (FR-08)
        low_max = self.thresholds.get("low_max", 29.0)
        med_max = self.thresholds.get("medium_max", 59.0)

        if final_risk_score <= low_max:
            threat_level = "Low"
            action = ACTIONS.get("LOW", "Allow")
            classification = "Safe"
        elif final_risk_score <= med_max:
            threat_level = "Medium"
            action = ACTIONS.get("MEDIUM", "Review")
            classification = "Suspicious"
        else:
            threat_level = "High"
            action = ACTIONS.get("HIGH", "Block / Quarantine")
            classification = "Malicious"

        # Special safety guardrail:
        # If severe non-educational rules matched with high confidence, guarantee High threat
        if rule_result.has_high_severity and final_risk_score >= 50.0:
            threat_level = "High"
            action = ACTIONS.get("HIGH", "Block / Quarantine")
            classification = "Malicious"
            if final_risk_score < 60.0:
                final_risk_score = 65.0

        # 7. Collect Structured Detection Details for SQLite
        detection_details: List[Dict[str, Any]] = []

        # Obfuscation details
        for obf_ind in preproc.obfuscation_indicators:
            detection_details.append({
                "method": "Obfuscation",
                "category": "Evasion / Encoding",
                "indicator": obf_ind["indicator"],
                "score": obf_ind["score"]
            })

        # Rule engine details
        for r_match in rule_result.matched_rules:
            detection_details.append({
                "method": "Rule",
                "category": r_match.category,
                "indicator": f"Matched pattern '{r_match.rule_name}': {r_match.matched_text}" + (f" ({r_match.context_note})" if r_match.context_note else ""),
                "score": r_match.score
            })

        # ML classifier details
        ml_pred_label = ml_result.get("predicted_class", "Safe")
        ml_conf = ml_result.get("confidence", 0.0)
        detection_details.append({
            "method": "ML",
            "category": "Statistical NLP",
            "indicator": f"Model predicted '{ml_pred_label}' (Confidence: {ml_conf:.2%})",
            "score": ml_score
        })

        if s_score > 0.0:
            detection_details.append({
                "method": "Semantic",
                "category": "Embedding Similarity",
                "indicator": f"SBERT Cosine Similarity: {s_score:.1f}%",
                "score": s_score
            })

        # 8. Generate Human-Readable Explanations (FR-09) & Recommendations (FR-14)
        explanation, recommendations = self._generate_explanation_and_recommendations(
            classification=classification,
            threat_level=threat_level,
            risk_score=final_risk_score,
            rule_result=rule_result,
            ml_result=ml_result,
            preproc=preproc,
            input_type=input_type
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return RiskAssessmentReport(
            risk_score=final_risk_score,
            threat_level=threat_level,
            action=action,
            classification=classification,
            scores_breakdown={
                "rule": rule_score,
                "ml": ml_score,
                "semantic": s_score,
                "obfuscation": obfuscation_score
            },
            explanation=explanation,
            recommendations=recommendations,
            detection_details=detection_details,
            preprocessing_metadata=preproc.metadata,
            execution_time_ms=elapsed_ms
        )

    def _generate_explanation_and_recommendations(
        self,
        classification: str,
        threat_level: str,
        risk_score: float,
        rule_result: RuleDetectionResult,
        ml_result: Dict[str, Any],
        preproc: PreprocessedText,
        input_type: str
    ) -> (str, List[str]):
        """Generates clear, security-focused explanations and action items per SRS FR-09 & FR-14."""
        reasons = []
        recommendations = []

        if classification == "Safe":
            explanation = f"Input evaluated as Safe (Risk Score: {risk_score}/100). No significant prompt-injection or evasion indicators detected."
            recommendations.append("Allow content to proceed into RAG generation pipeline.")
            return explanation, recommendations

        if rule_result.matched_rules:
            cat_str = ", ".join(rule_result.detected_categories)
            reasons.append(f"Triggered {len(rule_result.matched_rules)} security rule(s) across categories: {cat_str}.")

        if preproc.obfuscation_indicators:
            obf_types = {ind["type"] for ind in preproc.obfuscation_indicators}
            reasons.append(f"Detected evasion obfuscation ({', '.join(obf_types)}).")

        ml_label = ml_result.get("predicted_class")
        if ml_label in ["Malicious", "Suspicious"]:
            reasons.append(f"ML classifier detected {ml_label.lower()} instruction patterns with {ml_result.get('confidence', 0):.1%} confidence.")

        explanation = f"Content flagged as {classification} ({threat_level} Risk: {risk_score}/100). " + " ".join(reasons)

        # Policy recommendations
        if threat_level == "High":
            recommendations.append("Block content from reaching LLM generation stage.")
            if input_type in ["RetrievedChunk", "Document"]:
                recommendations.append("Quarantine suspicious document chunk from RAG vector store context.")
                recommendations.append("Do not follow instructions embedded in retrieved documents.")
            else:
                recommendations.append("Reject user prompt and notify security monitoring.")
            recommendations.append("Avoid passing flagged content into sensitive tool execution workflows.")
        elif threat_level == "Medium":
            recommendations.append("Flag content for administrative or analyst review.")
            recommendations.append("Sanitize context before forwarding to generation endpoint.")
            if any(m.is_educational_context for m in rule_result.matched_rules):
                recommendations.append("Context appears educational or analytical; verify intent before blocking.")

        recommendations.append("Maintain strict separation between trusted system instructions and untrusted data.")
        return explanation, recommendations
