"""
System Configuration Settings
Defines risk weights, thresholds, database paths, and model configurations
according to the Prompt-Injection Detection SRS v1.0.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CONFIG_DIR = BASE_DIR / "config"

# Database Configuration
DATABASE_PATH = DATA_DIR / "rag_security.db"

# Seed & Rules Paths
SEED_DATASET_PATH = DATA_DIR / "seed_dataset.csv"
DEFAULT_RULES_PATH = CONFIG_DIR / "default_rules.json"

# Model Paths
TFIDF_VECTORIZER_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"
ML_CLASSIFIER_PATH = MODELS_DIR / "logistic_regression_classifier.joblib"
SVM_CLASSIFIER_PATH = MODELS_DIR / "linear_svm_classifier.joblib"

# SBERT Model for Semantic Similarity Detection (FR-06 / Module 5)
SBERT_MODEL_NAME = "all-MiniLM-L6-v2"

# Risk Scoring Weights (SRS Section FR-07, Module 6)
# Risk Score = 0.30*R + 0.40*M + 0.20*S + 0.10*O
RISK_WEIGHTS = {
    "rule_weight": 0.30,
    "ml_weight": 0.40,
    "semantic_weight": 0.20,
    "obfuscation_weight": 0.10,
}

# Threat Classification Thresholds (SRS Section FR-08)
THRESHOLDS = {
    "low_max": 29.0,        # 0 - 29: Low Risk -> Allow
    "medium_max": 59.0,     # 30 - 59: Medium Risk -> Review
    "high_min": 60.0,       # 60 - 100: High Risk -> Block / Quarantine
}

# Policy Actions (SRS Section FR-08, Module 7)
ACTIONS = {
    "LOW": "Allow",
    "MEDIUM": "Review",
    "HIGH": "Block / Quarantine",
}

# Attack Categories (SRS Section Module 3)
ATTACK_CATEGORIES = [
    "Instruction Override",
    "Prompt Extraction",
    "Role Manipulation",
    "Restriction Bypass",
    "Data Exfiltration",
    "Tool Manipulation",
    "Context Manipulation",
    "Instruction Injection",
]
