"""
Machine Learning Detection Engine Module
Implements FR-05 (Machine-Learning Classification) and Module 4 per SRS v1.0:
- TF-IDF feature extraction (unigrams + bigrams)
- Multi-class classification: Safe, Suspicious, Malicious
- Logistic Regression (with support for Linear SVM)
- Prevention of data leakage: vectorizer fit strictly on training split
- Evaluation metrics: Accuracy, Precision, Recall, F1-score, Confusion Matrix
- Model persistence with joblib and graceful handling of missing model files
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import os
import joblib
import pandas as pd
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from config.settings import (
    SEED_DATASET_PATH,
    TFIDF_VECTORIZER_PATH,
    ML_CLASSIFIER_PATH,
    MODELS_DIR
)


CLASSES = ["Safe", "Suspicious", "Malicious"]


class MLPromptClassifier:
    def __init__(
        self,
        vectorizer_path: Optional[Path] = None,
        model_path: Optional[Path] = None,
        auto_load: bool = True
    ):
        self.vectorizer_path = Path(vectorizer_path) if vectorizer_path else TFIDF_VECTORIZER_PATH
        self.model_path = Path(model_path) if model_path else ML_CLASSIFIER_PATH
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.model: Optional[Any] = None
        self.is_trained: bool = False

        if auto_load:
            self.load()

    def load(self) -> bool:
        """Loads serialized vectorizer and model from disk if available."""
        if self.vectorizer_path.exists() and self.model_path.exists():
            try:
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                return True
            except Exception:
                self.is_trained = False
                return False
        self.is_trained = False
        return False

    def save(self) -> None:
        """Serializes trained vectorizer and model to disk."""
        if not self.is_trained or self.vectorizer is None or self.model is None:
            raise ValueError("Cannot save an untrained model.")
        self.vectorizer_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        joblib.dump(self.model, self.model_path)

    def train_and_evaluate(
        self,
        dataset_path: Optional[Path] = None,
        test_size: float = 0.20,
        random_state: int = 42,
        save_after_training: bool = True,
        classifier_type: str = "logistic_regression"
    ) -> Dict[str, Any]:
        """
        Trains TF-IDF vectorizer and classifier from dataset.
        Prevents data leakage by fitting vectorizer strictly on training data.
        """
        data_file = Path(dataset_path) if dataset_path else SEED_DATASET_PATH
        if not data_file.exists():
            raise FileNotFoundError(f"Dataset not found at {data_file}")

        df = pd.read_csv(data_file)
        if "text" not in df.columns or "label" not in df.columns:
            raise ValueError("Dataset must contain 'text' and 'label' columns.")

        # Clean nulls
        df = df.dropna(subset=["text", "label"])
        X = df["text"].astype(str).tolist()
        y = df["label"].astype(str).tolist()

        # Stratified train/test split to preserve class distributions and prevent data leakage
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=random_state,
            stratify=y
        )

        # Fit TF-IDF exclusively on training split
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
            strip_accents="unicode"
        )
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)

        # Instantiate classifier
        if classifier_type == "linear_svm":
            base_svm = LinearSVC(C=1.0, class_weight="balanced", random_state=random_state, max_iter=2000)
            self.model = CalibratedClassifierCV(base_svm, cv=3)
        else:
            self.model = LogisticRegression(
                C=2.0,
                max_iter=1000,
                class_weight="balanced",
                random_state=random_state,
                solver="lbfgs"
            )

        self.model.fit(X_train_vec, y_train)
        self.is_trained = True

        if save_after_training:
            self.save()

        # Evaluation on unseen test split
        y_pred = self.model.predict(X_test_vec)
        
        # Calculate standard evaluation metrics (SRS Section 16)
        accuracy = float(accuracy_score(y_test, y_pred))
        precision = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        recall = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        
        # Multiclass confusion matrix
        labels_order = [c for c in CLASSES if c in set(y_test) | set(y_pred)]
        cm = confusion_matrix(y_test, y_pred, labels=labels_order).tolist()
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        return {
            "model_type": classifier_type,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,
            "labels": labels_order,
            "classification_report": report
        }

    def predict(self, text: Optional[str]) -> Dict[str, Any]:
        """
        Classifies input text and returns predicted class, probabilities, and ML risk score.
        Gracefully handles untrained/missing model state with fallback heuristic.
        """
        if text is None:
            text = ""

        clean_text = text.strip()
        if not clean_text:
            return {
                "predicted_class": "Safe",
                "probabilities": {"Safe": 1.0, "Suspicious": 0.0, "Malicious": 0.0},
                "confidence": 1.0,
                "ml_risk_score": 0.0,
                "status": "empty_input"
            }

        # Fallback if model is not loaded or trained
        if not self.is_trained or self.vectorizer is None or self.model is None:
            return self._fallback_prediction(clean_text)

        try:
            X_vec = self.vectorizer.transform([clean_text])
            predicted_class = self.model.predict(X_vec)[0]

            # Extract calibrated class probabilities
            if hasattr(self.model, "predict_proba"):
                probs_raw = self.model.predict_proba(X_vec)[0]
                classes = list(self.model.classes_)
                prob_dict = {cls: round(float(probs_raw[classes.index(cls)]), 4) for cls in classes}
            else:
                prob_dict = {c: 1.0 if c == predicted_class else 0.0 for c in CLASSES}

            # Normalize to include all 3 classes
            for c in CLASSES:
                if c not in prob_dict:
                    prob_dict[c] = 0.0

            p_malicious = prob_dict.get("Malicious", 0.0)
            p_suspicious = prob_dict.get("Suspicious", 0.0)
            p_safe = prob_dict.get("Safe", 0.0)

            # Continuous ML Risk Score calibrated to SRS threat bands (FR-08)
            if predicted_class == "Safe":
                ml_risk_score = min(round((p_malicious * 40.0) + (p_suspicious * 20.0), 2), 28.0)
            elif predicted_class == "Suspicious":
                ml_risk_score = min(round(35.0 + (p_malicious * 45.0), 2), 58.0)
            else: # Malicious
                ml_risk_score = min(round(60.0 + (p_malicious * 38.0) + (p_suspicious * 10.0), 2), 100.0)

            confidence = max(prob_dict.values())

            return {
                "predicted_class": predicted_class,
                "probabilities": prob_dict,
                "confidence": round(confidence, 4),
                "ml_risk_score": ml_risk_score,
                "status": "success"
            }
        except Exception as e:
            return self._fallback_prediction(clean_text, error=str(e))

    def _fallback_prediction(self, text: str, error: Optional[str] = None) -> Dict[str, Any]:
        """Provides neutral fallback prediction when ML model file is missing or failed."""
        return {
            "predicted_class": "Suspicious",
            "probabilities": {"Safe": 0.33, "Suspicious": 0.34, "Malicious": 0.33},
            "confidence": 0.34,
            "ml_risk_score": 35.0,
            "status": "fallback",
            "note": f"ML model not trained/loaded. Fallback heuristic applied. {error or ''}".strip()
        }
