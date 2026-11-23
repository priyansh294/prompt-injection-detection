"""
Model Training and Evaluation Script
Trains baseline classifiers (Model B: Logistic Regression, Model C: Linear SVM)
and logs metrics to SQLite database per SRS Section 13 & 16.
"""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.detectors.ml_classifier import MLPromptClassifier
from src.database.db import DatabaseManager
from config.settings import SEED_DATASET_PATH, TFIDF_VECTORIZER_PATH, ML_CLASSIFIER_PATH


def main():
    print(f"Loading dataset from: {SEED_DATASET_PATH}")
    db = DatabaseManager()
    db.init_db()

    # 1. Train Model B: TF-IDF + Logistic Regression
    print("\n--- Training Model B: TF-IDF + Logistic Regression ---")
    clf_lr = MLPromptClassifier(auto_load=False)
    metrics_lr = clf_lr.train_and_evaluate(
        dataset_path=SEED_DATASET_PATH,
        classifier_type="logistic_regression",
        save_after_training=True
    )
    print(f"Model B Results -> Accuracy: {metrics_lr['accuracy']:.4f}, Precision: {metrics_lr['precision']:.4f}, Recall: {metrics_lr['recall']:.4f}, F1: {metrics_lr['f1_score']:.4f}")
    
    # Save to SQLite evaluation table
    db.save_evaluation(
        model_name="Model B: TF-IDF + Logistic Regression",
        accuracy=metrics_lr["accuracy"],
        precision=metrics_lr["precision"],
        recall=metrics_lr["recall"],
        f1_score=metrics_lr["f1_score"]
    )
    print("Saved Model B evaluation metrics to SQLite database.")

    # 2. Train Model C: TF-IDF + Linear SVM
    print("\n--- Training Model C: TF-IDF + Linear SVM ---")
    clf_svm = MLPromptClassifier(
        vectorizer_path=BASE_DIR / "models" / "tfidf_vectorizer_svm.joblib",
        model_path=BASE_DIR / "models" / "linear_svm_classifier.joblib",
        auto_load=False
    )
    metrics_svm = clf_svm.train_and_evaluate(
        dataset_path=SEED_DATASET_PATH,
        classifier_type="linear_svm",
        save_after_training=True
    )
    print(f"Model C Results -> Accuracy: {metrics_svm['accuracy']:.4f}, Precision: {metrics_svm['precision']:.4f}, Recall: {metrics_svm['recall']:.4f}, F1: {metrics_svm['f1_score']:.4f}")
    
    # Save to SQLite evaluation table
    db.save_evaluation(
        model_name="Model C: TF-IDF + Linear SVM",
        accuracy=metrics_svm["accuracy"],
        precision=metrics_svm["precision"],
        recall=metrics_svm["recall"],
        f1_score=metrics_svm["f1_score"]
    )
    print("Saved Model C evaluation metrics to SQLite database.")


if __name__ == "__main__":
    main()
