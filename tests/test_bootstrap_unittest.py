"""
Unit tests using Python standard library unittest.
Verifies project bootstrap, database operations, and seed dataset integrity without external dependencies.
"""

import unittest
import tempfile
import csv
from pathlib import Path
import sys

# Ensure root directory is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import (
    DATA_DIR,
    MODELS_DIR,
    SEED_DATASET_PATH,
    DEFAULT_RULES_PATH,
    RISK_WEIGHTS,
    THRESHOLDS
)
from src.database.db import DatabaseManager


class TestBootstrap(unittest.TestCase):
    def test_project_structure(self):
        self.assertTrue(DATA_DIR.exists())
        self.assertTrue(MODELS_DIR.exists())
        self.assertTrue((BASE_DIR / "src" / "preprocessing").exists())
        self.assertTrue((BASE_DIR / "src" / "detectors").exists())
        self.assertTrue((BASE_DIR / "src" / "engine").exists())
        self.assertTrue((BASE_DIR / "src" / "gateway").exists())
        self.assertTrue((BASE_DIR / "src" / "database").exists())
        self.assertTrue((BASE_DIR / "src" / "evaluation").exists())
        self.assertTrue((BASE_DIR / "app" / "pages").exists())

    def test_configuration_weights_and_thresholds(self):
        total_weight = sum(RISK_WEIGHTS.values())
        self.assertAlmostEqual(total_weight, 1.0)
        self.assertEqual(RISK_WEIGHTS["rule_weight"], 0.30)
        self.assertEqual(RISK_WEIGHTS["ml_weight"], 0.40)
        self.assertEqual(RISK_WEIGHTS["semantic_weight"], 0.20)
        self.assertEqual(RISK_WEIGHTS["obfuscation_weight"], 0.10)

        self.assertEqual(THRESHOLDS["low_max"], 29.0)
        self.assertEqual(THRESHOLDS["medium_max"], 59.0)
        self.assertEqual(THRESHOLDS["high_min"], 60.0)

    def test_seed_dataset_format(self):
        self.assertTrue(SEED_DATASET_PATH.exists())
        with open(SEED_DATASET_PATH, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            expected_fields = ["id", "text", "label", "attack_category", "text_type", "obfuscation", "notes"]
            self.assertEqual(reader.fieldnames, expected_fields)
            
            rows = list(reader)
            self.assertGreaterEqual(len(rows), 50)
            
            labels = {r["label"] for r in rows}
            self.assertEqual(labels, {"Safe", "Suspicious", "Malicious"})

    def test_database_manager(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db_path = Path(temp_dir) / "test_rag.db"
            db = DatabaseManager(db_path=test_db_path)
            db.init_db()
            
            # Test rule seeding
            seeded = db.seed_default_rules(rules_file=DEFAULT_RULES_PATH)
            self.assertGreaterEqual(seeded, 15)
            
            rules = db.get_rules(only_enabled=True)
            self.assertEqual(len(rules), seeded)
            
            # Test saving analysis and retrieval (UT-10)
            details = [
                {"method": "Rule", "category": "Instruction Override", "indicator": "Matched ignore_previous_instructions", "score": 85.0},
                {"method": "ML", "category": "Instruction Override", "indicator": "Logistic Regression Malicious (0.92)", "score": 92.0}
            ]
            analysis_id = db.save_analysis(
                input_type="UserPrompt",
                classification="Malicious",
                risk_score=87.5,
                action="Block / Quarantine",
                detection_details=details,
                input_text_snippet="Ignore previous instructions..."
            )
            self.assertIsNotNone(analysis_id)
            
            history = db.get_history(limit=10)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["classification"], "Malicious")
            self.assertEqual(history[0]["risk_score"], 87.5)
            self.assertEqual(history[0]["action"], "Block / Quarantine")
            
            analysis_details = db.get_analysis_details(analysis_id)
            self.assertEqual(len(analysis_details), 2)
            
            metrics = db.get_dashboard_metrics()
            self.assertEqual(metrics["total"], 1)
            self.assertEqual(metrics["malicious"], 1)
            self.assertEqual(metrics["safe"], 0)


if __name__ == "__main__":
    unittest.main()
