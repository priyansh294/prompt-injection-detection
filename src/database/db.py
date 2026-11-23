"""
Database Management Module
Implements SQLite schema and access layer per SRS Section 13:
- Table 1: analysis_records
- Table 2: detection_details
- Table 3: detection_rules
- Table 4: model_evaluation
"""

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import json

from config.settings import DATABASE_PATH, DEFAULT_RULES_PATH


class DatabaseManager:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self) -> None:
        """Create all tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Analysis Records (SRS Section 13.1 Table 1)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_records (
                    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    input_type TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    analysis_date DATETIME NOT NULL,
                    action TEXT NOT NULL,
                    input_text_snippet TEXT
                );
            """)

            # Table 2: Detection Details (SRS Section 13.1 Table 2)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_details (
                    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    category TEXT,
                    indicator TEXT NOT NULL,
                    score REAL NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_records (analysis_id) ON DELETE CASCADE
                );
            """)

            # Table 3: Detection Rules (SRS Section 13.1 Table 3)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_rules (
                    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    rule_pattern TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 1
                );
            """)

            # Table 4: Model Evaluation (SRS Section 13.1 Table 4)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS model_evaluation (
                    evaluation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT NOT NULL,
                    accuracy REAL NOT NULL,
                    precision REAL NOT NULL,
                    recall REAL NOT NULL,
                    f1_score REAL NOT NULL,
                    test_date DATETIME NOT NULL
                );
            """)
            conn.commit()

    def seed_default_rules(self, rules_file: Optional[Path] = None) -> int:
        """Load initial detection rules from json into detection_rules table."""
        file_path = Path(rules_file) if rules_file else DEFAULT_RULES_PATH
        if not file_path.exists():
            return 0

        with open(file_path, "r", encoding="utf-8") as f:
            rules_data = json.load(f)

        inserted_count = 0
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for r in rules_data:
                cursor.execute("""
                    INSERT OR IGNORE INTO detection_rules (rule_name, rule_pattern, category, severity, enabled)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    r["rule_name"],
                    r["rule_pattern"],
                    r["category"],
                    r.get("severity", "High"),
                    1 if r.get("enabled", True) else 0
                ))
                if cursor.rowcount > 0:
                    inserted_count += 1
            conn.commit()
        return inserted_count

    # -----------------------------
    # Analysis & Detection Logging
    # -----------------------------
    def save_analysis(
        self,
        input_type: str,
        classification: str,
        risk_score: float,
        action: str,
        detection_details: List[Dict[str, Any]],
        input_text_snippet: Optional[str] = None
    ) -> int:
        """Saves a complete scan record and all associated detection breakdown items."""
        now = datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analysis_records (input_type, classification, risk_score, analysis_date, action, input_text_snippet)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                input_type,
                classification,
                round(risk_score, 2),
                now,
                action,
                input_text_snippet[:150] if input_text_snippet else None
            ))
            analysis_id = cursor.lastrowid

            for det in detection_details:
                cursor.execute("""
                    INSERT INTO detection_details (analysis_id, method, category, indicator, score)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    det.get("method", "Unknown"),
                    det.get("category", "General"),
                    det.get("indicator", ""),
                    round(float(det.get("score", 0.0)), 2)
                ))
            conn.commit()
            return analysis_id

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent analysis records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT analysis_id, input_type, classification, risk_score, analysis_date, action, input_text_snippet
                FROM analysis_records
                ORDER BY analysis_id DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_analysis_details(self, analysis_id: int) -> List[Dict[str, Any]]:
        """Fetch all detection indicators for a given analysis record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT detection_id, analysis_id, method, category, indicator, score
                FROM detection_details
                WHERE analysis_id = ?
            """, (analysis_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Aggregate stats for the Home Dashboard (SRS Section FR-12 / Section 14)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM analysis_records")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM analysis_records WHERE classification = 'Safe'")
            safe = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM analysis_records WHERE classification = 'Suspicious'")
            suspicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM analysis_records WHERE classification = 'Malicious'")
            malicious = cursor.fetchone()[0]

            cursor.execute("""
                SELECT risk_score FROM analysis_records ORDER BY analysis_id DESC LIMIT 500
            """)
            scores = [row[0] for row in cursor.fetchall()]

            cursor.execute("""
                SELECT category, COUNT(*) as count 
                FROM detection_details 
                WHERE category IS NOT NULL AND category != 'None'
                GROUP BY category 
                ORDER BY count DESC
            """)
            categories = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT method, COUNT(*) as count 
                FROM detection_details 
                GROUP BY method 
                ORDER BY count DESC
            """)
            methods = [dict(row) for row in cursor.fetchall()]

            return {
                "total": total,
                "safe": safe,
                "suspicious": suspicious,
                "malicious": malicious,
                "scores": scores,
                "categories": categories,
                "methods": methods
            }

    # -----------------------------
    # Detection Rules Management
    # -----------------------------
    def get_rules(self, only_enabled: bool = True) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT rule_id, rule_name, rule_pattern, category, severity, enabled FROM detection_rules"
            if only_enabled:
                query += " WHERE enabled = 1"
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def toggle_rule(self, rule_id: int, enabled: bool) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE detection_rules SET enabled = ? WHERE rule_id = ?", (1 if enabled else 0, rule_id))
            conn.commit()

    # -----------------------------
    # Model Evaluation Records
    # -----------------------------
    def save_evaluation(
        self,
        model_name: str,
        accuracy: float,
        precision: float,
        recall: float,
        f1_score: float,
        test_date: Optional[str] = None
    ) -> int:
        now = test_date or datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO model_evaluation (model_name, accuracy, precision, recall, f1_score, test_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                model_name,
                round(accuracy, 4),
                round(precision, 4),
                round(recall, 4),
                round(f1_score, 4),
                now
            ))
            conn.commit()
            return cursor.lastrowid

    def get_evaluations(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT evaluation_id, model_name, accuracy, precision, recall, f1_score, test_date
                FROM model_evaluation
                ORDER BY evaluation_id DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
