"""
Database Initialization Script
Sets up SQLite schema and seeds default detection rules from config/default_rules.json.
"""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.database.db import DatabaseManager

def main():
    print("Initializing SQLite Database...")
    db = DatabaseManager()
    db.init_db()
    print("Database tables created successfully.")

    print("Seeding default detection rules...")
    count = db.seed_default_rules()
    print(f"Successfully seeded {count} detection rules into detection_rules table.")

    # Verification query
    rules = db.get_rules(only_enabled=False)
    print(f"Total rules in database: {len(rules)}")
    for r in rules[:3]:
        print(f"  - [{r['category']}] ({r['severity']}) {r['rule_name']}: {r['rule_pattern']}")

if __name__ == "__main__":
    main()
