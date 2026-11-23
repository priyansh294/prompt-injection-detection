"""
Streamlit Page 7: Settings & Policy Configuration
Implements FR-16 (Admin Module) and UI/UX Redesign SRS Section 6.7.
Provides dynamic risk threshold tuning, weight calibration,
rule management, and audit log controls.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd

from src.database.db import DatabaseManager
from config.settings import THRESHOLDS, RISK_WEIGHTS, ATTACK_CATEGORIES
from app.ui_theme import inject_custom_css, render_header

st.set_page_config(
    page_title="Settings — RAG Security",
    page_icon="⚙️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_custom_css()

render_header(
    title="Security Policy & Threshold Configuration",
    subtitle="Configure risk scoring formula weights, policy enforcement boundaries, and detection pattern rules.",
    icon="⚙️"
)

db = DatabaseManager()
db.init_db()

# Section 1: Risk Score Thresholds Card
st.markdown("""
<div style="background: #161E2E; border: 1px solid #374151; border-radius: 10px; padding: 14px 18px; margin-bottom: 16px;">
    <span style="font-weight: 700; color: #F9FAFB; font-size: 1.05rem;">🎯 Policy Decision Boundaries (Risk Score 0–100)</span>
    <p style="font-size: 0.88rem; color: #9CA3AF; margin: 4px 0 0 0;">
        Calibrate cutoffs for allowing, reviewing, or quarantining content within the RAG pipeline.
    </p>
</div>
""", unsafe_allow_html=True)

t_col1, t_col2 = st.columns(2)
with t_col1:
    low_max = st.slider(
        "Low Risk Ceiling (ALLOW):",
        min_value=10.0,
        max_value=45.0,
        value=float(THRESHOLDS.get("low_max", 29.0)),
        step=1.0,
        help="Scores at or below this value are classified as Safe and allowed to proceed."
    )
with t_col2:
    med_max = st.slider(
        "Medium Risk Ceiling (REVIEW):",
        min_value=46.0,
        max_value=75.0,
        value=float(THRESHOLDS.get("medium_max", 59.0)),
        step=1.0,
        help="Scores above this value are classified as High Risk (Block / Quarantine)."
    )

st.markdown(f"""
<div class="sec-banner banner-safe" style="margin-top: 6px;">
    <div>
        <strong>Active Boundary Policy:</strong> &nbsp;
        <span style="color: #34D399;">Low Risk [0.0 – {low_max:.0f}]: ALLOW</span> &nbsp;•&nbsp; 
        <span style="color: #FBBF24;">Medium Risk [{low_max + 1:.0f} – {med_max:.0f}]: REVIEW</span> &nbsp;•&nbsp; 
        <span style="color: #F87171;">High Risk [{med_max + 1:.0f} – 100.0]: BLOCK / QUARANTINE</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()

# Section 2: Weight Calibration Card
st.markdown("""
<div style="background: #161E2E; border: 1px solid #374151; border-radius: 10px; padding: 14px 18px; margin-bottom: 16px;">
    <span style="font-weight: 700; color: #F9FAFB; font-size: 1.05rem;">⚖️ Composite Risk Signal Weights</span>
    <p style="font-size: 0.88rem; color: #9CA3AF; margin: 4px 0 0 0;">
        Formula: <code>Risk = w_R*R + w_M*M + w_S*S + w_O*O</code>. Weights must sum to 1.00 (100%).
    </p>
</div>
""", unsafe_allow_html=True)

w_col1, w_col2, w_col3, w_col4 = st.columns(4)
with w_col1:
    w_r = st.number_input("Rule Weight (R):", min_value=0.0, max_value=1.0, value=float(RISK_WEIGHTS.get("rule_weight", 0.30)), step=0.05)
with w_col2:
    w_m = st.number_input("ML Weight (M):", min_value=0.0, max_value=1.0, value=float(RISK_WEIGHTS.get("ml_weight", 0.40)), step=0.05)
with w_col3:
    w_s = st.number_input("Semantic Weight (S):", min_value=0.0, max_value=1.0, value=float(RISK_WEIGHTS.get("semantic_weight", 0.20)), step=0.05)
with w_col4:
    w_o = st.number_input("Obfuscation Weight (O):", min_value=0.0, max_value=1.0, value=float(RISK_WEIGHTS.get("obfuscation_weight", 0.10)), step=0.05)

total_w = round(w_r + w_m + w_s + w_o, 2)
if abs(total_w - 1.0) > 1e-4:
    st.warning(f"⚠️ Warning: Total weight sum is {total_w:.2f}. Recommended sum is exactly 1.00 (100%).")
else:
    st.success("✅ Total weights sum perfectly to 1.00 (100%).")

st.divider()

# Section 3: Detection Rules Management Card
st.markdown("#### 📜 Detection Pattern Rules Management")
st.caption("Active regex rules in SQLite database queried during Rule-Based Detection stage.")

rules = db.get_rules(only_enabled=False)
if rules:
    df_rules = pd.DataFrame(rules)
    display_rules = df_rules[["rule_id", "rule_name", "category", "severity", "enabled", "rule_pattern"]].copy()
    display_rules.columns = ["Rule ID", "Rule Name", "Attack Category", "Severity", "Status", "Regex Pattern"]
    display_rules["Status"] = display_rules["Status"].apply(lambda x: "Active" if x == 1 else "Disabled")
    st.dataframe(display_rules, use_container_width=True, hide_index=True)

# Add custom rule form
with st.expander("➕ Add New Detection Rule"):
    with st.form("new_rule_form"):
        r_name = st.text_input("Rule Identifier:", placeholder="e.g., custom_instruction_override")
        r_pattern = st.text_input("Regex Pattern:", placeholder="(?i)\\bmy_attack_pattern\\b")
        r_cat = st.selectbox("Target Attack Category:", ATTACK_CATEGORIES)
        r_sev = st.selectbox("Severity Level:", ["High", "Medium", "Low"])
        submitted = st.form_submit_button("Save Rule to SQLite Database", type="primary")

        if submitted:
            if r_name and r_pattern:
                with db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO detection_rules (rule_name, rule_pattern, category, severity, enabled)
                        VALUES (?, ?, ?, ?, 1)
                    """, (r_name, r_pattern, r_cat, r_sev))
                    conn.commit()
                st.success(f"Rule '{r_name}' added successfully! Refresh to view in table.")
            else:
                st.error("Both rule identifier and regex pattern are required.")
