"""
Streamlit Page 5: Detection History & Audit Log
Implements FR-13 (Detection History) and UI/UX Redesign SRS Section 6.5.
Provides audit trail filtering, search, export, and granular indicator drilldown.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd

from src.database.db import DatabaseManager
from app.ui_theme import inject_custom_css, render_header

st.set_page_config(
    page_title="Detection History — RAG Security",
    page_icon="📜",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_custom_css()

render_header(
    title="Detection History & Security Audit Logs",
    subtitle="Query persistent SQLite audit records, filter historical scans, review detection indicators, and export logs.",
    icon="📜"
)

db = DatabaseManager()
db.init_db()

# Filter Controls Card
st.markdown("""
<div style="background: #161E2E; border: 1px solid #374151; border-radius: 10px; padding: 12px 18px; margin-bottom: 14px;">
    <span style="font-size: 0.82rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #9CA3AF;">🔍 Filter & Search Audit Trails:</span>
</div>
""", unsafe_allow_html=True)

f_col1, f_col2, f_col3, f_col4 = st.columns(4)

with f_col1:
    class_filter = st.selectbox("Classification:", ["All", "Safe", "Suspicious", "Malicious"])
with f_col2:
    type_filter = st.selectbox("Input Type:", ["All", "UserPrompt", "RetrievedChunk", "Document"])
with f_col3:
    limit = st.slider("Record Limit:", min_value=10, max_value=200, value=50, step=10)
with f_col4:
    search_term = st.text_input("Search Text Snippet:", "", placeholder="Keyword...")

# Fetch records
records = db.get_history(limit=limit)

filtered = []
for r in records:
    if class_filter != "All" and r["classification"] != class_filter:
        continue
    if type_filter != "All" and r["input_type"] != type_filter:
        continue
    if search_term and search_term.lower() not in (r["input_text_snippet"] or "").lower():
        continue
    filtered.append(r)

st.markdown(f"**Found {len(filtered)} matching record(s)**:")

if filtered:
    df = pd.DataFrame(filtered)
    display_df = df[["analysis_id", "input_type", "classification", "risk_score", "action", "analysis_date", "input_text_snippet"]].copy()
    display_df.columns = ["ID", "Input Type", "Classification", "Risk Score", "Action", "Timestamp", "Snippet"]
    display_df["Timestamp"] = display_df["Timestamp"].apply(lambda x: str(x)[:19].replace("T", " "))

    st.dataframe(display_df, use_container_width=True, hide_index=True)

    # Download CSV
    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Export Audit History (CSV)",
        data=csv_bytes,
        file_name="rag_security_history.csv",
        mime="text/csv",
        help="Export current filtered view to CSV"
    )

    st.divider()

    # Granular Drilldown Inspector
    st.markdown("#### 🔎 Granular Record Inspector")
    selected_id = st.selectbox(
        "Select Record ID to Inspect Detailed Indicators:",
        options=[r["analysis_id"] for r in filtered],
        format_func=lambda x: f"Record #{x}"
    )

    if selected_id:
        target_rec = next((r for r in filtered if r["analysis_id"] == selected_id), None)
        if target_rec:
            st.markdown(f"##### Record #{selected_id} Summary")
            r_col1, r_col2 = st.columns([1, 1])
            with r_col1:
                st.write(f"- **Input Type**: `{target_rec['input_type']}`")
                st.write(f"- **Classification**: **{target_rec['classification']}**")
                st.write(f"- **Composite Risk Score**: `{target_rec['risk_score']:.1f} / 100`")
                st.write(f"- **Policy Action Enforced**: `{target_rec['action']}`")
                st.write(f"- **Audit Timestamp**: `{str(target_rec['analysis_date'])[:19].replace('T', ' ')}`")
            with r_col2:
                st.markdown("**Original Text Snippet:**")
                st.info(target_rec["input_text_snippet"] or "None recorded.")

            # Load child detection details
            details = db.get_analysis_details(selected_id)
            if details:
                st.markdown("##### Detailed Detection Indicators Fired:")
                df_det = pd.DataFrame(details)
                df_det_display = df_det[["method", "category", "indicator", "score"]].copy()
                df_det_display.columns = ["Method", "Category", "Detection Indicator Pattern", "Signal Score"]
                st.dataframe(df_det_display, use_container_width=True, hide_index=True)
            else:
                st.caption("No specific alert indicators fired (safe input).")
else:
    st.info("No audit records matching your current filter criteria.")
