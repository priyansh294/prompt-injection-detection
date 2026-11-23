"""
Streamlit Home Dashboard
Implements Page 1: Home Dashboard per SRS Section 14.1 & UI/UX Redesign SRS Section 6.1.
Displays project overview, live security metrics, risk score distributions,
attack category statistics, and recent scan logs using the unified dark design system.
"""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd
import plotly.express as px

from src.database.db import DatabaseManager
from app.ui_theme import inject_custom_css, render_header, apply_chart_theme

# Page Configuration
st.set_page_config(
    page_title="RAG Security Gateway — Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply global dark styling
inject_custom_css()

# Header
render_header(
    title="Prompt-Injection Detection Dashboard",
    subtitle="Multi-layered defense protecting Retrieval-Augmented Generation (RAG) pipelines from direct & indirect injection attacks.",
    icon="🛡️"
)

# Load Database Metrics
db = DatabaseManager()
db.init_db()
metrics = db.get_dashboard_metrics()
history = db.get_history(limit=25)

# Row 1: High-level KPI Metrics
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Scans", f"{metrics['total']:,}")
with col2:
    st.metric("Safe Inputs", f"{metrics['safe']:,}")
with col3:
    st.metric("Suspicious Inputs", f"{metrics['suspicious']:,}")
with col4:
    st.metric("Malicious Inputs", f"{metrics['malicious']:,}")
with col5:
    avg_score = round(sum(metrics["scores"]) / len(metrics["scores"]), 1) if metrics["scores"] else 0.0
    st.metric("Avg Risk Score", f"{avg_score} / 100")

st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

# Row 2: Charts (Threat Classes & Attack Categories)
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("#### 📊 Threat Class Distribution")
    if metrics["total"] > 0:
        class_df = pd.DataFrame({
            "Classification": ["Safe", "Suspicious", "Malicious"],
            "Count": [metrics["safe"], metrics["suspicious"], metrics["malicious"]]
        })
        fig_donut = px.pie(
            class_df,
            values="Count",
            names="Classification",
            color="Classification",
            color_discrete_map={"Safe": "#10B981", "Suspicious": "#F59E0B", "Malicious": "#EF4444"},
            hole=0.55
        )
        fig_donut = apply_chart_theme(fig_donut, height=290)
        fig_donut.update_traces(textposition='inside', textinfo='percent+label', marker=dict(line=dict(color='#111827', width=2)))
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.info("No scan records available yet. Run scans using Prompt Scanner or Document Scanner to populate charts.")

with chart_col2:
    st.markdown("#### 🎯 Detected Attack Categories")
    if metrics["categories"]:
        cat_df = pd.DataFrame(metrics["categories"])
        fig_cat = px.bar(
            cat_df,
            x="count",
            y="category",
            orientation="h",
            color="count",
            color_continuous_scale="Reds",
            labels={"count": "Detections", "category": "Category"},
        )
        fig_cat = apply_chart_theme(fig_cat, height=290)
        fig_cat.update_layout(coloraxis_showscale=False, yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_cat, use_container_width=True)
    else:
        st.info("No attack indicators logged yet.")

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

# Row 3: Risk Score Distribution & Detection Methods
row3_col1, row3_col2 = st.columns(2)

with row3_col1:
    st.markdown("#### 📈 Risk Score Histogram")
    if metrics["scores"]:
        score_df = pd.DataFrame({"Risk Score": metrics["scores"]})
        fig_hist = px.histogram(
            score_df,
            x="Risk Score",
            nbins=12,
            color_discrete_sequence=["#3B82F6"]
        )
        fig_hist.add_vline(x=29.0, line_dash="dash", line_color="#10B981", annotation_text="Low Max (29)", annotation_position="top left")
        fig_hist.add_vline(x=60.0, line_dash="dash", line_color="#EF4444", annotation_text="High Min (60)", annotation_position="top right")
        fig_hist = apply_chart_theme(fig_hist, height=270)
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("No risk score distribution data available.")

with row3_col2:
    st.markdown("#### ⚙️ Invocations by Detection Method")
    if metrics["methods"]:
        m_df = pd.DataFrame(metrics["methods"])
        fig_methods = px.bar(
            m_df,
            x="method",
            y="count",
            color="method",
            color_discrete_sequence=["#8B5CF6", "#EC4899", "#3B82F6", "#10B981"],
            labels={"count": "Invocations", "method": "Method"}
        )
        fig_methods = apply_chart_theme(fig_methods, height=270)
        fig_methods.update_layout(showlegend=False)
        st.plotly_chart(fig_methods, use_container_width=True)
    else:
        st.info("No detection method statistics available.")

st.divider()

# Row 4: Recent Analysis Records
st.markdown("#### 🕒 Recent Analysis Records")
if history:
    hist_table = []
    for h in history[:10]:
        hist_table.append({
            "ID": f"#{h['analysis_id']}",
            "Input Type": h["input_type"],
            "Classification": h["classification"],
            "Risk Score": f"{h['risk_score']:.1f}",
            "Policy Action": h["action"],
            "Timestamp": h["analysis_date"][:19].replace("T", " "),
            "Text Snippet": (h["input_text_snippet"] or "")[:75] + ("..." if len(h["input_text_snippet"] or "") > 75 else "")
        })
    df_hist = pd.DataFrame(hist_table)
    st.dataframe(df_hist, use_container_width=True, hide_index=True)
else:
    st.info("No analysis records in database.")
