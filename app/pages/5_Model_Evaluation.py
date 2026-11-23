"""
Streamlit Page 6: Model Evaluation & Benchmarks
Implements FR-15 (Evaluation Module), SRS Section 16, and UI/UX Redesign SRS Section 6.6.
Visualizes Accuracy, Precision, Recall, F1-score, and Confusion Matrices across models.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.figure_factory as ff

from src.detectors.ml_classifier import MLPromptClassifier
from src.database.db import DatabaseManager
from config.settings import SEED_DATASET_PATH
from app.ui_theme import inject_custom_css, render_header, apply_chart_theme

st.set_page_config(
    page_title="Model Evaluation — RAG Security",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_custom_css()

render_header(
    title="Model Evaluation & Benchmark Comparison",
    subtitle="Evaluate detection performance across Accuracy, Precision, Recall, and F1-score using standard test splits and confusion matrix heatmaps.",
    icon="📊"
)

db = DatabaseManager()
db.init_db()

evaluations = db.get_evaluations()

# Benchmark Table
st.markdown("#### 🏆 Saved Model Benchmarks")
if evaluations:
    eval_df = pd.DataFrame(evaluations)
    eval_display = eval_df[["model_name", "accuracy", "precision", "recall", "f1_score", "test_date"]].copy()
    eval_display.columns = ["Model Identifier", "Accuracy", "Precision", "Recall", "F1-Score", "Evaluation Timestamp"]
    eval_display["Evaluation Timestamp"] = eval_display["Evaluation Timestamp"].apply(lambda x: str(x)[:19].replace("T", " "))
    
    st.dataframe(
        eval_display.style.format({
            "Accuracy": "{:.2%}",
            "Precision": "{:.2%}",
            "Recall": "{:.2%}",
            "F1-Score": "{:.2%}"
        }),
        use_container_width=True,
        hide_index=True
    )

    # Comparative Grouped Bar Chart
    chart_df = eval_display.melt(
        id_vars=["Model Identifier"],
        value_vars=["Accuracy", "Precision", "Recall", "F1-Score"],
        var_name="Metric",
        value_name="Score"
    )
    fig_comp = px.bar(
        chart_df,
        x="Metric",
        y="Score",
        color="Model Identifier",
        barmode="group",
        text_auto=".1%",
        range_y=[0.0, 1.05],
        color_discrete_sequence=["#3B82F6", "#8B5CF6", "#10B981"]
    )
    fig_comp = apply_chart_theme(fig_comp, height=320)
    st.plotly_chart(fig_comp, use_container_width=True)
else:
    st.info("No saved model evaluation records found in database.")

st.divider()

# Interactive Train & Evaluation Card
st.markdown("#### 🔄 Interactive Model Evaluation on Dataset")
st.caption("Train a fresh TF-IDF vectorizer and classifier on `seed_dataset.csv` with a stratified 80/20 train/test split.")

with st.container():
    c_box1, c_box2 = st.columns([2, 1])
    with c_box1:
        clf_type = st.selectbox(
            "Select Classifier Algorithm to Benchmark:",
            ["logistic_regression", "linear_svm"],
            format_func=lambda x: "Logistic Regression (TF-IDF + L-BFGS)" if x == "logistic_regression" else "Linear SVM (TF-IDF + Calibrated CV)"
        )
    with c_box2:
        st.write("")
        st.write("")
        train_eval_btn = st.button("🚀 Train & Evaluate on Test Split", type="primary", use_container_width=True)

if train_eval_btn:
    with st.spinner("Training model strictly on training split and predicting on unseen test split..."):
        clf = MLPromptClassifier(auto_load=False)
        metrics_dict = clf.train_and_evaluate(
            dataset_path=SEED_DATASET_PATH,
            classifier_type=clf_type,
            save_after_training=True
        )

        model_display_name = f"Model: TF-IDF + {'Logistic Regression' if clf_type == 'logistic_regression' else 'Linear SVM'}"
        db.save_evaluation(
            model_name=model_display_name,
            accuracy=metrics_dict["accuracy"],
            precision=metrics_dict["precision"],
            recall=metrics_dict["recall"],
            f1_score=metrics_dict["f1_score"]
        )

    st.success(f"Evaluation Complete for **{model_display_name}** ({metrics_dict['test_samples']} test samples evaluated).")

    # Metric Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("Test Accuracy", f"{metrics_dict['accuracy']:.2%}")
    with k2:
        st.metric("Weighted Precision", f"{metrics_dict['precision']:.2%}")
    with k3:
        st.metric("Weighted Recall", f"{metrics_dict['recall']:.2%}")
    with k4:
        st.metric("Weighted F1-Score", f"{metrics_dict['f1_score']:.2%}")

    # Confusion Matrix Visualization
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    st.markdown("##### 🔲 Multi-Class Confusion Matrix (Safe vs Suspicious vs Malicious)")
    labels = metrics_dict["labels"]
    cm = metrics_dict["confusion_matrix"]

    fig_cm = ff.create_annotated_heatmap(
        z=cm,
        x=[f"Pred {lbl}" for lbl in labels],
        y=[f"True {lbl}" for lbl in labels],
        colorscale="Blues",
        showscale=True
    )
    fig_cm = apply_chart_theme(fig_cm, height=330)
    fig_cm.update_layout(xaxis=dict(side="bottom"))
    st.plotly_chart(fig_cm, use_container_width=True)

    st.caption("A confusion matrix details true positives, false positives, and false negatives across classes to ensure balanced threat detection.")
