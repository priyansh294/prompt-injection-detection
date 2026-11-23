"""
Shared UI Theme and Design System for Streamlit Web Application
Implements Section 5 of the UI/UX Redesign SRS:
- Dark theme color tokens (Near-black canvas, slate surfaces, coral/red accents, green/amber status)
- Reusable CSS injection for consistent typography, cards, badges, and interaction states
- Plotly dark theme chart standardizer
"""

import streamlit as st
import plotly.graph_objects as go

# Design System Color Tokens
THEME_COLORS = {
    "canvas_bg": "#0B0F19",
    "surface_bg": "#161E2E",
    "surface_elevated": "#1F2937",
    "border_subtle": "#374151",
    "border_focus": "#60A5FA",
    "primary_red": "#EF4444",
    "accent_blue": "#3B82F6",
    "status_safe": "#10B981",
    "status_suspicious": "#F59E0B",
    "status_malicious": "#EF4444",
    "text_primary": "#F9FAFB",
    "text_secondary": "#9CA3AF",
    "text_muted": "#6B7280",
}

CUSTOM_CSS = """
<style>
    /* Google Fonts Inter */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Container Spacing & Layout */
    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        padding-left: 2rem;
        padding-right: 2rem;
        max-width: 1400px;
    }

    /* Card Containers */
    .sec-card {
        background: #161E2E;
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 18px 22px;
        margin-bottom: 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25), 0 2px 4px -1px rgba(0, 0, 0, 0.15);
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .sec-card:hover {
        border-color: #4B5563;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.35);
    }

    /* Highlight Banner Card */
    .sec-banner {
        border-radius: 10px;
        padding: 14px 18px;
        margin: 12px 0 18px 0;
        display: flex;
        align-items: center;
        gap: 12px;
        font-weight: 500;
    }
    .banner-safe {
        background-color: rgba(16, 185, 129, 0.12);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34D399;
    }
    .banner-suspicious {
        background-color: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.35);
        color: #FBBF24;
    }
    .banner-malicious {
        background-color: rgba(239, 68, 68, 0.14);
        border: 1px solid rgba(239, 68, 68, 0.4);
        color: #F87171;
    }

    /* Status Badges */
    .status-badge {
        display: inline-block;
        padding: 3px 10px;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        border-radius: 20px;
        line-height: 1.4;
    }
    .badge-safe {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid #10B981;
    }
    .badge-suspicious {
        background: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid #F59E0B;
    }
    .badge-malicious {
        background: rgba(239, 68, 68, 0.18);
        color: #F87171;
        border: 1px solid #EF4444;
    }

    /* Metric Tiles */
    [data-testid="stMetric"] {
        background: #161E2E;
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 12px 16px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.85rem !important;
        color: #9CA3AF !important;
        font-weight: 500 !important;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        color: #F9FAFB !important;
        font-feature-settings: "tnum" 1;
    }

    /* Primary Buttons */
    button[kind="primary"] {
        background-color: #EF4444 !important;
        border: none !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        transition: transform 0.1s ease, background-color 0.2s ease !important;
    }
    button[kind="primary"]:hover {
        background-color: #DC2626 !important;
        transform: translateY(-1px);
    }
    button[kind="secondary"] {
        background-color: #1F2937 !important;
        border: 1px solid #4B5563 !important;
        color: #E5E7EB !important;
        font-weight: 500 !important;
        border-radius: 8px !important;
        transition: border-color 0.2s ease, background-color 0.2s ease !important;
    }
    button[kind="secondary"]:hover {
        border-color: #9CA3AF !important;
        background-color: #2D3748 !important;
    }

    /* Text Areas & Inputs */
    [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input {
        background-color: #1F2937 !important;
        border: 1px solid #374151 !important;
        color: #F9FAFB !important;
        border-radius: 8px !important;
        font-size: 0.95rem !important;
    }
    [data-testid="stTextArea"] textarea:focus, [data-testid="stTextInput"] input:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 1px #3B82F6 !important;
    }

    /* Pipeline Step Breadcrumb */
    .pipeline-tracker {
        display: flex;
        gap: 12px;
        align-items: center;
        background: #161E2E;
        border: 1px solid #374151;
        padding: 12px 18px;
        border-radius: 10px;
        margin-bottom: 20px;
        overflow-x: auto;
    }
    .pipe-step {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        color: #9CA3AF;
    }
    .pipe-step.active {
        color: #60A5FA;
    }
    .pipe-step.done {
        color: #34D399;
    }
    .pipe-step.blocked {
        color: #F87171;
    }
    .pipe-sep {
        color: #4B5563;
        font-size: 0.8rem;
    }
</style>
"""


def inject_custom_css():
    """Injects unified custom stylesheet into the active Streamlit turn."""
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def render_header(title: str, subtitle: str, icon: str = "🛡️"):
    """Renders a visually prominent, consistent page header."""
    st.markdown(f"""
    <div style="margin-bottom: 22px;">
        <h1 style="display: flex; align-items: center; gap: 12px; font-size: 1.95rem; font-weight: 700; color: #F9FAFB; margin-bottom: 6px;">
            <span>{icon}</span> {title}
        </h1>
        <p style="font-size: 0.95rem; color: #9CA3AF; margin: 0; line-height: 1.5;">
            {subtitle}
        </p>
    </div>
    """, unsafe_allow_html=True)


def render_status_pill(classification: str) -> str:
    """Returns HTML for a high-contrast classification pill badge."""
    cls_lower = classification.lower()
    if cls_lower == "safe":
        return f'<span class="status-badge badge-safe">✓ {classification.upper()}</span>'
    elif cls_lower == "suspicious":
        return f'<span class="status-badge badge-suspicious">⚠ {classification.upper()}</span>'
    else:
        return f'<span class="status-badge badge-malicious">🛑 {classification.upper()}</span>'


def apply_chart_theme(fig: go.Figure, height: int = 300) -> go.Figure:
    """Applies unified dark cybersecurity theme to any Plotly figure."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(22, 30, 46, 0.6)",
        plot_bgcolor="rgba(22, 30, 46, 0.6)",
        font=dict(family="Inter, sans-serif", color="#D1D5DB", size=12),
        margin=dict(t=30, b=30, l=30, r=30),
        height=height,
        xaxis=dict(
            gridcolor="#2D3748",
            zerolinecolor="#2D3748",
            showline=True,
            linecolor="#374151"
        ),
        yaxis=dict(
            gridcolor="#2D3748",
            zerolinecolor="#2D3748",
            showline=True,
            linecolor="#374151"
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            bordercolor="rgba(0,0,0,0)",
            font=dict(size=11, color="#9CA3AF")
        )
    )
    return fig
