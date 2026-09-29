"""
PrivacyGuard X - Reports & Analytics Page
Complete report dashboard backed exclusively by real SQLite database scan metrics.
Includes dynamic charts for risk levels, content categories, and recent activity.
Displays clean empty state when no scans exist. No fake numbers.
"""

import streamlit as st
import pandas as pd
import altair as alt
from database.database import get_metrics, get_recent_scans


def render_reports():
    """Renders the analytics and audit reporting dashboard."""
    metrics = get_metrics()
    recent = get_recent_scans(limit=25)

    st.markdown("## 📊 Reports & Analytics Dashboard")
    st.caption("Live statistical insights and exposure trends derived from real on-device scans.")

    total_scans = metrics["total_scans"]

    if total_scans == 0:
        st.markdown("""
        <div style="background: #161f30; border: 1px dashed #243247; border-radius: 12px; padding: 48px 24px; text-align: center; margin: 30px 0;">
            <div style="font-size: 3rem; margin-bottom: 12px;">📈</div>
            <h3 style="color: #94a3b8; margin: 0;">No scan history yet.</h3>
            <p style="color: #64748b; font-size: 0.95rem; margin-top: 6px;">
                Perform an Image, Document, Text, or Code scan in the Scan Center to populate real-time analytics.
            </p>
        </div>
        """, unsafe_allow_html=True)
        return

    # Metric Cards Row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #38bdf8;">{total_scans:,}</div>
            <div class="metric-label">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)

    with m_col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #f59e0b;">{metrics['total_findings']:,}</div>
            <div class="metric-label">Total Findings</div>
        </div>
        """, unsafe_allow_html=True)

    with m_col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ef4444;">{metrics['high_risk_findings']:,}</div>
            <div class="metric-label">High-Risk (Secrets)</div>
        </div>
        """, unsafe_allow_html=True)

    with m_col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #f59e0b;">{metrics['medium_risk_findings']:,}</div>
            <div class="metric-label">Medium-Risk (PII)</div>
        </div>
        """, unsafe_allow_html=True)

    with m_col5:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #10b981;">{metrics['low_risk_findings']:,}</div>
            <div class="metric-label">Low-Risk</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    st.markdown("---")

    # Real Charts Section
    ch_col1, ch_col2 = st.columns(2)

    with ch_col1:
        st.subheader("🥧 Risk Severity Distribution")
        risk_data = metrics.get("scans_by_risk", {})
        if risk_data:
            df_risk = pd.DataFrame([
                {"Risk Level": k, "Count": v}
                for k, v in risk_data.items()
            ])
            # Color map
            color_scale = alt.Scale(
                domain=["HIGH", "MEDIUM", "LOW", "CLEAN"],
                range=["#ef4444", "#f59e0b", "#3b82f6", "#10b981"]
            )
            chart_pie = alt.Chart(df_risk).mark_arc(innerRadius=45).encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Risk Level", type="nominal", scale=color_scale),
                tooltip=["Risk Level", "Count"]
            ).properties(height=260)
            st.altair_chart(chart_pie, use_container_width=True)
        else:
            st.info("No risk distribution data available.")

    with ch_col2:
        st.subheader("📂 Scans by Content Modality")
        type_data = metrics.get("scans_by_type", {})
        if type_data:
            df_type = pd.DataFrame([
                {"Modality": k.capitalize(), "Scans": v}
                for k, v in type_data.items()
            ])
            chart_bar = alt.Chart(df_type).mark_bar(cornerRadius=6, color="#0096d6").encode(
                x=alt.X("Modality:N", sort="-y"),
                y=alt.Y("Scans:Q"),
                tooltip=["Modality", "Scans"]
            ).properties(height=260)
            st.altair_chart(chart_bar, use_container_width=True)
        else:
            st.info("No modality data available.")

    st.write("")
    st.markdown("---")

    # Category Breakdown
    st.subheader("🏷️ Findings Breakdown by Category")
    cat_counts = metrics.get("category_counts", {})
    if cat_counts:
        df_cat = pd.DataFrame([
            {"Category": k, "Detections": v}
            for k, v in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        ])
        cat_chart = alt.Chart(df_cat).mark_bar(cornerRadius=6, color="#ff2a5f").encode(
            x=alt.X("Detections:Q"),
            y=alt.Y("Category:N", sort="-x"),
            tooltip=["Category", "Detections"]
        ).properties(height=max(200, len(df_cat) * 32))
        st.altair_chart(cat_chart, use_container_width=True)
    else:
        st.info("No specific finding categories recorded yet.")

    st.write("")
    st.markdown("---")

    # Recent Activity Audit Table
    st.subheader("🕒 Full Scan Activity Log")
    rows = []
    for s in recent:
        rows.append({
            "Scan ID": s["scan_id"],
            "Timestamp": s["timestamp"][:19].replace("T", " "),
            "Target Name": s["file_name"],
            "Type": s["file_type"].upper(),
            "Score": f"{s['risk_score']}/100",
            "Risk Level": s["risk_level"],
            "Findings": s["findings_count"],
            "Action Taken": s["action_taken"]
        })
    st.dataframe(rows, use_container_width=True)
