"""
PrivacyGuard X - Scan History Page
Detailed inspection of past scans, finding metadata (without raw secret exposure),
and record management (single deletion and bulk wipe).
"""

import json
import streamlit as st
from database.database import get_recent_scans, delete_scan, clear_all_scans


def render_history():
    """Renders the Scan History management page."""
    st.markdown("## 🕒 Scan History Audit Trail")
    st.caption("Inspect past scan metadata. Raw credentials and document contents are never retained.")

    scans = get_recent_scans(limit=50)

    if not scans:
        st.info("No scan history found. Perform a scan in the Scan Center to generate records.")
        return

    top_c1, top_c2 = st.columns([3, 1])
    with top_c2:
        if st.button("🗑️ Clear All History", type="secondary", use_container_width=True):
            clear_all_scans()
            st.success("All scan history records purged.")
            st.rerun()

    st.write("")

    for s in scans:
        scan_id = s["scan_id"]
        level = s["risk_level"]
        badge_class = (
            "risk-badge-high" if level == "HIGH"
            else "risk-badge-med" if level == "MEDIUM"
            else "risk-badge-low" if level == "LOW"
            else "risk-badge-clean"
        )

        with st.expander(f"{s['file_type'].upper()}: {s['file_name']} — {s['timestamp'][:19].replace('T', ' ')} ({level} RISK)"):
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"**Scan ID:** `{scan_id}`")
                st.markdown(f"**Scan Type:** {s['scan_type']}")
            with c2:
                st.markdown(f"**Risk Level:** <span class='{badge_class}'>{level}</span>", unsafe_allow_html=True)
                st.markdown(f"**Risk Score:** {s['risk_score']}/100")
            with c3:
                st.markdown(f"**Findings Count:** {s['findings_count']}")
                st.markdown(f"**Action Taken:** {s['action_taken']}")
            with c4:
                if st.button("Delete Entry", key=f"del_{scan_id}", use_container_width=True):
                    delete_scan(scan_id)
                    st.success(f"Deleted scan {scan_id}")
                    st.rerun()

            if s.get("summary_reasons"):
                st.markdown("**Observations & Reasons:**")
                st.write(s["summary_reasons"])

            # Render sanitized findings list if present
            try:
                details = json.loads(s.get("details_json", "[]"))
                if details:
                    st.markdown("**Sanitized Findings List:**")
                    for idx, item in enumerate(details, start=1):
                        st.markdown(
                            f"- #{idx} **{item.get('category')}** ({item.get('risk_level')} Risk) at `{item.get('location')}`: "
                            f"`{item.get('masked_text') or item.get('matched_snippet')}` — *{item.get('recommended_action', '')}*"
                        )
            except Exception:
                pass
