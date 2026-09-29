"""
PrivacyGuard X - UI Styling & CSS Design Tokens
Custom aesthetics tailored for Snapdragon-powered HP PCs.
Modern, sleek dark obsidian theme with Snapdragon Crimson & HP Indigo accents.
"""

def get_custom_css(dark_mode: bool = True) -> str:
    """Returns responsive CSS for modern cybersecurity aesthetic."""
    if dark_mode:
        bg_primary = "#090d16"
        bg_secondary = "#111827"
        bg_card = "#161f30"
        border_color = "#243247"
        text_primary = "#f3f4f6"
        text_muted = "#94a3b8"
        accent_snapdragon = "#ff2a5f"
        accent_hp = "#0096d6"
    else:
        bg_primary = "#f8fafc"
        bg_secondary = "#ffffff"
        bg_card = "#ffffff"
        border_color = "#e2e8f0"
        text_primary = "#0f172a"
        text_muted = "#64748b"
        accent_snapdragon = "#e11d48"
        accent_hp = "#0284c7"

    return f"""
    <style>
        /* Modern Font and Root Settings */
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

        html, body, [class*="css"] {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
        }}

        code, pre, .mono-text {{
            font-family: 'JetBrains Mono', monospace !important;
        }}

        /* App Background */
        .stApp {{
            background-color: {bg_primary};
            color: {text_primary};
        }}

        /* Brand Header Hero Card */
        .brand-hero {{
            background: linear-gradient(135deg, rgba(22, 31, 48, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
            border: 1px solid {border_color};
            border-radius: 14px;
            padding: 24px 28px;
            margin-bottom: 24px;
            box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.35);
            position: relative;
            overflow: hidden;
        }}

        .brand-hero::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 5px;
            height: 100%;
            background: linear-gradient(180deg, {accent_snapdragon} 0%, {accent_hp} 100%);
        }}

        /* Metric Cards */
        .metric-card {{
            background: {bg_card};
            border: 1px solid {border_color};
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 12px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .metric-card:hover {{
            border-color: {accent_hp};
            transform: translateY(-2px);
        }}

        .metric-value {{
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.1;
        }}

        .metric-label {{
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: {text_muted};
            margin-top: 4px;
        }}

        /* Risk Badges */
        .risk-badge-high {{
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.4);
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
        }}

        .risk-badge-med {{
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.4);
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
        }}

        .risk-badge-low {{
            background: rgba(59, 130, 246, 0.15);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.4);
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
        }}

        .risk-badge-clean {{
            background: rgba(16, 185, 129, 0.15);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.4);
            padding: 4px 12px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.85rem;
            display: inline-block;
        }}

        /* Finding Card */
        .finding-card {{
            background: {bg_card};
            border-left: 4px solid {border_color};
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 14px;
            border-top: 1px solid {border_color};
            border-right: 1px solid {border_color};
            border-bottom: 1px solid {border_color};
        }}

        .finding-card-high {{
            border-left-color: #ef4444 !important;
        }}

        .finding-card-med {{
            border-left-color: #f59e0b !important;
        }}

        .finding-card-low {{
            border-left-color: #3b82f6 !important;
        }}

        /* Snapdragon Badge */
        .snapdragon-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(90deg, rgba(255, 42, 95, 0.15) 0%, rgba(0, 150, 214, 0.15) 100%);
            border: 1px solid rgba(255, 42, 95, 0.35);
            border-radius: 6px;
            padding: 3px 10px;
            font-size: 0.78rem;
            font-weight: 700;
            color: #ff4d79;
        }}

        /* Streamlit UI custom tweaks */
        div[data-testid="stSidebar"] {{
            background-color: {bg_secondary};
            border-right: 1px solid {border_color};
        }}

        .stButton>button {{
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s;
        }}
    </style>
    """
