"""
PrivacyGuard X - Authentication UI Layer
Provides Sign Up page with "Already have an account? Log In" navigation at the bottom,
and matching Log In page with "Don't have an account? Sign Up" navigation.
Uses local PBKDF2 HMAC-SHA256 password hashing stored in SQLite.
"""

import streamlit as st
try:
    from database import create_user, authenticate_user
except ImportError:
    from database.database import create_user, authenticate_user


def render_auth_page():
    """Renders either Sign Up or Log In page based on session state."""
    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "signup"  # Default to Sign Up page as requested

    auth_mode = st.session_state.auth_mode

    # Outer Centered Card Container
    col_left, col_center, col_right = st.columns([1, 2.2, 1])

    with col_center:
        if auth_mode == "signup":
            render_signup_view()
        else:
            render_login_view()


def render_signup_view():
    """Renders the Sign Up page with 'Already have an account? Log In' at the bottom."""
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(22, 31, 48, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); border: 1px solid #243247; border-top: 4px solid #ff2a5f; border-radius: 14px; padding: 28px 32px; box-shadow: 0 10px 30px -5px rgba(0,0,0,0.5);">
        <div style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 2.5rem; margin-bottom: 6px;">🛡️</div>
            <h2 style="margin: 0; font-size: 1.8rem; font-weight: 800; letter-spacing: -0.02em;">
                Create Your Account
            </h2>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                Join PrivacyGuard <span style="color: #ff2a5f; font-weight: 700;">X</span> — On-Device Digital Safety Copilot
            </p>
            <div style="margin-top: 10px;">
                <span class="snapdragon-badge">⚡ Snapdragon X Elite Local Protection</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")

    with st.form("signup_form", clear_on_submit=False):
        full_name = st.text_input("Full Name (Optional)", placeholder="e.g. Subaharini", key="su_fullname")
        username = st.text_input("Username *", placeholder="e.g. subaharini", key="su_username").strip().lower()
        email = st.text_input("Email Address *", placeholder="e.g. user@hp-snapdragon.com", key="su_email").strip().lower()
        
        c_pw1, c_pw2 = st.columns(2)
        with c_pw1:
            password = st.text_input("Password *", type="password", placeholder="Min 6 characters", key="su_pwd")
        with c_pw2:
            confirm_pwd = st.text_input("Confirm Password *", type="password", placeholder="Repeat password", key="su_confirm_pwd")

        agree_terms = st.checkbox(
            "I agree to on-device zero-knowledge analysis (No data is transmitted to external cloud APIs)",
            value=True,
            key="su_agree"
        )

        st.write("")
        submit_signup = st.form_submit_button("🚀 Create Account", type="primary", use_container_width=True)

    if submit_signup:
        if not username:
            st.error("⚠️ Please choose a username.")
        elif not email or "@" not in email:
            st.error("⚠️ Please enter a valid email address.")
        elif len(password) < 6:
            st.error("⚠️ Password must be at least 6 characters long.")
        elif password != confirm_pwd:
            st.error("⚠️ Passwords do not match. Please re-enter.")
        elif not agree_terms:
            st.warning("⚠️ Please accept the on-device privacy terms to proceed.")
        else:
            success, msg = create_user(
                username=username,
                email=email,
                password=password,
                full_name=full_name
            )
            if success:
                st.success(f"✅ {msg}")
                # Automatically log in the newly registered user
                ok_auth, user_obj, _ = authenticate_user(username, password)
                if ok_auth:
                    st.session_state.authenticated = True
                    st.session_state.current_user = user_obj
                    st.session_state.current_page = "Dashboard"
                    st.balloons()
                    st.rerun()
            else:
                st.error(f"⚠️ {msg}")

    # ==========================================
    # BOTTOM NAVIGATION: ALREADY HAVE AN ACCOUNT?
    # ==========================================
    st.write("")
    st.markdown("""
    <div style="text-align: center; margin: 18px 0 10px 0; border-top: 1px solid #243247; padding-top: 18px;">
        <span style="color: #94a3b8; font-size: 0.95rem;">Already have an account?</span>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🔑 Log In Here", use_container_width=True, key="btn_goto_login"):
        st.session_state.auth_mode = "login"
        st.rerun()

    # Guest exploration option
    st.write("")
    if st.button("🌐 Continue as Guest / Tester", use_container_width=True, key="btn_guest_explore"):
        st.session_state.authenticated = True
        st.session_state.current_user = {
            "username": "guest_tester",
            "email": "guest@snapdragon-hp.internal",
            "full_name": "Guest Tester"
        }
        st.session_state.current_page = "Dashboard"
        st.rerun()


def render_login_view():
    """Renders the Log In page with 'Don't have an account? Sign Up' at the bottom."""
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(22, 31, 48, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); border: 1px solid #243247; border-top: 4px solid #0096d6; border-radius: 14px; padding: 28px 32px; box-shadow: 0 10px 30px -5px rgba(0,0,0,0.5);">
        <div style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 2.5rem; margin-bottom: 6px;">🔐</div>
            <h2 style="margin: 0; font-size: 1.8rem; font-weight: 800; letter-spacing: -0.02em;">
                Welcome Back
            </h2>
            <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                Log in to PrivacyGuard <span style="color: #ff2a5f; font-weight: 700;">X</span>
            </p>
            <div style="margin-top: 10px;">
                <span class="snapdragon-badge">⚡ On-Device Zero-Knowledge Security</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")

    with st.form("login_form", clear_on_submit=False):
        identifier = st.text_input("Username or Email Address", placeholder="Enter username or email", key="li_identifier").strip().lower()
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="li_pwd")
        
        st.write("")
        submit_login = st.form_submit_button("🔐 Log In", type="primary", use_container_width=True)

    if submit_login:
        if not identifier or not password:
            st.error("⚠️ Please fill in both your username/email and password.")
        else:
            success, user_obj, msg = authenticate_user(identifier, password)
            if success:
                st.session_state.authenticated = True
                st.session_state.current_user = user_obj
                st.session_state.current_page = "Dashboard"
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error(f"⚠️ {msg}")

    # ==========================================
    # BOTTOM NAVIGATION: DON'T HAVE AN ACCOUNT?
    # ==========================================
    st.write("")
    st.markdown("""
    <div style="text-align: center; margin: 18px 0 10px 0; border-top: 1px solid #243247; padding-top: 18px;">
        <span style="color: #94a3b8; font-size: 0.95rem;">Don't have an account?</span>
    </div>
    """, unsafe_allow_html=True)

    if st.button("📝 Create New Account (Sign Up)", use_container_width=True, key="btn_goto_signup"):
        st.session_state.auth_mode = "signup"
        st.rerun()

    # Quick demo account sign in
    st.write("")
    if st.button("🧪 Quick Demo Sign In (Tester Account)", use_container_width=True, key="btn_demo_signin"):
        # Auto-create demo user if not present
        create_user(
            username="snapdragon_demo",
            email="demo@hp-pc.ai",
            password="DemoPassword2026!",
            full_name="Snapdragon Demo User"
        )
        ok_auth, demo_user, _ = authenticate_user("snapdragon_demo", "DemoPassword2026!")
        if ok_auth:
            st.session_state.authenticated = True
            st.session_state.current_user = demo_user
            st.session_state.current_page = "Dashboard"
            st.rerun()
