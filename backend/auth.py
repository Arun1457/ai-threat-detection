# auth.py
# AI-Driven Unified Threat Detection Platform
# Login / logout for Streamlit dashboard

import streamlit as st

# ─────────────────────────────────────────────
# User credentials — add your team here
# ─────────────────────────────────────────────
USERS = {
    "Arun":    "1457",
    "Mrunali": "2004",
    "Dina":    "0000",
    "Pranjal": "1234",
    "admin":   "admin",
}

def login():
    st.markdown("""
    <div style='text-align:center; padding: 40px 0 10px 0'>
        <span style='font-size:48px'>🛡️</span>
        <h2 style='margin:8px 0 4px 0'>AI Threat Detection Platform</h2>
        <p style='color:var(--color-text-secondary); font-size:14px'>
            Unified SIEM + SOAR | CICIDS Dataset
        </p>
    </div>
    """, unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]   # centre the form

    with col:
        st.markdown("#### Sign in")
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")

        if st.button("Login", use_container_width=True):
            if username in USERS and USERS[username] == password:
                st.session_state["logged_in"] = True
                st.session_state["user"]       = username
                st.rerun()
            else:
                st.error("Invalid username or password")

        st.markdown(
            "<p style='text-align:center;font-size:12px;"
            "color:var(--color-text-secondary);margin-top:16px'>"
            "Konkan Gyanpeeth College of Engineering · Major Project 2024-25"
            "</p>",
            unsafe_allow_html=True
        )

def logout():
    st.session_state["logged_in"] = False
    st.session_state["user"]      = None
