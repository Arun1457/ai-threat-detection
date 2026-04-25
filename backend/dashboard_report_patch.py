# ─────────────────────────────────────────────────────────────────────────────
# ADD THIS TO dashboard.py
# ─────────────────────────────────────────────────────────────────────────────

# STEP 1 — Add this import at the top of dashboard.py with other imports:
from generate_report import generate_pdf_report

# STEP 2 — Add this block inside the "📊 Dashboard" page section,
#           just before the final st.markdown("---") footer line:

st.markdown("---")
st.markdown("#### 📄 Generate Threat Report")

col_r1, col_r2 = st.columns([2, 1])
with col_r1:
    st.write("Export a full PDF report with KPIs, severity breakdown, attack analysis and SOAR summary.")
with col_r2:
    if st.button("📥 Generate PDF Report", use_container_width=True):
        with st.spinner("Generating PDF report ..."):
            try:
                report_path = generate_pdf_report(data=filtered)
                # Read the file and offer download
                with open(report_path, "rb") as f:
                    pdf_bytes = f.read()
                st.download_button(
                    label="⬇️ Download Report PDF",
                    data=pdf_bytes,
                    file_name=f"threat_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
                st.success(f"✅ Report ready!")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
