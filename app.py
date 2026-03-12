"""ProShield-AI — Streamlit Cyber Defense Dashboard."""

import pandas as pd
import streamlit as st

import database
from cti_mapper import map_events_to_mitre
from detector import detect_anomalies
from log_loader import load_logs
from predictor import predict_next_step
from report_generator import build_report, generate_report, report_to_markdown

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ProShield-AI Cyber Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ ProShield-AI Cyber Defense Dashboard")
st.caption("AI-powered log analysis · anomaly detection · MITRE ATT&CK mapping")
st.divider()

# ── Sidebar controls ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    log_path = st.text_input("Log file path", value="data/sample_logs.json")
    save_logs_to_db = st.checkbox("Save loaded logs to MongoDB", value=True)
    save_report_to_db = st.checkbox("Save incident report to MongoDB", value=True)
    st.divider()
    st.info("Click **Load Logs** to start the analysis pipeline.")

# ── Session state — keeps results across Streamlit reruns ─────────────────────
if "report" not in st.session_state:
    st.session_state.report = None
if "logs" not in st.session_state:
    st.session_state.logs = []
if "db_log_save_count" not in st.session_state:
    st.session_state.db_log_save_count = 0
if "db_log_save_failed" not in st.session_state:
    st.session_state.db_log_save_failed = 0

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Load Logs
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("① Load Logs")

if st.button("📂 Load Logs", use_container_width=True):
    loaded_logs = load_logs(log_path)
    if not loaded_logs:
        st.warning("No valid logs loaded. Check the file path and JSON structure.")
        st.stop()

    saved_count = 0
    failed_count = 0
    if save_logs_to_db:
        if database.connect():
            for log in loaded_logs:
                if database.save_log(log):
                    saved_count += 1
                else:
                    failed_count += 1
        else:
            failed_count = len(loaded_logs)
            st.warning("MongoDB connection failed. Continuing analysis without saving logs.")

    # Run the full pipeline and cache results in session state
    all_events = detect_anomalies(loaded_logs)
    suspicious   = [e for e in all_events if e.get("label") == "suspicious"]
    predictions  = [predict_next_step(e.get("activity_type", "")) for e in suspicious]
    mitre        = map_events_to_mitre(suspicious)
    report       = build_report(loaded_logs, suspicious, predictions, mitre)
    report["event_reports"] = [
        generate_report(event, prediction, mitre_info)
        for event, prediction, mitre_info in zip(suspicious, predictions, mitre)
    ]

    st.session_state.logs = all_events   # enriched with label + anomaly_score
    st.session_state.report = report
    st.session_state.db_log_save_count = saved_count
    st.session_state.db_log_save_failed = failed_count
    st.success(f"✅ Loaded **{len(loaded_logs)}** log(s) — **{len(suspicious)}** suspicious event(s) detected.")

# Nothing to show until logs are loaded
if not st.session_state.report:
    st.info("No analysis run yet. Enter a log file path and click **Load Logs**.")
    st.stop()

report = st.session_state.report
logs   = st.session_state.logs

# ── Summary metrics ───────────────────────────────────────────────────────────
c1, c2, c3 = st.columns(3)
c1.metric("Total Logs",        report["summary"]["total_logs"])
c2.metric("Suspicious Events", report["summary"]["suspicious_events"])
c3.metric("Normal Events",
          report["summary"]["total_logs"] - report["summary"]["suspicious_events"])

if save_logs_to_db:
    s1, s2 = st.columns(2)
    s1.metric("Logs Saved To MongoDB", st.session_state.db_log_save_count)
    s2.metric("Log Save Failures", st.session_state.db_log_save_failed)
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — Log Table
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("② All Log Events")

log_df = pd.DataFrame(logs)
# Highlight suspicious rows with a simple colour map on the label column
def _colour_label(val: str) -> str:
    return "background-color: #ff4b4b; color: white;" if val == "suspicious" else ""

display_cols = [c for c in
    ["timestamp", "source_ip", "destination_ip", "activity_type",
     "bytes_transferred", "label", "anomaly_score"]
    if c in log_df.columns]

st.dataframe(
    log_df[display_cols].style.applymap(_colour_label, subset=["label"] if "label" in display_cols else []),
    use_container_width=True,
    hide_index=True,
)
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — Anomaly Detection Results
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("③ Anomaly Detection Results")

if report["suspicious_events"]:
    anom_df = pd.DataFrame(report["suspicious_events"])
    anom_cols = [c for c in
        ["timestamp", "source_ip", "destination_ip", "activity_type",
         "bytes_transferred", "anomaly_score"]
        if c in anom_df.columns]
    st.dataframe(anom_df[anom_cols], use_container_width=True, hide_index=True)
else:
    st.success("No anomalies detected in the loaded logs.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — Predicted Next Attacker Action
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("④ Predicted Next Attacker Action")

if report["predictions"]:
    pred_rows = [
        {
            "Observed Activity": p["activity_type"],
            "Predicted Next Step": p["predicted_next"] or "Unknown",
            "Mapped": "✅" if p["known"] else "❓",
        }
        for p in report["predictions"]
    ]
    st.table(pd.DataFrame(pred_rows))
else:
    st.info("No predictions — no suspicious events were found.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5 — MITRE Tactic Mapping
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑤ MITRE ATT&CK Tactic Mapping")

if report["mitre_techniques"]:
    mitre_rows = [
        {
            "Activity":       m.get("activity_type", "—"),
            "Technique ID":   m.get("technique_id", "Unknown"),
            "Technique Name": m.get("technique_name", "Unknown"),
            "Tactic":         m.get("tactic", "Unknown"),
        }
        for m in report["mitre_techniques"]
    ]
    st.table(pd.DataFrame(mitre_rows))
else:
    st.info("No MITRE mappings — no suspicious events were found.")
st.divider()

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Generate Incident Report
# ═════════════════════════════════════════════════════════════════════════════
st.subheader("⑥ Generate Incident Report")

if st.button("📄 Generate Incident Report", use_container_width=True):
    if report.get("event_reports"):
        for i, text_report in enumerate(report["event_reports"], start=1):
            with st.expander(f"Event {i} — {report['suspicious_events'][i - 1].get('activity_type', '')}"):
                st.code(text_report, language=None)
    else:
        st.info("No individual event reports — no suspicious events detected.")

    markdown_report = report_to_markdown(report)
    st.download_button(
        label="⬇️ Download Full Report (.md)",
        data=markdown_report,
        file_name="proshield_report.md",
        mime="text/markdown",
        use_container_width=True,
    )

    if save_report_to_db:
        if database.connect():
            inserted_id = database.save_report(report)
            if inserted_id:
                st.success(f"Report saved to MongoDB · ID: {inserted_id}")
            else:
                st.error("Report was not saved — insert failed.")
        else:
            st.error("MongoDB connection failed. Report not saved.")
