"""Report generator for ProShield-AI.

Two public interfaces:
  generate_report(log, prediction, mitre_info)  – formats one event as text
  build_report(...)                              – assembles the full pipeline report dict
  report_to_markdown(report)                     – converts the report dict to markdown
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

# ── Defensive action recommendations keyed by MITRE tactic ───────────────────
DEFENSIVE_ACTIONS: Dict[str, str] = {
    "Reconnaissance":       "Block scanning IPs at the perimeter firewall and enable port-scan alerts.",
    "Credential Access":    "Enforce MFA, lock accounts after repeated failures, and audit login logs.",
    "Collection":           "Restrict file permissions, enable DLP controls, and audit file access.",
    "Exfiltration":         "Inspect outbound traffic, apply data-loss-prevention rules, and alert on large transfers.",
    "Privilege Escalation": "Review sudo/admin rights, apply least-privilege policy, and patch known exploits.",
    "Execution":            "Deploy endpoint protection, block untrusted executables, and isolate the host.",
    "Defense Evasion":      "Re-enable security tools, review EDR alerts, and audit service configurations.",
    "Lateral Movement":     "Segment the network, rotate credentials, and review east-west traffic.",
    "Persistence":          "Audit scheduled tasks and startup items, and check for new/modified accounts.",
}

UNKNOWN = "Unknown"


def _risk_level(anomaly_score: Any) -> str:
    """Derive a human-readable risk level from the IsolationForest anomaly score."""
    if anomaly_score is None:
        return "Unknown"
    try:
        score = float(anomaly_score)
    except (TypeError, ValueError):
        return "Unknown"
    # IsolationForest decision scores: negative → anomalous, positive → normal
    if score < -0.1:
        return "High"
    if score < 0.0:
        return "Medium"
    return "Low"


# ── Primary function ──────────────────────────────────────────────────────────

def generate_report(
    log: Dict[str, Any],
    prediction: Dict[str, Any],
    mitre_info: Dict[str, Any],
) -> str:
    """Format a single suspicious event as a multi-line threat report.

    Parameters
    ----------
    log : dict
        A log entry from sample_logs.json, enriched by detect_anomalies()
        with ``label`` and ``anomaly_score`` fields.
    prediction : dict
        Output of ``predictor.predict_next_step()``.
        Expected keys: ``activity_type``, ``predicted_next``, ``known``.
    mitre_info : dict
        Output of ``cti_mapper.map_to_mitre()``.
        Expected keys: ``technique_id``, ``technique_name``, ``tactic``.

    Returns
    -------
    str
        A formatted multi-line report string ready for printing or display.
    """
    tactic = mitre_info.get("tactic", UNKNOWN)
    defensive_action = DEFENSIVE_ACTIONS.get(tactic, "Review logs and apply standard hardening procedures.")
    predicted_next = prediction.get("predicted_next") or UNKNOWN
    risk = _risk_level(log.get("anomaly_score"))

    separator = "=" * 60
    report = (
        f"{separator}\n"
        f"  ProShield-AI  —  Threat Event Report\n"
        f"{separator}\n"
        f"  Timestamp          : {log.get('timestamp', UNKNOWN)}\n"
        f"  Source IP          : {log.get('source_ip', UNKNOWN)}\n"
        f"  Destination IP     : {log.get('destination_ip', UNKNOWN)}\n"
        f"  Detected Activity  : {log.get('activity_type', UNKNOWN)}\n"
        f"  Bytes Transferred  : {log.get('bytes_transferred', UNKNOWN)}\n"
        f"{'-' * 60}\n"
        f"  MITRE Technique ID : {mitre_info.get('technique_id', UNKNOWN)}\n"
        f"  MITRE Technique    : {mitre_info.get('technique_name', UNKNOWN)}\n"
        f"  MITRE Tactic       : {tactic}\n"
        f"{'-' * 60}\n"
        f"  Predicted Next     : {predicted_next}\n"
        f"  Risk Level         : {risk}\n"
        f"{'-' * 60}\n"
        f"  Recommended Action : {defensive_action}\n"
        f"{separator}\n"
    )
    return report


# ── Pipeline helpers ──────────────────────────────────────────────────────────

def build_report(
    logs: List[Dict[str, Any]],
    suspicious_events: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    mitre_techniques: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the full pipeline output into a single report dictionary."""
    event_reports = []
    for event, prediction, mitre_info in zip(suspicious_events, predictions, mitre_techniques):
        event_reports.append(generate_report(event, prediction, mitre_info))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_logs": len(logs),
            "suspicious_events": len(suspicious_events),
        },
        "suspicious_events": suspicious_events,
        "predictions": predictions,
        "mitre_techniques": mitre_techniques,
        "event_reports": event_reports,
    }


def report_to_markdown(report: Dict[str, Any]) -> str:
    """Convert the report dictionary into a markdown document."""
    summary = report.get("summary", {})
    predictions = report.get("predictions", [])
    mitre_techniques = report.get("mitre_techniques", [])
    known_predictions = [p for p in predictions if p.get("known")]

    lines = [
        "# ProShield-AI — Threat Analysis Report",
        "",
        f"**Generated At:** {report.get('generated_at', 'N/A')}",
        "",
        "## Summary",
        f"- Total Logs Analysed : {summary.get('total_logs', 0)}",
        f"- Suspicious Events   : {summary.get('suspicious_events', 0)}",
        "",
        "## Predicted Next Attacker Steps",
    ]

    if known_predictions:
        for p in known_predictions:
            lines.append(f"- `{p['activity_type']}` → **{p['predicted_next']}**")
    else:
        lines.append("- No predictions available.")

    lines += ["", "## MITRE ATT&CK Mapping"]
    if mitre_techniques:
        for m in mitre_techniques:
            if m.get("technique_id") != UNKNOWN:
                lines.append(
                    f"- `{m.get('activity_type', '?')}` → "
                    f"{m['technique_id']} · {m['technique_name']} "
                    f"(*{m['tactic']}*)"
                )
    else:
        lines.append("- No MITRE mappings available.")

    lines += ["", "## Individual Event Reports", ""]
    for text_report in report.get("event_reports", []):
        lines.append("```")
        lines.append(text_report.strip())
        lines.append("```")
        lines.append("")

    return "\n".join(lines) + "\n"
