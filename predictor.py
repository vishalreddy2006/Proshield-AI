"""Attack-chain predictor for ProShield-AI.

Given an observed activity type, predicts the most likely next step
an attacker would take based on known threat progression patterns.
Rules are stored in a plain dictionary — easy to extend or modify.
"""

from typing import Dict, Optional

# ── Prediction rules ──────────────────────────────────────────────────────────
# Key   : observed activity_type (matches values in sample_logs.json)
# Value : predicted next attacker step
#
# Add, remove, or change entries here to update the prediction logic.
NEXT_STEP_RULES: Dict[str, str] = {
    "port_scan":            "credential_attack",
    "login_attempt":        "privilege_escalation",
    "privilege_escalation": "lateral_movement",
    "data_transfer":        "data_exfiltration",
    "file_access":          "data_exfiltration",
    "malware_activity":     "persistence",
    "failed_login":         "credential_attack",
}


def predict_next_step(activity_type: str) -> Dict[str, Optional[str]]:
    """Predict the most likely next attacker step for a given activity type.

    Parameters
    ----------
    activity_type : str
        The activity observed in a log event (e.g. ``"port_scan"``).

    Returns
    -------
    dict with keys:
        * ``activity_type``  – the input activity (normalised to lower-case)
        * ``predicted_next`` – predicted next step, or ``None`` if unknown
        * ``known``          – ``True`` if the activity is in the rule table

    Examples
    --------
    >>> predict_next_step("port_scan")
    {'activity_type': 'port_scan', 'predicted_next': 'credential_attack', 'known': True}

    >>> predict_next_step("unknown_event")
    {'activity_type': 'unknown_event', 'predicted_next': None, 'known': False}
    """
    normalised = activity_type.strip().lower()
    predicted = NEXT_STEP_RULES.get(normalised)

    if predicted:
        print(f"[predictor] {normalised}  →  {predicted}")
    else:
        print(f"[predictor] No prediction rule for activity: '{normalised}'")

    return {
        "activity_type": normalised,
        "predicted_next": predicted,
        "known": predicted is not None,
    }
