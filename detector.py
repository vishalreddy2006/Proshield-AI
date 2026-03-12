"""Anomaly-based suspicious activity detector for ProShield-AI.

Uses scikit-learn's IsolationForest trained on numeric log features
to label each event as 'normal' or 'suspicious'.
"""

from typing import Any, Dict, List, Optional

import pandas as pd
from sklearn.ensemble import IsolationForest

# Module-level model so train_model() and detect_anomalies() share state.
_model: Optional[IsolationForest] = None

# Numeric features extracted from each log entry.
FEATURES = ["bytes_transferred"]


def _logs_to_dataframe(logs: List[Dict[str, Any]]) -> pd.DataFrame:
    """Convert a list of log dicts into a numeric feature DataFrame."""
    frame = pd.DataFrame(logs)

    # Keep only known numeric features; fill missing values with 0.
    for col in FEATURES:
        if col not in frame.columns:
            frame[col] = 0
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0)

    return frame[FEATURES]


def train_model(logs: List[Dict[str, Any]]) -> IsolationForest:
    """Train an IsolationForest model on the provided logs.

    Parameters
    ----------
    logs : list[dict]
        Raw log entries (at minimum each needs a ``bytes_transferred`` field).

    Returns
    -------
    IsolationForest
        The fitted model (also stored module-level for detect_anomalies).
    """
    global _model

    if not logs:
        print("[detector] No logs provided — model not trained.")
        _model = None
        return None

    X = _logs_to_dataframe(logs)

    _model = IsolationForest(
        n_estimators=100,
        contamination=0.2,   # expect ~20 % of events to be anomalous
        random_state=42,
    )
    _model.fit(X)
    print(f"[detector] Model trained on {len(logs)} log(s).")
    return _model


def detect_anomalies(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect anomalies in logs using the trained IsolationForest model.

    Calls ``train_model`` automatically if the model has not been trained yet.

    Parameters
    ----------
    logs : list[dict]
        Raw log entries to classify.

    Returns
    -------
    list[dict]
        Copy of each log entry with two extra fields added:

        * ``label``  – ``"suspicious"`` or ``"normal"``
        * ``anomaly_score`` – raw IsolationForest decision score (lower = more anomalous)
    """
    if not logs:
        print("[detector] No logs to analyse.")
        return []

    # Auto-train if needed.
    global _model
    if _model is None:
        train_model(logs)

    if _model is None:
        # Training failed (e.g. empty input) — mark everything unknown.
        return [{**log, "label": "unknown", "anomaly_score": None} for log in logs]

    X = _logs_to_dataframe(logs)
    predictions = _model.predict(X)          # 1 = normal, -1 = anomaly
    scores = _model.decision_function(X)     # higher = more normal

    results = []
    suspicious_count = 0

    for log, pred, score in zip(logs, predictions, scores):
        label = "suspicious" if pred == -1 else "normal"
        if label == "suspicious":
            suspicious_count += 1
        results.append({
            **log,
            "label": label,
            "anomaly_score": round(float(score), 4),
        })

    print(f"[detector] {suspicious_count} suspicious / {len(logs) - suspicious_count} normal  "
          f"out of {len(logs)} event(s).")
    return results
