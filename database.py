"""MongoDB helper for ProShield-AI.

Collections used
----------------
logs        – raw ingested log events
alerts      – suspicious events flagged by the detector
predictions – risk scores produced by the predictor
reports     – full analysis reports
"""

from typing import Any, Dict, List, Optional

from pymongo import MongoClient
from pymongo.database import Database

# ── Connection settings ───────────────────────────────────────────────────────
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "proshield_ai"

# Module-level client and database, initialized once via connect()
_client: Optional[MongoClient] = None
_db: Optional[Database] = None


# ── Connection ────────────────────────────────────────────────────────────────

def connect() -> bool:
    """Connect to MongoDB running on localhost.

    Returns True on success, False if the server is unreachable.
    Call this once at application startup before using any other function.
    """
    global _client, _db

    try:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        # Trigger an actual network call to verify the server is up.
        _client.server_info()
        _db = _client[DB_NAME]
        print(f"[database] Connected to MongoDB  →  {DB_NAME}")
        return True
    except Exception as exc:
        print(f"[database] Connection failed: {exc}")
        _client = None
        _db = None
        return False


def _get_collection(name: str):
    """Return a collection object, or None if not connected."""
    if _db is None:
        print(f"[database] Not connected. Call connect() first.")
        return None
    return _db[name]


# ── Logs collection ───────────────────────────────────────────────────────────

def save_log(log: Dict[str, Any]) -> Optional[str]:
    """Insert a single log event into the *logs* collection.

    Parameters
    ----------
    log : dict
        A log event dictionary (e.g. loaded from sample_logs.json).

    Returns
    -------
    str | None
        The inserted document's id as a string, or None on failure.
    """
    col = _get_collection("logs")
    if col is None:
        return None

    try:
        result = col.insert_one(log)
        return str(result.inserted_id)
    except Exception as exc:
        print(f"[database] save_log failed: {exc}")
        return None


def get_logs() -> List[Dict[str, Any]]:
    """Retrieve all documents from the *logs* collection.

    Returns
    -------
    list[dict]
        List of log documents (``_id`` field converted to string).
    """
    col = _get_collection("logs")
    if col is None:
        return []

    try:
        documents = list(col.find())
        for doc in documents:
            doc["_id"] = str(doc["_id"])
        return documents
    except Exception as exc:
        print(f"[database] get_logs failed: {exc}")
        return []


# ── Alerts collection ─────────────────────────────────────────────────────────

def save_alert(alert: Dict[str, Any]) -> Optional[str]:
    """Insert a suspicious event into the *alerts* collection.

    Parameters
    ----------
    alert : dict
        A flagged event dictionary produced by detector.py.

    Returns
    -------
    str | None
        Inserted document id, or None on failure.
    """
    col = _get_collection("alerts")
    if col is None:
        return None

    try:
        result = col.insert_one(alert)
        return str(result.inserted_id)
    except Exception as exc:
        print(f"[database] save_alert failed: {exc}")
        return None


# ── Predictions collection ────────────────────────────────────────────────────

def save_prediction(prediction: Dict[str, Any]) -> Optional[str]:
    """Insert a risk prediction into the *predictions* collection.

    Parameters
    ----------
    prediction : dict
        Output of predictor.predict_risk().

    Returns
    -------
    str | None
        Inserted document id, or None on failure.
    """
    col = _get_collection("predictions")
    if col is None:
        return None

    try:
        result = col.insert_one(prediction)
        return str(result.inserted_id)
    except Exception as exc:
        print(f"[database] save_prediction failed: {exc}")
        return None


# ── Reports collection ────────────────────────────────────────────────────────

def save_report(report: Dict[str, Any]) -> Optional[str]:
    """Insert a full analysis report into the *reports* collection.

    Parameters
    ----------
    report : dict
        Output of report_generator.build_report().

    Returns
    -------
    str | None
        Inserted document id, or None on failure.
    """
    col = _get_collection("reports")
    if col is None:
        return None

    try:
        result = col.insert_one(report)
        return str(result.inserted_id)
    except Exception as exc:
        print(f"[database] save_report failed: {exc}")
        return None
