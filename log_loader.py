"""Log loader for ProShield-AI.

Reads raw log events from a JSON file, validates the structure,
and returns them as a plain Python list ready for the pipeline.
"""

import json
from typing import Any, Dict, List

# Fields every valid log entry must contain.
REQUIRED_FIELDS = {"timestamp", "source_ip", "destination_ip", "activity_type", "bytes_transferred"}


def load_logs(file_path: str = "data/sample_logs.json") -> List[Dict[str, Any]]:
    """Read and validate log events from a JSON file.

    Parameters
    ----------
    file_path : str
        Path to the JSON log file. Defaults to ``data/sample_logs.json``.

    Returns
    -------
    list[dict]
        Valid log entries. Invalid entries are skipped with a warning.
        Returns an empty list if the file cannot be read or parsed.
    """
    # ── Read file ─────────────────────────────────────────────────────────────
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        print(f"[log_loader] File not found: {file_path}")
        return []
    except json.JSONDecodeError as exc:
        print(f"[log_loader] Invalid JSON in {file_path}: {exc}")
        return []
    except OSError as exc:
        print(f"[log_loader] Could not read {file_path}: {exc}")
        return []

    # ── Validate top-level structure ──────────────────────────────────────────
    if not isinstance(raw, list):
        print(f"[log_loader] Expected a JSON array, got {type(raw).__name__}. Aborting.")
        return []

    # ── Validate individual entries ───────────────────────────────────────────
    valid_logs: List[Dict[str, Any]] = []
    skipped = 0

    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            print(f"[log_loader] Entry {index} is not a dict — skipped.")
            skipped += 1
            continue

        missing = REQUIRED_FIELDS - entry.keys()
        if missing:
            print(f"[log_loader] Entry {index} missing fields {missing} — skipped.")
            skipped += 1
            continue

        valid_logs.append(entry)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"[log_loader] Loaded {len(valid_logs)} log(s) from '{file_path}'"
          + (f"  ({skipped} skipped)" if skipped else "") + ".")

    return valid_logs
