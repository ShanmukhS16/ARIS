"""Parser for DARPA OpTC eCAR-format JSON logs.

eCAR fields are mapped to Sysmon-compatible names so existing Sigma rules
fire without modification. This is a deliberate design choice: one set of
rules covers both lab data (Sysmon) and benchmark data (OpTC).

Supports both plain JSONL and gzipped JSONL (.json.gz).
Streams line-by-line to handle multi-GB OpTC files.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from typing import Iterator

from app.models import Event

# Object-action pairs worth keeping. The OpTC dataset has millions of benign
# FILE_READ / FILE_WRITE events that would flood the DB without this filter.
RELEVANT_ACTIONS = {
    ("PROCESS", "CREATE"),
    ("PROCESS", "OPEN"),
    ("REGISTRY", "WRITE"),
    ("REGISTRY", "READ"),
    ("REGISTRY", "DELETE"),
    ("FLOW", "OPEN"),
    ("FLOW", "START"),
    ("SHELL", "EXECUTE"),
    ("FILE", "CREATE"),
    ("FILE", "DELETE"),
    ("FILE", "MODIFY"),
    ("MODULE", "LOAD"),
    ("USER_SESSION", "LOGIN"),
    ("USER_SESSION", "LOGOUT"),
}


def parse_optc_file(content: str) -> Iterator[Event]:
    """Parse a plain JSONL string of eCAR events."""
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev = _map_ecar_event(raw, line)
        if ev is not None:
            yield ev


def parse_optc_gzip(path: str) -> Iterator[Event]:
    """Stream events from a gzipped eCAR file."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = _map_ecar_event(raw, line)
            if ev is not None:
                yield ev


def parse_optc_gzip_strided(path: str, stride: int, offset: int = 0) -> Iterator[Event]:
    """Stream every Nth event from a gzipped eCAR file.

    Skips JSON parsing entirely for lines that won't be kept,
    which is much faster than parsing everything and discarding.
    Returns (event, line_index) tuples.
    """
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for idx, line in enumerate(fh, start=offset):
            if idx % stride != 0:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = _map_ecar_event(raw, line)
            if ev is not None:
                yield ev
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            ev = _map_ecar_event(raw, line)
            if ev is not None:
                yield ev


def _map_ecar_event(raw: dict, raw_line: str) -> Event | None:
    """Map a single eCAR record to our Event model.

    eCAR structure:
      - actorID: process UUID that caused the event
      - object: "PROCESS", "REGISTRY", "FLOW", "FILE", etc.
      - action: "CREATE", "WRITE", "OPEN", etc.
      - timestamp: nanoseconds since Unix epoch
      - hostname: source machine
      - properties: dict with object-specific fields
    """
    obj = raw.get("object", "").upper()
    action = raw.get("action", "").upper()

    if (obj, action) not in RELEVANT_ACTIONS:
        return None

    props = raw.get("properties", {})
    timestamp = _ns_to_datetime(raw.get("timestamp", 0))
    host = raw.get("hostname", raw.get("host", "unknown"))

    # Map eCAR fields to Sysmon-compatible field names
    command_line = props.get("command_line", props.get("image_path", ""))
    image = props.get("image_path", props.get("file_path", ""))
    parent_image = props.get("parent_image_path", "")
    user = props.get("user", props.get("principal", ""))
    target_object = props.get("key", props.get("value", ""))
    target_filename = props.get("file_path", "")
    dest_ip = props.get("dest_ip", props.get("remote_ip", ""))
    dest_port = props.get("dest_port", props.get("remote_port", ""))

    parsed = {
        "event_id": f"ecar_{obj}_{action}",
        "image": image,
        "command_line": command_line,
        "parent_image": parent_image,
        "parent_command_line": props.get("parent_command_line", ""),
        "target_filename": target_filename,
        "target_object": target_object,
        "details": props.get("data", ""),
        "destination_ip": str(dest_ip),
        "destination_port": str(dest_port),
        "source_ip": props.get("src_ip", props.get("local_ip", "")),
        "hashes": props.get("md5_hash", ""),
        "ecar_object": obj,
        "ecar_action": action,
        "actor_id": raw.get("actorID", ""),
    }

    return Event(
        timestamp=timestamp,
        host=host,
        source_type="ecar",
        user=user if user else None,
        process=command_line or image,
        raw=raw_line,
        parsed=json.dumps(parsed),
    )


def _ns_to_datetime(ns: int | str) -> datetime:
    """Convert nanosecond Unix timestamp to datetime."""
    try:
        ns_int = int(ns)
        return datetime.fromtimestamp(ns_int / 1_000_000_000, tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return datetime.utcnow()


def is_ecar_format(content: str) -> bool:
    """Quick check: does the first JSON line look like eCAR?"""
    for line in content.strip().splitlines()[:3]:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            return "actorID" in raw or ("object" in raw and "action" in raw)
        except json.JSONDecodeError:
            continue
    return False
