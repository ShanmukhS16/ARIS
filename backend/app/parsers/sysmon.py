"""Parser for Sysmon JSONL log files.

Each line is a JSON object with fields like:
  EventID, UtcTime, Computer, User, Image, CommandLine, ParentImage, etc.

We normalise these into Event model instances.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Iterator

from app.models import Event


def parse_sysmon_file(content: str) -> Iterator[Event]:
    """Parse a Sysmon JSONL string into Event objects."""
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue

        timestamp = _parse_timestamp(raw.get("UtcTime", raw.get("timestamp", "")))
        host = raw.get("Computer", raw.get("host", "unknown"))
        user = raw.get("User", raw.get("user"))
        process = raw.get("CommandLine", raw.get("Image", ""))
        parent = raw.get("ParentImage", "")

        parsed = {
            "event_id": raw.get("EventID"),
            "image": raw.get("Image", ""),
            "command_line": raw.get("CommandLine", ""),
            "parent_image": parent,
            "parent_command_line": raw.get("ParentCommandLine", ""),
            "target_filename": raw.get("TargetFilename", ""),
            "target_object": raw.get("TargetObject", ""),
            "details": raw.get("Details", ""),
            "destination_ip": raw.get("DestinationIp", ""),
            "destination_port": raw.get("DestinationPort", ""),
            "source_ip": raw.get("SourceIp", ""),
            "hashes": raw.get("Hashes", ""),
        }

        yield Event(
            timestamp=timestamp,
            host=host,
            source_type="sysmon",
            user=user,
            process=process,
            raw=line,
            parsed=json.dumps(parsed),
        )


def _parse_timestamp(ts_str: str) -> datetime:
    """Best-effort timestamp parsing for Sysmon formats."""
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except (ValueError, TypeError):
            continue
    return datetime.utcnow()
