"""Parser for Linux auth.log files.

Typical line format:
  Sep  1 14:23:05 srv-01 sshd[12345]: Failed password for root from 10.0.0.5 port 22 ssh2

We extract timestamp, host, process, user, and the action described.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Iterator

from app.models import Event

_AUTH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<daemon>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_authlog_file(content: str, year: int = 2024) -> Iterator[Event]:
    """Parse an auth.log string into Event objects."""
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = _AUTH_RE.match(line)
        if not m:
            continue

        month_num = _MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        time_parts = m.group("time").split(":")
        timestamp = datetime(
            year, month_num, day,
            int(time_parts[0]), int(time_parts[1]), int(time_parts[2]),
        )

        host = m.group("host")
        daemon = m.group("daemon")
        message = m.group("message")
        user = _extract_user(message)
        process = f"{daemon}: {message}"

        # Extract source IP if present
        source_ip = ""
        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", message)
        if ip_match:
            source_ip = ip_match.group(1)

        parsed = {
            "daemon": daemon,
            "pid": m.group("pid"),
            "message": message,
            "source_ip": source_ip,
            "auth_action": _classify_action(message),
        }

        yield Event(
            timestamp=timestamp,
            host=host,
            source_type="authlog",
            user=user,
            process=process,
            raw=line,
            parsed=json.dumps(parsed),
        )


def _extract_user(message: str) -> str | None:
    """Pull username from common auth.log message patterns."""
    patterns = [
        r"for (?:invalid user )?(\S+)",
        r"user[= ](\S+)",
        r"session opened for user (\S+)",
        r"by (\S+)\(",
    ]
    for pat in patterns:
        m = re.search(pat, message)
        if m:
            return m.group(1)
    return None


def _classify_action(message: str) -> str:
    """Classify the auth action type."""
    msg_lower = message.lower()
    if "failed password" in msg_lower:
        return "auth_failure"
    if "accepted" in msg_lower:
        return "auth_success"
    if "session opened" in msg_lower:
        return "session_open"
    if "session closed" in msg_lower:
        return "session_close"
    if "sudo" in msg_lower:
        return "privilege_escalation"
    return "other"
