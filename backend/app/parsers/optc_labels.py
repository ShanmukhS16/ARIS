"""OpTC Red Team ground truth labels.

Encodes the attack time windows from OpTCRedTeamGroundTruth.pdf as
structured data. The label_event() function returns whether an event
falls inside a known malicious window, plus which techniques and
campaign it maps to.

NOTE: Verify timestamps against your copy of the ground truth PDF.
The windows below are approximate and may need adjustment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class AttackWindow:
    day: int
    campaign: str
    host: str
    start: datetime
    end: datetime
    techniques: tuple[str, ...]
    description: str


# Red team activity windows from the OpTC ground truth document.
# Day 1: Plain PowerShell Empire
# Day 2: Custom PSEmpire variant
# Day 3: Obfuscated PSEmpire
GROUND_TRUTH: list[AttackWindow] = [
    # Day 1 - Plain PSEmpire on SysClient0201
    AttackWindow(
        day=1, campaign="Plain PSEmpire", host="SysClient0201",
        start=datetime(2019, 9, 23, 10, 0, 0),
        end=datetime(2019, 9, 23, 17, 0, 0),
        techniques=("T1059.001", "T1033", "T1082", "T1547.001"),
        description="Initial access via spearphishing, PowerShell Empire stager, "
                    "system discovery, persistence via registry Run key",
    ),
    # Day 1 - Lateral movement to SysClient0402
    AttackWindow(
        day=1, campaign="Plain PSEmpire", host="SysClient0402",
        start=datetime(2019, 9, 23, 13, 0, 0),
        end=datetime(2019, 9, 23, 17, 0, 0),
        techniques=("T1021.001", "T1059.001", "T1003.001"),
        description="Lateral movement via RDP, credential dumping",
    ),
    # Day 2 - Custom PSEmpire on SysClient0201
    AttackWindow(
        day=2, campaign="Custom PSEmpire", host="SysClient0201",
        start=datetime(2019, 9, 24, 10, 0, 0),
        end=datetime(2019, 9, 24, 17, 0, 0),
        techniques=("T1059.001", "T1033", "T1547.001", "T1105"),
        description="Custom PSEmpire variant with ingress tool transfer",
    ),
    # Day 2 - Custom PSEmpire lateral to SysClient0660
    AttackWindow(
        day=2, campaign="Custom PSEmpire", host="SysClient0660",
        start=datetime(2019, 9, 24, 12, 0, 0),
        end=datetime(2019, 9, 24, 17, 0, 0),
        techniques=("T1021.001", "T1059.001"),
        description="Lateral movement via RDP to additional host",
    ),
    # Day 3 - Obfuscated PSEmpire on SysClient0201
    AttackWindow(
        day=3, campaign="Obfuscated PSEmpire", host="SysClient0201",
        start=datetime(2019, 9, 25, 10, 0, 0),
        end=datetime(2019, 9, 25, 17, 0, 0),
        techniques=("T1059.001", "T1027", "T1033", "T1547.001"),
        description="Obfuscated PowerShell stager with encoded commands",
    ),
    # Day 3 - Obfuscated lateral to SysClient0402
    AttackWindow(
        day=3, campaign="Obfuscated PSEmpire", host="SysClient0402",
        start=datetime(2019, 9, 25, 13, 0, 0),
        end=datetime(2019, 9, 25, 17, 0, 0),
        techniques=("T1021.001", "T1059.001", "T1003.001"),
        description="Obfuscated lateral movement and credential access",
    ),
]


def label_event(
    timestamp: datetime, host: str
) -> dict:
    """Check if an event falls inside a known malicious window.

    Returns:
        {
            "is_malicious": bool,
            "day": int | None,
            "campaign": str | None,
            "techniques": list[str],
            "description": str | None,
        }
    """
    for w in GROUND_TRUTH:
        if w.host == host and w.start <= timestamp <= w.end:
            return {
                "is_malicious": True,
                "day": w.day,
                "campaign": w.campaign,
                "techniques": list(w.techniques),
                "description": w.description,
            }
    return {
        "is_malicious": False,
        "day": None,
        "campaign": None,
        "techniques": [],
        "description": None,
    }


def summary() -> str:
    """Human-readable summary of ground truth windows."""
    lines = ["OpTC Red Team Ground Truth Windows:"]
    for w in GROUND_TRUTH:
        lines.append(
            f"  Day {w.day} | {w.campaign:24s} | {w.host:18s} | "
            f"{w.start.strftime('%Y-%m-%d %H:%M')}-{w.end.strftime('%H:%M')} | "
            f"Techniques: {', '.join(w.techniques)}"
        )
    return "\n".join(lines)
