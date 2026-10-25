"""Curated MITRE ATT&CK knowledge base for narrative grounding.

Contains technique descriptions for the IDs our rules and ML actually
reference. These are injected into the LLM prompt as RAG context so
the model describes techniques accurately instead of hallucinating.
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to identify the primary user, currently logged "
            "in user, set of users that commonly uses a system, or whether a user is "
            "actively using the system. Commands such as whoami, quser, and id are "
            "commonly used for this purpose."
        ),
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "tactic": "Persistence",
        "description": (
            "Adversaries may achieve persistence by adding a program to the registry "
            "Run or RunOnce keys. Adding an entry to these keys causes the referenced "
            "program to be executed when a user logs in. These programs will be "
            "executed under the context of the user and will have the account's "
            "associated permissions level."
        ),
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for execution. "
            "PowerShell is a powerful interactive command-line interface and scripting "
            "environment included in the Windows operating system. Adversaries can use "
            "PowerShell to perform a number of actions, including discovery of "
            "information and execution of code. Encoded commands (-enc, -EncodedCommand) "
            "are commonly used to obfuscate the payload."
        ),
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to attempt access to accounts "
            "when passwords are unknown or when password hashes are obtained. Without "
            "knowledge of the password for an account, an adversary may systematically "
            "guess the password using a repetitive or iterative mechanism."
        ),
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to dump the contents of /etc/shadow to enable "
            "offline password cracking. On Linux systems, password hashes are stored "
            "in /etc/shadow which is only readable by root. Adversaries must first "
            "gain sufficient privileges before attempting to access this file."
        ),
    },
    "T1012": {
        "name": "Query Registry",
        "tactic": "Discovery",
        "description": (
            "Adversaries may interact with the Windows Registry to gather information "
            "about the system, configuration, and installed software. The Registry "
            "contains a significant amount of information about the operating system, "
            "configuration, software, and security. The reg query utility can be used "
            "to query specific keys."
        ),
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to get detailed information about the operating "
            "system and hardware, including version, patches, hotfixes, service packs, "
            "and architecture. This information may be used to shape follow-on behaviors."
        ),
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to access credential material stored in the process "
            "memory of the Local Security Authority Subsystem Service (LSASS). After a "
            "user logs on, the system generates and stores a variety of credential "
            "materials in LSASS process memory. These credential materials can be "
            "harvested by tools such as Mimikatz, procdump, or the built-in comsvcs.dll "
            "MiniDump technique using rundll32."
        ),
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use Valid Accounts to log into a computer using the Remote "
            "Desktop Protocol (RDP). The adversary may then perform actions as the logged "
            "on user. RDP is commonly used for lateral movement within enterprise "
            "environments because it provides interactive access to a remote system."
        ),
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to make an executable or file difficult to discover "
            "or analyze by encrypting, encoding, or otherwise obfuscating its contents "
            "on the system or in transit. This includes encoding PowerShell commands in "
            "Base64, using mshta.exe as a LOLBin to bypass application whitelisting, "
            "and employing string concatenation or character substitution in scripts."
        ),
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer tools or other files from an external system into "
            "a compromised environment. Tools or files may be copied from an external "
            "adversary-controlled system to the victim network through the command and "
            "control channel or through alternate protocols such as FTP. Common methods "
            "include PowerShell's DownloadString and DownloadFile, certutil, and BITSAdmin."
        ),
    },
}


def get_technique(technique_id: str) -> dict[str, str] | None:
    """Look up a technique by its ATT&CK ID."""
    return TECHNIQUES.get(technique_id.upper())


def get_techniques_context(technique_ids: list[str]) -> str:
    """Build a RAG context block for a set of technique IDs."""
    lines = []
    for tid in sorted(set(technique_ids)):
        tech = get_technique(tid)
        if tech:
            lines.append(
                f"[{tid}] {tech['name']} (Tactic: {tech['tactic']})\n"
                f"  {tech['description']}"
            )
    return "\n\n".join(lines) if lines else "No matching ATT&CK techniques found."
