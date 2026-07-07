"""
MITRE ATT&CK Enterprise Matrix — Static reference data.

Contains the 14 tactics and key techniques most relevant to SOC operations.
Sourced from MITRE ATT&CK v14. This is an embedded subset focused on
techniques commonly detected by Wazuh SIEM rules.
"""

# Ordered by kill chain progression
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

def tactic_index(tactic: str) -> "int | None":
    """Return the kill-chain index of ``tactic`` in MITRE_TACTICS.

    Case-sensitive exact match. Returns None for unknown tactics. Used as
    the deterministic ordering key for attack-chain grouping.
    """
    try:
        return MITRE_TACTICS.index(tactic)
    except ValueError:
        return None


def order_tactics(tactics: "list[str]") -> "list[str]":
    """Return the distinct *known* tactics sorted by kill-chain index.

    Unknown tactics are dropped; duplicates are collapsed. Deterministic —
    no ML, pure ordering by MITRE_TACTICS position.
    """
    distinct = {t for t in tactics if tactic_index(t) is not None}
    return sorted(distinct, key=lambda t: tactic_index(t))


TACTIC_IDS = {
    "Reconnaissance": "TA0043",
    "Resource Development": "TA0042",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# Key techniques per tactic — focused on what Wazuh/SIEM rules typically detect
MITRE_MATRIX = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning"},
        {"id": "T1592", "name": "Gather Victim Host Information"},
        {"id": "T1589", "name": "Gather Victim Identity Information"},
        {"id": "T1590", "name": "Gather Victim Network Information"},
        {"id": "T1591", "name": "Gather Victim Org Information"},
    ],
    "Resource Development": [
        {"id": "T1583", "name": "Acquire Infrastructure"},
        {"id": "T1586", "name": "Compromise Accounts"},
        {"id": "T1584", "name": "Compromise Infrastructure"},
        {"id": "T1587", "name": "Develop Capabilities"},
        {"id": "T1588", "name": "Obtain Capabilities"},
    ],
    "Initial Access": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1133", "name": "External Remote Services"},
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1078", "name": "Valid Accounts"},
        {"id": "T1189", "name": "Drive-by Compromise"},
        {"id": "T1195", "name": "Supply Chain Compromise"},
        {"id": "T1199", "name": "Trusted Relationship"},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1053", "name": "Scheduled Task/Job"},
        {"id": "T1047", "name": "Windows Management Instrumentation"},
        {"id": "T1204", "name": "User Execution"},
        {"id": "T1203", "name": "Exploitation for Client Execution"},
        {"id": "T1106", "name": "Native API"},
        {"id": "T1569", "name": "System Services"},
    ],
    "Persistence": [
        {"id": "T1098", "name": "Account Manipulation"},
        {"id": "T1136", "name": "Create Account"},
        {"id": "T1543", "name": "Create or Modify System Process"},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        {"id": "T1053", "name": "Scheduled Task/Job"},
        {"id": "T1505", "name": "Server Software Component"},
        {"id": "T1078", "name": "Valid Accounts"},
    ],
    "Privilege Escalation": [
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
        {"id": "T1134", "name": "Access Token Manipulation"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
        {"id": "T1078", "name": "Valid Accounts"},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        {"id": "T1053", "name": "Scheduled Task/Job"},
    ],
    "Defense Evasion": [
        {"id": "T1070", "name": "Indicator Removal"},
        {"id": "T1562", "name": "Impair Defenses"},
        {"id": "T1036", "name": "Masquerading"},
        {"id": "T1027", "name": "Obfuscated Files or Information"},
        {"id": "T1218", "name": "System Binary Proxy Execution"},
        {"id": "T1112", "name": "Modify Registry"},
        {"id": "T1222", "name": "File and Directory Permissions Modification"},
    ],
    "Credential Access": [
        {"id": "T1003", "name": "OS Credential Dumping"},
        {"id": "T1110", "name": "Brute Force"},
        {"id": "T1555", "name": "Credentials from Password Stores"},
        {"id": "T1056", "name": "Input Capture"},
        {"id": "T1558", "name": "Steal or Forge Kerberos Tickets"},
        {"id": "T1552", "name": "Unsecured Credentials"},
        {"id": "T1539", "name": "Steal Web Session Cookie"},
    ],
    "Discovery": [
        {"id": "T1087", "name": "Account Discovery"},
        {"id": "T1083", "name": "File and Directory Discovery"},
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1135", "name": "Network Share Discovery"},
        {"id": "T1057", "name": "Process Discovery"},
        {"id": "T1082", "name": "System Information Discovery"},
        {"id": "T1016", "name": "System Network Configuration Discovery"},
    ],
    "Lateral Movement": [
        {"id": "T1021", "name": "Remote Services"},
        {"id": "T1570", "name": "Lateral Tool Transfer"},
        {"id": "T1080", "name": "Taint Shared Content"},
        {"id": "T1091", "name": "Replication Through Removable Media"},
        {"id": "T1550", "name": "Use Alternate Authentication Material"},
    ],
    "Collection": [
        {"id": "T1560", "name": "Archive Collected Data"},
        {"id": "T1005", "name": "Data from Local System"},
        {"id": "T1039", "name": "Data from Network Shared Drive"},
        {"id": "T1114", "name": "Email Collection"},
        {"id": "T1074", "name": "Data Staged"},
    ],
    "Command and Control": [
        {"id": "T1071", "name": "Application Layer Protocol"},
        {"id": "T1095", "name": "Non-Application Layer Protocol"},
        {"id": "T1572", "name": "Protocol Tunneling"},
        {"id": "T1090", "name": "Proxy"},
        {"id": "T1105", "name": "Ingress Tool Transfer"},
        {"id": "T1571", "name": "Non-Standard Port"},
        {"id": "T1573", "name": "Encrypted Channel"},
    ],
    "Exfiltration": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        {"id": "T1567", "name": "Exfiltration Over Web Service"},
        {"id": "T1029", "name": "Scheduled Transfer"},
        {"id": "T1537", "name": "Transfer Data to Cloud Account"},
    ],
    "Impact": [
        {"id": "T1486", "name": "Data Encrypted for Impact"},
        {"id": "T1490", "name": "Inhibit System Recovery"},
        {"id": "T1489", "name": "Service Stop"},
        {"id": "T1485", "name": "Data Destruction"},
        {"id": "T1499", "name": "Endpoint Denial of Service"},
        {"id": "T1491", "name": "Defacement"},
    ],
}

# All technique IDs in the matrix for quick lookup
ALL_TECHNIQUE_IDS = set()
TECHNIQUE_NAMES = {}  # id -> name
TECHNIQUE_TACTICS = {}  # id -> list of tactics

for tactic, techniques in MITRE_MATRIX.items():
    for t in techniques:
        ALL_TECHNIQUE_IDS.add(t["id"])
        TECHNIQUE_NAMES[t["id"]] = t["name"]
        TECHNIQUE_TACTICS.setdefault(t["id"], []).append(tactic)

TOTAL_TECHNIQUES = len(ALL_TECHNIQUE_IDS)
