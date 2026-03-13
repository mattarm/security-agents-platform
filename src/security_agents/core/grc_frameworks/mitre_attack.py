"""MITRE ATT&CK — 14 tactics with top techniques per tactic."""

from security_agents.core.grc_models import Control, Framework
from security_agents.core.grc_frameworks import _register

# Top techniques per tactic — expandable via STIX feeds
_CONTROLS = [
    # =========================================================================
    # TA0043 — Reconnaissance
    # =========================================================================
    Control(id="T1595", framework_id="mitre_attack", parent_id="TA0043", title="Active Scanning",
            description="Adversaries may execute active reconnaissance scans to gather information."),
    Control(id="T1592", framework_id="mitre_attack", parent_id="TA0043", title="Gather Victim Host Information",
            description="Adversaries may gather information about the victim's hosts."),
    Control(id="T1589", framework_id="mitre_attack", parent_id="TA0043", title="Gather Victim Identity Information",
            description="Adversaries may gather information about the victim's identity."),
    Control(id="T1590", framework_id="mitre_attack", parent_id="TA0043", title="Gather Victim Network Information",
            description="Adversaries may gather information about the victim's networks."),
    Control(id="T1591", framework_id="mitre_attack", parent_id="TA0043", title="Gather Victim Org Information",
            description="Adversaries may gather information about the victim's organization."),

    # =========================================================================
    # TA0001 — Initial Access
    # =========================================================================
    Control(id="T1566", framework_id="mitre_attack", parent_id="TA0001", title="Phishing",
            description="Adversaries may send phishing messages to gain access to victim systems."),
    Control(id="T1190", framework_id="mitre_attack", parent_id="TA0001", title="Exploit Public-Facing Application",
            description="Adversaries may attempt to exploit a weakness in an Internet-facing host or service."),
    Control(id="T1133", framework_id="mitre_attack", parent_id="TA0001", title="External Remote Services",
            description="Adversaries may leverage external-facing remote services to initially access a network."),
    Control(id="T1078", framework_id="mitre_attack", parent_id="TA0001", title="Valid Accounts",
            description="Adversaries may obtain and abuse credentials of existing accounts."),
    Control(id="T1189", framework_id="mitre_attack", parent_id="TA0001", title="Drive-by Compromise",
            description="Adversaries may gain access through a user visiting a website during normal browsing."),

    # =========================================================================
    # TA0002 — Execution
    # =========================================================================
    Control(id="T1059", framework_id="mitre_attack", parent_id="TA0002", title="Command and Scripting Interpreter",
            description="Adversaries may abuse command and script interpreters to execute commands."),
    Control(id="T1204", framework_id="mitre_attack", parent_id="TA0002", title="User Execution",
            description="Adversaries may rely upon specific actions by a user to gain execution."),
    Control(id="T1053", framework_id="mitre_attack", parent_id="TA0002", title="Scheduled Task/Job",
            description="Adversaries may abuse task scheduling functionality to facilitate execution."),
    Control(id="T1203", framework_id="mitre_attack", parent_id="TA0002", title="Exploitation for Client Execution",
            description="Adversaries may exploit software vulnerabilities in client applications."),

    # =========================================================================
    # TA0003 — Persistence
    # =========================================================================
    Control(id="T1547", framework_id="mitre_attack", parent_id="TA0003", title="Boot or Logon Autostart Execution",
            description="Adversaries may configure system settings to automatically execute a program during boot or logon."),
    Control(id="T1136", framework_id="mitre_attack", parent_id="TA0003", title="Create Account",
            description="Adversaries may create an account to maintain access to victim systems."),
    Control(id="T1543", framework_id="mitre_attack", parent_id="TA0003", title="Create or Modify System Process",
            description="Adversaries may create or modify system processes to repeatedly execute malicious payloads."),
    Control(id="T1546", framework_id="mitre_attack", parent_id="TA0003", title="Event Triggered Execution",
            description="Adversaries may establish persistence using system mechanisms triggered by specific events."),

    # =========================================================================
    # TA0004 — Privilege Escalation
    # =========================================================================
    Control(id="T1548", framework_id="mitre_attack", parent_id="TA0004", title="Abuse Elevation Control Mechanism",
            description="Adversaries may circumvent mechanisms designed to control elevated privileges."),
    Control(id="T1134", framework_id="mitre_attack", parent_id="TA0004", title="Access Token Manipulation",
            description="Adversaries may modify access tokens to operate under a different user or system security context."),
    Control(id="T1068", framework_id="mitre_attack", parent_id="TA0004", title="Exploitation for Privilege Escalation",
            description="Adversaries may exploit software vulnerabilities to elevate privileges."),

    # =========================================================================
    # TA0005 — Defense Evasion
    # =========================================================================
    Control(id="T1070", framework_id="mitre_attack", parent_id="TA0005", title="Indicator Removal",
            description="Adversaries may delete or modify artifacts generated within systems to remove evidence."),
    Control(id="T1036", framework_id="mitre_attack", parent_id="TA0005", title="Masquerading",
            description="Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate."),
    Control(id="T1027", framework_id="mitre_attack", parent_id="TA0005", title="Obfuscated Files or Information",
            description="Adversaries may attempt to make an executable or file difficult to discover or analyze."),
    Control(id="T1562", framework_id="mitre_attack", parent_id="TA0005", title="Impair Defenses",
            description="Adversaries may maliciously modify components of a victim environment to hinder defenses."),

    # =========================================================================
    # TA0006 — Credential Access
    # =========================================================================
    Control(id="T1110", framework_id="mitre_attack", parent_id="TA0006", title="Brute Force",
            description="Adversaries may use brute force techniques to gain access to accounts."),
    Control(id="T1003", framework_id="mitre_attack", parent_id="TA0006", title="OS Credential Dumping",
            description="Adversaries may attempt to dump credentials for use in subsequent operations."),
    Control(id="T1555", framework_id="mitre_attack", parent_id="TA0006", title="Credentials from Password Stores",
            description="Adversaries may search for common password storage locations."),
    Control(id="T1056", framework_id="mitre_attack", parent_id="TA0006", title="Input Capture",
            description="Adversaries may use methods of capturing user input to obtain credentials."),

    # =========================================================================
    # TA0007 — Discovery
    # =========================================================================
    Control(id="T1087", framework_id="mitre_attack", parent_id="TA0007", title="Account Discovery",
            description="Adversaries may attempt to get a listing of valid accounts or email addresses."),
    Control(id="T1083", framework_id="mitre_attack", parent_id="TA0007", title="File and Directory Discovery",
            description="Adversaries may enumerate files and directories or search for information within a file system."),
    Control(id="T1057", framework_id="mitre_attack", parent_id="TA0007", title="Process Discovery",
            description="Adversaries may attempt to get information about running processes."),
    Control(id="T1018", framework_id="mitre_attack", parent_id="TA0007", title="Remote System Discovery",
            description="Adversaries may attempt to get a listing of other systems by IP address or hostname."),

    # =========================================================================
    # TA0008 — Lateral Movement
    # =========================================================================
    Control(id="T1021", framework_id="mitre_attack", parent_id="TA0008", title="Remote Services",
            description="Adversaries may use valid accounts to log into a service for lateral movement."),
    Control(id="T1570", framework_id="mitre_attack", parent_id="TA0008", title="Lateral Tool Transfer",
            description="Adversaries may transfer tools or files between systems in a compromised environment."),
    Control(id="T1550", framework_id="mitre_attack", parent_id="TA0008", title="Use Alternate Authentication Material",
            description="Adversaries may use alternate authentication material to move laterally."),

    # =========================================================================
    # TA0009 — Collection
    # =========================================================================
    Control(id="T1560", framework_id="mitre_attack", parent_id="TA0009", title="Archive Collected Data",
            description="Adversaries may compress and/or encrypt data prior to exfiltration."),
    Control(id="T1005", framework_id="mitre_attack", parent_id="TA0009", title="Data from Local System",
            description="Adversaries may search local system sources to find files of interest."),
    Control(id="T1114", framework_id="mitre_attack", parent_id="TA0009", title="Email Collection",
            description="Adversaries may target user email to collect sensitive information."),

    # =========================================================================
    # TA0011 — Command and Control
    # =========================================================================
    Control(id="T1071", framework_id="mitre_attack", parent_id="TA0011", title="Application Layer Protocol",
            description="Adversaries may communicate using application layer protocols to avoid detection."),
    Control(id="T1105", framework_id="mitre_attack", parent_id="TA0011", title="Ingress Tool Transfer",
            description="Adversaries may transfer tools or files from an external system into a compromised environment."),
    Control(id="T1572", framework_id="mitre_attack", parent_id="TA0011", title="Protocol Tunneling",
            description="Adversaries may tunnel network communications to avoid detection."),
    Control(id="T1090", framework_id="mitre_attack", parent_id="TA0011", title="Proxy",
            description="Adversaries may use a connection proxy to direct network traffic between systems."),

    # =========================================================================
    # TA0010 — Exfiltration
    # =========================================================================
    Control(id="T1041", framework_id="mitre_attack", parent_id="TA0010", title="Exfiltration Over C2 Channel",
            description="Adversaries may steal data by exfiltrating it over an existing command and control channel."),
    Control(id="T1567", framework_id="mitre_attack", parent_id="TA0010", title="Exfiltration Over Web Service",
            description="Adversaries may use an existing, legitimate external Web service to exfiltrate data."),
    Control(id="T1048", framework_id="mitre_attack", parent_id="TA0010", title="Exfiltration Over Alternative Protocol",
            description="Adversaries may steal data by exfiltrating it over a different protocol than existing C2."),

    # =========================================================================
    # TA0040 — Impact
    # =========================================================================
    Control(id="T1486", framework_id="mitre_attack", parent_id="TA0040", title="Data Encrypted for Impact",
            description="Adversaries may encrypt data on target systems to interrupt system and network availability."),
    Control(id="T1489", framework_id="mitre_attack", parent_id="TA0040", title="Service Stop",
            description="Adversaries may stop or disable services on a system to render those services unavailable."),
    Control(id="T1485", framework_id="mitre_attack", parent_id="TA0040", title="Data Destruction",
            description="Adversaries may destroy data and files on specific systems or in large numbers."),
    Control(id="T1490", framework_id="mitre_attack", parent_id="TA0040", title="Inhibit System Recovery",
            description="Adversaries may delete or remove built-in data for operating system recovery."),
]

# Tactic metadata for coverage matrix
MITRE_TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

MITRE_ATTACK = Framework(
    id="mitre_attack",
    name="MITRE ATT&CK Enterprise",
    version="14.1",
    structure_type="matrix",
    controls=_CONTROLS,
)

_register(MITRE_ATTACK)
