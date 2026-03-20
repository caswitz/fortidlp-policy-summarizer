"""Data models for FortiDLP policy analysis."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyAction:
    """Represents a configured action on a policy."""
    action_type: str
    config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"action_type": self.action_type, "config": self.config}

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyAction":
        return cls(action_type=d["action_type"], config=d.get("config", {}))


@dataclass
class MitreIndicator:
    """Parsed MITRE ATT&CK indicator."""
    tactic_id: str
    technique_id: str
    subtechnique_id: Optional[str] = None
    raw: str = ""

    def to_dict(self) -> dict:
        d = {"tactic_id": self.tactic_id, "technique_id": self.technique_id, "raw": self.raw}
        if self.subtechnique_id:
            d["subtechnique_id"] = self.subtechnique_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MitreIndicator":
        return cls(
            tactic_id=d["tactic_id"], technique_id=d["technique_id"],
            subtechnique_id=d.get("subtechnique_id"), raw=d.get("raw", ""),
        )


# Maps MITRE tactic IDs to human-readable names
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Common MITRE technique IDs to names (subset covering FortiDLP policy space)
MITRE_TECHNIQUES = {
    "T1005": "Data from Local System",
    "T1008": "Fallback Channels",
    "T1010": "Application Window Discovery",
    "T1012": "Query Registry",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1020": "Automated Exfiltration",
    "T1021": "Remote Services",
    "T1025": "Data from Removable Media",
    "T1027": "Obfuscated Files or Information",
    "T1030": "Data Transfer Size Limits",
    "T1036": "Masquerading",
    "T1037": "Boot or Logon Initialization Scripts",
    "T1039": "Data from Network Shared Drive",
    "T1040": "Network Sniffing",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1052": "Exfiltration Over Physical Medium",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1056": "Input Capture",
    "T1057": "Process Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1069": "Permission Groups Discovery",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1074": "Data Staged",
    "T1078": "Valid Accounts",
    "T1080": "Taint Shared Content",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1090": "Proxy",
    "T1091": "Replication Through Removable Media",
    "T1095": "Non-Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1102": "Web Service",
    "T1104": "Multi-Stage Channels",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1112": "Modify Registry",
    "T1113": "Screen Capture",
    "T1114": "Email Collection",
    "T1115": "Clipboard Data",
    "T1119": "Automated Collection",
    "T1120": "Peripheral Device Discovery",
    "T1123": "Audio Capture",
    "T1125": "Video Capture",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1129": "Shared Modules",
    "T1133": "External Remote Services",
    "T1134": "Access Token Manipulation",
    "T1135": "Network Share Discovery",
    "T1136": "Create Account",
    "T1137": "Office Application Startup",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1176": "Browser Extensions",
    "T1185": "Browser Session Hijacking",
    "T1187": "Forced Authentication",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1197": "BITS Jobs",
    "T1199": "Trusted Relationship",
    "T1200": "Hardware Additions",
    "T1201": "Password Policy Discovery",
    "T1202": "Indirect Command Execution",
    "T1203": "Exploitation for Client Execution",
    "T1204": "User Execution",
    "T1207": "Rogue Domain Controller",
    "T1210": "Exploitation of Remote Services",
    "T1211": "Exploitation for Defense Evasion",
    "T1213": "Data from Information Repositories",
    "T1218": "System Binary Proxy Execution",
    "T1219": "Remote Access Software",
    "T1220": "XSL Script Processing",
    "T1221": "Template Injection",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement",
    "T1496": "Resource Hijacking",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1498": "Network Denial of Service",
    "T1499": "Endpoint Denial of Service",
    "T1505": "Server Software Component",
    "T1518": "Software Discovery",
    "T1525": "Implant Internal Image",
    "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal",
    "T1534": "Internal Spearphishing",
    "T1537": "Transfer Data to Cloud Account",
    "T1539": "Steal Web Session Cookie",
    "T1542": "Pre-OS Boot",
    "T1543": "Create or Modify System Process",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Unsecured Credentials",
    "T1553": "Subvert Trust Controls",
    "T1555": "Credentials from Password Stores",
    "T1556": "Modify Authentication Process",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1559": "Inter-Process Communication",
    "T1560": "Archive Collected Data",
    "T1561": "Disk Wipe",
    "T1562": "Impair Defenses",
    "T1563": "Remote Service Session Hijacking",
    "T1564": "Hide Artifacts",
    "T1565": "Data Manipulation",
    "T1566": "Phishing",
    "T1567": "Exfiltration Over Web Service",
    "T1568": "Dynamic Resolution",
    "T1569": "System Services",
    "T1570": "Lateral Tool Transfer",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1573": "Encrypted Channel",
    "T1574": "Hijack Execution Flow",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1580": "Cloud Infrastructure Discovery",
    "T1583": "Acquire Infrastructure",
    "T1588": "Obtain Capabilities",
    "T1595": "Active Scanning",
    "T1598": "Phishing for Information",
    "T1599": "Network Boundary Bridging",
    "T1600": "Weaken Encryption",
    "T1602": "Data from Configuration Repository",
    "T1606": "Forge Web Credentials",
    "T1608": "Stage Capabilities",
    "T1609": "Container Administration Command",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
    "T1612": "Build Image on Host",
    "T1613": "Container and Resource Discovery",
    "T1614": "System Location Discovery",
}


def parse_mitre_indicator(raw: str) -> Optional[MitreIndicator]:
    """Parse a MITRE indicator string like 'mitre:ta0005/t1562.001'."""
    if not raw.startswith("mitre:"):
        return None
    parts = raw[6:].upper().split("/")
    if len(parts) < 2:
        return None
    tactic_id = parts[0]
    technique_parts = parts[1].split(".")
    technique_id = technique_parts[0]
    subtechnique_id = f"{technique_id}.{technique_parts[1]}" if len(technique_parts) > 1 else None
    return MitreIndicator(
        tactic_id=tactic_id,
        technique_id=technique_id,
        subtechnique_id=subtechnique_id,
        raw=raw,
    )


def mitre_display(indicator: MitreIndicator) -> str:
    """Format a MITRE indicator for display."""
    tactic_name = MITRE_TACTICS.get(indicator.tactic_id, indicator.tactic_id)
    technique_name = MITRE_TECHNIQUES.get(indicator.technique_id, indicator.technique_id)
    ref = indicator.subtechnique_id or indicator.technique_id
    return f"{indicator.tactic_id} ({tactic_name}) / {ref} ({technique_name})"


# Security category mapping from FortiDLP tags
TAG_CATEGORIES = {
    "systemsecurity": "System Security",
    "datasecurity": "Data Security",
    "dataloss": "Data Loss Prevention",
    "dataexfiltration": "Data Exfiltration Prevention",
    "insiderthreat": "Insider Threat",
    "compliance": "Compliance",
    "networksecurity": "Network Security",
    "endpointsecurity": "Endpoint Security",
    "browsersecurity": "Browser Security",
    "emailsecurity": "Email Security",
    "cloudaccess": "Cloud Access Security",
    "threatdetection": "Threat Detection",
    "useractivity": "User Activity Monitoring",
    "privilegedaccess": "Privileged Access Monitoring",
    "antitamper": "Anti-Tamper",
    "physicalsecurity": "Physical Security",
}


def severity_label(score: int) -> str:
    """Convert a numeric risk score to a severity label."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    return "Informational"


@dataclass
class ParsedPolicy:
    """A fully parsed policy ready for reporting."""
    name: str
    description: str
    enabled: bool
    group_name: str
    group_description: str
    group_labels: list = field(default_factory=list)
    risk_score: int = 0
    severity: str = "Informational"
    tags: list = field(default_factory=list)
    security_categories: list = field(default_factory=list)
    detection_description_template: str = ""
    mitre_indicators: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    template_id: str = ""
    template_language: str = ""
    pack_id: str = ""
    clustering_rules: list = field(default_factory=list)
    requirements: list = field(default_factory=list)
    raw_parameters: list = field(default_factory=list)  # Original parameter definitions
    raw_parameter_values: dict = field(default_factory=dict)  # Original parameterValues
    explanation: str = ""  # Generated English explanation of detection logic

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "group_name": self.group_name,
            "group_description": self.group_description,
            "group_labels": self.group_labels,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "tags": self.tags,
            "security_categories": self.security_categories,
            "detection_description_template": self.detection_description_template,
            "mitre_indicators": [m.to_dict() for m in self.mitre_indicators],
            "actions": [a.to_dict() for a in self.actions],
            "template_id": self.template_id,
            "template_language": self.template_language,
            "pack_id": self.pack_id,
            "clustering_rules": self.clustering_rules,
            "requirements": self.requirements,
            "explanation": self.explanation,
            "raw_parameters": self.raw_parameters,
            "raw_parameter_values": self.raw_parameter_values,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ParsedPolicy":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            enabled=d.get("enabled", True),
            group_name=d.get("group_name", ""),
            group_description=d.get("group_description", ""),
            group_labels=d.get("group_labels", []),
            risk_score=d.get("risk_score", 0),
            severity=d.get("severity", "Informational"),
            tags=d.get("tags", []),
            security_categories=d.get("security_categories", []),
            detection_description_template=d.get("detection_description_template", ""),
            mitre_indicators=[MitreIndicator.from_dict(m) for m in d.get("mitre_indicators", [])],
            actions=[PolicyAction.from_dict(a) for a in d.get("actions", [])],
            template_id=d.get("template_id", ""),
            template_language=d.get("template_language", ""),
            pack_id=d.get("pack_id", ""),
            clustering_rules=d.get("clustering_rules", []),
            requirements=d.get("requirements", []),
            explanation=d.get("explanation", ""),
            raw_parameters=d.get("raw_parameters", []),
            raw_parameter_values=d.get("raw_parameter_values", {}),
        )


@dataclass
class ParsedGroup:
    """A parsed policy group."""
    name: str
    description: str
    labels: list = field(default_factory=list)
    policies: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "labels": self.labels,
            "policies": [p.to_dict() for p in self.policies],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ParsedGroup":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            labels=d.get("labels", []),
            policies=[ParsedPolicy.from_dict(p) for p in d.get("policies", [])],
        )
