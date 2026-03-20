"""Parse FortiDLP .policies export files."""

import gzip
import io
import json
import tarfile
from pathlib import Path

from .models import (
    ParsedGroup,
    ParsedPolicy,
    PolicyAction,
    parse_mitre_indicator,
    severity_label,
    TAG_CATEGORIES,
)


# Maps known action type keys to human-readable names
ACTION_TYPE_NAMES = {
    "blockBrowserDownload": "Block browser download",
    "blockBrowserUpload": "Block browser upload",
    "blockEmail": "Block email",
    "blockOutboundEmail": "Block outbound email",
    "blockPrintJob": "Block print job",
    "blockUsbMount": "Block USB storage device mounting",
    "blockFileTransferToUsb": "Block file transfer to USB",
    "captureClipboardEvidence": "Capture clipboard evidence",
    "captureFileEvidence": "Capture file evidence",
    "captureScreenshotEvidence": "Capture screenshot evidence",
    "displayMessage": "Display on-screen message",
    "emptyClipboard": "Empty clipboard",
    "isolate": "Isolate device (network isolation)",
    "killProcess": "Kill process",
    "lock": "Lock keyboard/mouse",
    "reboot": "Restart device",
}


def extract_policy_data(filepath: Path) -> dict:
    """Extract JSON data from a .policies file (gzip'd tar containing 'data')."""
    with gzip.open(filepath, "rb") as gz:
        tar_bytes = gz.read()
    tar_buffer = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=tar_buffer, mode="r:") as tar:
        data_member = tar.getmember("data")
        data_file = tar.extractfile(data_member)
        return json.loads(data_file.read())


def _parse_actions(action_value: dict) -> list[PolicyAction]:
    """Parse action configuration from parameterValues.action."""
    actions = []
    actions_value = action_value.get("actionsValue", {})

    # New format: {"value": [{"type": "message", "actionData": "..."}, {"type": "screenshot"}]}
    if "value" in actions_value and isinstance(actions_value["value"], list):
        for action_entry in actions_value["value"]:
            action_type = action_entry.get("type", "unknown")
            action_name = ACTION_TYPE_NAMES.get(action_type, action_type.replace("_", " ").title())
            config = {}
            if "actionData" in action_entry:
                try:
                    config = json.loads(action_entry["actionData"])
                except (json.JSONDecodeError, TypeError):
                    config = {"raw": action_entry["actionData"]}
            actions.append(PolicyAction(action_type=action_name, config=config))
        return actions

    # Legacy format: direct keys in actionsValue
    for key, config in actions_value.items():
        if key == "rateLimit":
            continue
        action_name = ACTION_TYPE_NAMES.get(key, key)
        actions.append(PolicyAction(action_type=action_name, config=config if isinstance(config, dict) else {}))
    return actions



def parse_policy_file(filepath: Path) -> list[ParsedGroup]:
    """Parse a .policies file and return a list of ParsedGroups."""
    data = extract_policy_data(filepath)
    groups = []

    for group_data in data.get("groups", []):
        group_info = group_data.get("group", {})
        group_name = group_info.get("name", "Unknown")
        group_desc = group_info.get("description", "")
        include_labels = group_info.get("includeLabels") or []
        label_names = [lbl.get("name", "") for lbl in include_labels if isinstance(lbl, dict)]

        parsed_policies = []
        for policy_entry in group_data.get("policies", []):
            pol = policy_entry.get("policy", {})
            param_values = pol.get("parameterValues", {})

            # Extract sensor/detection config
            sensor = param_values.get("sensor", {}).get("sensorValue", {})
            risk_score = sensor.get("score", 0)
            tags = sensor.get("tags", [])
            indicators_raw = sensor.get("indicators", [])
            detection_desc = sensor.get("description", "")

            # Parse MITRE indicators from both indicators array and tags
            mitre_indicators = []
            seen_mitre = set()
            for ind in indicators_raw:
                parsed = parse_mitre_indicator(ind)
                if parsed and parsed.raw not in seen_mitre:
                    mitre_indicators.append(parsed)
                    seen_mitre.add(parsed.raw)
            # Also extract mitre: prefixed tags
            for tag in tags:
                if tag.startswith("mitre:") and tag not in seen_mitre:
                    parsed = parse_mitre_indicator(tag)
                    if parsed:
                        mitre_indicators.append(parsed)
                        seen_mitre.add(tag)

            display_tags = tags

            # Parse actions
            action_value = param_values.get("action", {})
            actions = _parse_actions(action_value)

            # Derive security categories from tags
            security_cats = []
            for tag in tags:
                cat = TAG_CATEGORIES.get(tag.lower())
                if cat:
                    security_cats.append(cat)
            if not security_cats:
                security_cats = ["General Security"]

            parameters = pol.get("parameters", [])

            # Requirements
            requirements = pol.get("requirements", [])
            if isinstance(requirements, dict):
                requirements = [requirements]

            parsed_policies.append(ParsedPolicy(
                name=pol.get("name", "Unnamed"),
                description=pol.get("description", ""),
                enabled=pol.get("enabled", False),
                group_name=group_name,
                group_description=group_desc,
                group_labels=label_names,
                risk_score=risk_score,
                severity=severity_label(risk_score),
                tags=display_tags,
                security_categories=security_cats,
                detection_description_template=detection_desc,
                mitre_indicators=mitre_indicators,
                actions=actions,
                template_id=pol.get("templateId", ""),
                template_language=pol.get("templateLanguage", ""),
                pack_id=pol.get("packId", ""),
                clustering_rules=list(pol.get("clusteringRules", {}).keys()),
                requirements=requirements,
                raw_parameters=parameters,
                raw_parameter_values=param_values,
            ))

        groups.append(ParsedGroup(
            name=group_name,
            description=group_desc,
            labels=label_names,
            policies=parsed_policies,
        ))

    return groups


def parse_all_policy_files(directory: Path) -> list[ParsedGroup]:
    """Parse all .policies files in a directory."""
    all_groups = []
    for filepath in sorted(directory.glob("*.policies")):
        groups = parse_policy_file(filepath)
        all_groups.extend(groups)
    return all_groups
