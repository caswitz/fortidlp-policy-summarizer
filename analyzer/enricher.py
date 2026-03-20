"""Enrich parsed policies with detection logic explanations."""

from .models import ParsedGroup, ParsedPolicy


def enrich_policies(groups: list[ParsedGroup]) -> list[ParsedGroup]:
    """Enrich all policies in groups with English explanations of detection logic."""
    for group in groups:
        for policy in group.policies:
            policy.explanation = explain_policy_logic(policy)

    return groups


# --- Detection logic explanation engine ---

# Human-readable labels for parameter semantic roles
_PARAM_ROLE_LABELS = {
    # Deny-mode params: what triggers detection
    "deny": {
        "application_name_list": "Triggers when any of these applications are used",
        "application_id_list": "Triggers for these specific application versions",
        "application_path_list": "Triggers when applications at these paths are used",
        "binary_name_list": "Triggers when these processes are involved",
        "binary_path_list": "Triggers when processes at these paths are involved",
        "called_path_list": "Triggers when command matches these patterns",
        "domain_list": "Monitors these websites/URLs",
        "url_list": "Monitors URLs matching these patterns",
        "tab_title_list": "Monitors browser tabs with these titles",
        "file_path_list": "Monitors files at these paths",
        "file_extension_list": "Monitors these file extensions",
        "mime_type_list": "Monitors these file types",
        "source_file_path_list": "Monitors files copied/moved from these locations",
        "target_file_path_list": "Monitors files copied/moved to these locations",
        "username_list": "Targets these user accounts",
        "username_regex_list": "Targets users matching these patterns",
        "uid_list": "Targets these user identifiers (SID)",
        "ip_address_list": "Monitors connections to/from these IP addresses",
        "port_list": "Monitors these network ports",
        "printer_name_list": "Monitors these printers",
        "usb_identifier_list": "Monitors these USB devices",
        "saas_apps": "Monitors these SaaS applications",
        "window_title_patterns": "Monitors windows with these titles",
        "parameter_list": "Monitors form fields matching these values",
        "recipient_domain_list": "Monitors emails to these domains",
        "sender_domain_list": "Monitors emails from these domains",
    },
    # Allow-mode params: exceptions that suppress detection
    "allow": {
        "application_name_list": "Exempt applications (will not trigger)",
        "application_id_list": "Exempt application versions",
        "application_path_list": "Exempt application paths",
        "binary_name_list": "Exempt processes (will not trigger)",
        "binary_path_list": "Exempt process paths",
        "called_path_list": "Exempt command patterns",
        "domain_list": "Exempt websites/URLs",
        "url_list": "Exempt URL patterns",
        "tab_title_list": "Exempt browser tab titles",
        "file_path_list": "Exempt file paths",
        "file_extension_list": "Exempt file extensions",
        "mime_type_list": "Exempt file types",
        "source_file_path_list": "Exempt source locations",
        "target_file_path_list": "Exempt destination locations",
        "username_list": "Exempt user accounts (will not trigger)",
        "username_regex_list": "Exempt username patterns",
        "uid_list": "Exempt user identifiers (SID)",
        "ip_address_list": "Exempt IP addresses",
        "port_list": "Exempt network ports",
        "printer_name_list": "Exempt printers",
        "usb_identifier_list": "Exempt USB devices",
        "saas_apps": "Exempt SaaS applications",
        "window_title_patterns": "Exempt window titles",
        "parameter_list": "Exempt form fields",
        "recipient_domain_list": "Exempt recipient domains",
        "sender_domain_list": "Exempt sender domains",
        "parent_application_name_list": "Exempt parent processes",
        "parent_application_path_list": "Exempt parent process paths",
        "account_list": "Exempt user account domains",
        "file_path_keywords": "Exempt file path keywords",
    },
}

# Boolean parameter labels (only mention when the value is notable)
_BOOL_LABELS = {
    "monitor_read": (True, "Monitors files opened for reading"),
    "monitor_write": (True, "Monitors files opened for writing"),
    "monitor_rename": (True, "Monitors file renames"),
    "monitor_move": (True, "Monitors file moves"),
    "monitor_copy": (True, "Monitors file copies"),
    "only_track_network_share": (True, "Only monitors network share activity"),
    "allow_service_accounts": (True, "Ignores system service accounts"),
    "allow_admin_to_run_application": (True, "Ignores administrator accounts"),
    "include_unknown_account": (True, "Includes unknown user accounts"),
    "group_sensors": (True, "Groups detections within time window"),
}


def _get_role_label(mode: str, param_name: str, param_label: str) -> str:
    """Get the best human-readable role label for a parameter.

    Uses the static mapping first, then falls back to the parameter's own label
    from the FortiDLP template definition.
    """
    # Check if the param label hints at a different role than the name
    # e.g., application_path_list labeled "Called paths" is about command patterns, not app paths
    label_lower = param_label.lower()
    if "called path" in label_lower:
        if mode == "deny":
            return "Triggers when command matches these patterns"
        else:
            return "Exempt command patterns"

    mapped = _PARAM_ROLE_LABELS.get(mode, {}).get(param_name)
    if mapped:
        return mapped

    # Fallback: use the parameter's own label
    if mode == "deny":
        return f"Triggers on matching {param_label}"
    else:
        return f"Exempt {param_label}"


def _format_value_display(custom_values: list, asset_names: list, data_objects: list) -> str:
    """Format values, assets, and data objects for display."""
    parts = []
    if custom_values:
        # Check if values look like hashes (long hex strings) — show count instead
        if all(len(str(v)) > 40 and all(c in "0123456789abcdefv." for c in str(v).lower()) for v in custom_values):
            parts.append(f"{len(custom_values)} application signature(s)")
        else:
            parts.append(_format_values(custom_values))
    if asset_names:
        parts.append(f"using assets: {', '.join(asset_names)}")
    if data_objects and not custom_values and not asset_names:
        parts.append(f"{len(data_objects)} predefined asset(s) referenced")
    return "; ".join(parts)


def _format_values(values: list) -> str:
    """Format a list of values for display."""
    if not values:
        return ""
    clean = [str(v).strip() for v in values if v]
    return ", ".join(f"`{v}`" for v in clean)


def explain_policy_logic(policy: ParsedPolicy) -> str:
    """Generate an English-language explanation of how a policy's detection logic works."""
    params = policy.raw_parameters
    param_values = policy.raw_parameter_values
    if not params or not param_values:
        return ""

    triggers = []     # Deny-mode params with values: what triggers detection
    exceptions = []   # Allow-mode params with values: what's excluded
    content_info = [] # Content inspection details
    settings = []     # Boolean toggles, thresholds, etc.
    customizable = [] # Empty parameter slots available for configuration

    for param in params:
        name = param.get("name", "")
        label = param.get("label", name)
        if name in ("action", "sensor"):
            continue

        value = param_values.get(name, {})
        if not value:
            continue

        # --- String data object list (allow/deny lists) ---
        if "stringDataObjectListValue" in value:
            slv = value["stringDataObjectListValue"]
            behavior = slv.get("behavior", "")
            custom_values = slv.get("customValues", [])
            assets = slv.get("assets", [])
            data_objects = slv.get("dataObjects", [])
            asset_names = [a.get("name", a.get("id", "?")) for a in assets] if assets else []
            has_values = bool(custom_values or asset_names or data_objects)

            # Content inspection has special "regex_keyword" behavior
            if behavior == "regex_keyword" or name in ("regex_list", "keywords_list"):
                _handle_content_param(name, label, slv, data_objects, custom_values, asset_names, content_info)
                continue

            if not has_values:
                if behavior:
                    role = "allow list" if behavior == "allow" else "deny list"
                    customizable.append(f"{label} ({role})")
                continue

            if behavior == "deny" or (not behavior and has_values):
                role_label = _get_role_label("deny", name, label)
                val_display = _format_value_display(custom_values, asset_names, data_objects)
                triggers.append(f"{role_label}: {val_display}" if val_display else role_label)

            elif behavior == "allow":
                role_label = _get_role_label("allow", name, label)
                val_display = _format_value_display(custom_values, asset_names, data_objects)
                exceptions.append(f"{role_label}: {val_display}" if val_display else role_label)

        # --- Content inspection value ---
        elif "contentInspectionValue" in value:
            civ = value["contentInspectionValue"]
            _handle_content_inspection_value(civ, content_info)

        # --- SaaS app filter ---
        elif "saasAppFilter" in value:
            saf = value["saasAppFilter"]
            behavior = saf.get("behavior", "")
            if saf.get("saasAppConditions") or saf.get("saasApps"):
                if behavior == "deny" or not behavior:
                    triggers.append(f"Monitors specific SaaS applications")
                elif behavior == "allow":
                    exceptions.append(f"Exempt SaaS applications configured")

        # --- Simple string values ---
        elif "stringValue" in value:
            sv = value["stringValue"]
            if name == "match_type":
                content_info.append(f"Match requirement: **{sv}**")
            elif sv:
                settings.append(f"{label}: {sv}")

        # --- Numeric values ---
        elif "integerValue" in value or "intValue" in value:
            iv = value.get("integerValue", value.get("intValue", 0))
            val = iv.get("value", iv) if isinstance(iv, dict) else iv
            if name == "match_frequency" and val and val > 1:
                content_info.append(f"Each pattern/keyword must appear at least **{val}** times to trigger")
            elif name == "group_time_window_seconds" and val:
                settings.append(f"Detection grouping window: {val} seconds")
            elif name == "max_file_size":
                if val and val > 0:
                    settings.append(f"Only monitors files up to {val} MB")
            elif val and name not in ("match_frequency", "group_time_window_seconds", "max_file_size"):
                settings.append(f"{label}: {val}")

        elif "floatValue" in value:
            fv = value["floatValue"]
            val = fv.get("value", fv) if isinstance(fv, dict) else fv
            if name == "max_file_size":
                if val and val > 0:
                    settings.append(f"Only monitors files up to {val} MB")
            elif val:
                settings.append(f"{label}: {val}")

        # --- Boolean values ---
        elif "booleanValue" in value or "boolValue" in value:
            bv = value.get("booleanValue", value.get("boolValue", False))
            val = bv.get("value", bv) if isinstance(bv, dict) else bv
            if name in _BOOL_LABELS:
                notable_when, description = _BOOL_LABELS[name]
                if val == notable_when:
                    settings.append(description)

        # --- String list values (simple lists like tampering actions) ---
        elif "stringListValue" in value:
            slv = value["stringListValue"]
            vals = slv.get("value", [])
            if vals:
                triggers.append(f"{label}: {', '.join(str(v) for v in vals)}")

        # --- Data object list ---
        elif "dataObjectListValue" in value:
            dov = value["dataObjectListValue"]
            objs = dov.get("dataObjects", [])
            if objs:
                obj_names = [o.get("name", "?") for o in objs if isinstance(o, dict)]
                if obj_names:
                    triggers.append(f"{label}: {', '.join(obj_names)}")

    # --- Assemble the explanation ---
    parts = []

    if triggers:
        parts.append("**Triggers when:**")
        for t in triggers:
            parts.append(f"- {t}")

    if content_info:
        parts.append("")
        parts.append("**Content inspection:**")
        for c in content_info:
            parts.append(f"- {c}")

    if exceptions:
        parts.append("")
        parts.append("**Exceptions (will not trigger):**")
        for e in exceptions:
            parts.append(f"- {e}")

    if settings:
        parts.append("")
        parts.append("**Additional settings:**")
        for s in settings:
            parts.append(f"- {s}")

    if customizable:
        parts.append("")
        parts.append("**Customizable (not configured):**")
        for c in customizable:
            parts.append(f"- {c}")

    return "\n".join(parts)


def _handle_content_param(name, label, slv, data_objects, custom_values, asset_names, content_info):
    """Handle content inspection regex/keyword parameters."""
    if name == "regex_list":
        if custom_values:
            if custom_values == [".*"]:
                content_info.append("Content patterns: matches **all content** (wildcard `.*`)")
            else:
                content_info.append(f"Content patterns: {_format_values(custom_values)}")
        if asset_names:
            content_info.append(f"Content pattern assets: {', '.join(asset_names)}")
        if data_objects and not custom_values and not asset_names:
            content_info.append(f"Content patterns: {len(data_objects)} predefined asset(s) referenced")
    elif name == "keywords_list":
        if custom_values:
            content_info.append(f"Content keywords: {_format_values(custom_values)}")
        if asset_names:
            content_info.append(f"Content keyword assets: {', '.join(asset_names)}")
        if data_objects and not custom_values and not asset_names:
            content_info.append(f"Content keywords: {len(data_objects)} predefined asset(s) referenced")


def _handle_content_inspection_value(civ, content_info):
    """Handle contentInspectionValue parameter type."""
    patterns = civ.get("patterns", {})
    if patterns.get("assets"):
        names = [a.get("name", "?") for a in patterns["assets"]]
        content_info.append(f"Content patterns: {', '.join(names)}")
    if patterns.get("customValues"):
        content_info.append(f"Custom content patterns: {_format_values(patterns['customValues'])}")

    keywords = civ.get("keywords", {})
    if keywords.get("assets"):
        names = [a.get("name", "?") for a in keywords["assets"]]
        content_info.append(f"Content keywords: {', '.join(names)}")
    if keywords.get("customValues"):
        content_info.append(f"Custom keywords: {_format_values(keywords['customValues'])}")

    labels = civ.get("sensitivityLabels", {})
    if labels.get("labels"):
        label_names = [l.get("name", l.get("id", "?")) for l in labels["labels"] if isinstance(l, dict)]
        content_info.append(f"Microsoft sensitivity labels: {', '.join(label_names)}")

    match_type = civ.get("matchType", "")
    if match_type:
        content_info.append(f"Match requirement: **{match_type}**")
