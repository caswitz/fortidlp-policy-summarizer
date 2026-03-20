"""Report generation for FortiDLP policy analysis."""

import html
import re
from datetime import datetime
from pathlib import Path

from .models import MITRE_TACTICS, ParsedGroup, ParsedPolicy, mitre_display, severity_label


def _generate_flowchart_svg() -> str:
    """Generate an inline SVG flowchart for the Detection Flow section."""
    # Layout constants
    cx = 340        # center x for main column (shifted right for left branch)
    box_w = 340     # main box width
    box_h = 56      # main box height (single line)
    box_h2 = 68     # main box height (two lines)
    dec_w = 200     # decision box width
    dec_h = 48      # decision box height
    arrow_len = 24  # arrow connector length
    r = 6           # corner radius

    # Left branch (Activity Feed)
    log_cx = 65     # center x for Investigate box
    log_w = 130     # width of Investigate box
    log_h = 56      # height of Investigate box
    log_fill = '#d4edda'
    log_stroke = '#28a745'

    # Y positions (top of each element)
    y1 = 10                                  # Activity on endpoint
    y1_bot = y1 + box_h2
    a1_top = y1_bot + 2                      # arrow 1
    a1_bot = a1_top + arrow_len
    y2 = a1_bot + 2                          # Policy conditions
    y2_bot = y2 + box_h2
    a2_top = y2_bot + 2                      # arrow 2
    a2_bot = a2_top + arrow_len
    y3 = a2_bot + 2                          # All match? decision
    y3_bot = y3 + dec_h
    y3_mid = y3 + dec_h // 2                 # vertical center of decision

    # Branch: Yes (down from decision)
    a3_top = y3_bot + 2
    a3_bot = a3_top + arrow_len
    y4 = a3_bot + 2                          # Detection created
    y4_bot = y4 + box_h
    a4_top = y4_bot + 2
    a4_bot = a4_top + arrow_len
    y5 = a4_bot + 2                          # Actions fire
    y5_bot = y5 + box_h
    a5_top = y5_bot + 2
    a5_bot = a5_top + arrow_len
    y6 = a5_bot + 2                          # Raise incident enabled? decision
    y6_bot = y6 + dec_h
    y6_mid = y6 + dec_h // 2                 # vertical center of decision

    # Yes arrow (down from incident decision)
    a6_top = y6_bot + 2
    a6_bot = a6_top + arrow_len
    y7 = a6_bot + 2                          # Incident created
    y7_bot = y7 + box_h2

    # Branch: No (right from decision)
    no_cx = cx + box_w // 2 + 80             # center of "No detection" box
    no_w = 160
    no_h = 46

    # Left branch: Investigate box centered on the fork arrow Y
    fork_y = a1_top + arrow_len // 2
    log_y = fork_y - log_h // 2

    total_w = no_cx + no_w // 2 + 20
    total_h = y7_bot + 10

    # Colors
    step_fill = '#fafafa'
    step_stroke = '#aaa'
    det_fill = '#e8f4f8'       # detection created — prominent
    det_stroke = '#2980b9'
    inc_fill = '#f5f5f5'       # incident — conditional/optional
    inc_stroke = '#999'
    dec_fill = '#fff3cd'
    dec_stroke = '#e9c46a'
    no_fill = '#f8d7da'
    no_stroke = '#d9534f'
    arrow_color = '#555'
    text_color = '#1d3557'
    sub_color = '#555'

    lines = []
    lines.append(f'<svg class="flowchart" viewBox="-10 0 {total_w + 10} {total_h}" '
                 f'style="display:block;max-width:700px;margin:16px auto;" '
                 f'xmlns="http://www.w3.org/2000/svg">')
    lines.append('<title>Detection Flow</title>')

    # Arrowhead markers
    lines.append('<defs>')
    lines.append(f'<marker id="ah" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">')
    lines.append(f'<path d="M0,0 L8,3 L0,6 Z" fill="{arrow_color}"/>')
    lines.append('</marker>')
    lines.append(f'<marker id="ah-no" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">')
    lines.append(f'<path d="M0,0 L8,3 L0,6 Z" fill="{no_stroke}"/>')
    lines.append('</marker>')
    lines.append(f'<marker id="ah-log" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">')
    lines.append(f'<path d="M0,0 L8,3 L0,6 Z" fill="{log_stroke}"/>')
    lines.append('</marker>')
    lines.append(f'<marker id="ah-inc" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">')
    lines.append(f'<path d="M0,0 L8,3 L0,6 Z" fill="{inc_stroke}"/>')
    lines.append('</marker>')
    lines.append('</defs>')

    def box(x, y, w, h, fill, stroke, text1, text2=None):
        bx = x - w // 2
        lines.append(f'<rect x="{bx}" y="{y}" width="{w}" height="{h}" '
                     f'rx="{r}" fill="{fill}" stroke="{stroke}"/>')
        if text2:
            lines.append(f'<text x="{x}" y="{y + h // 2 - 6}" text-anchor="middle" '
                         f'font-size="13" font-family="system-ui,sans-serif" fill="{text_color}">{text1}</text>')
            lines.append(f'<text x="{x}" y="{y + h // 2 + 10}" text-anchor="middle" '
                         f'font-size="12" font-family="system-ui,sans-serif" fill="{sub_color}">{text2}</text>')
        else:
            lines.append(f'<text x="{x}" y="{y + h // 2 + 5}" text-anchor="middle" '
                         f'font-size="13" font-family="system-ui,sans-serif" fill="{text_color}">{text1}</text>')

    def arrow_down(x, y_top, y_bot, color=arrow_color, marker='ah'):
        lines.append(f'<line x1="{x}" y1="{y_top}" x2="{x}" y2="{y_bot}" '
                     f'stroke="{color}" stroke-width="1.5" marker-end="url(#{marker})"/>')

    # Step 1: Activity on endpoint
    box(cx, y1, box_w, box_h2, step_fill, step_stroke,
        'Activity on endpoint', 'file copy, upload, USB, etc.')

    # Fork arrow from step 1: down to step 2 AND left to Investigate box
    # Vertical segment down (main flow continues to step 2)
    lines.append(f'<line x1="{cx}" y1="{a1_top}" x2="{cx}" y2="{a1_bot}" '
                 f'stroke="{arrow_color}" stroke-width="1.5" marker-end="url(#ah)"/>')
    # Horizontal arrow left from fork point into the Investigate box
    # Draw line + manual arrowhead polygon (SVG markers create offset gaps)
    log_box_right = log_cx + log_w // 2
    lines.append(f'<line x1="{cx}" y1="{fork_y}" x2="{log_box_right + 8}" y2="{fork_y}" '
                 f'stroke="{log_stroke}" stroke-width="1.5"/>')
    # Arrowhead triangle pointing left, tip touching box right edge
    lines.append(f'<polygon points="{log_box_right},{fork_y} '
                 f'{log_box_right + 8},{fork_y - 4} '
                 f'{log_box_right + 8},{fork_y + 4}" '
                 f'fill="{log_stroke}"/>')

    # Investigate Activity Feed box (left branch, terminal)
    box(log_cx, log_y, log_w, log_h, log_fill, log_stroke,
        'Logged to Investigate', 'Activity Feed')

    # Step 2: Policy conditions
    box(cx, y2, box_w, box_h2, step_fill, step_stroke,
        'Policy conditions evaluated by Agent',
        'All configured conditions must be met for a detection')
    arrow_down(cx, a2_top, a2_bot)

    # Step 3: Decision — All match?
    box(cx, y3, dec_w, dec_h, dec_fill, dec_stroke, 'All match?')

    # Yes arrow (down)
    arrow_down(cx, a3_top, a3_bot)
    lines.append(f'<text x="{cx + 10}" y="{a3_top + arrow_len // 2 + 4}" '
                 f'font-size="12" font-family="system-ui,sans-serif" fill="{arrow_color}">Yes</text>')

    # No arrow (right from decision)
    no_line_x1 = cx + dec_w // 2 + 2
    no_line_x2 = no_cx - no_w // 2 - 10
    lines.append(f'<line x1="{no_line_x1}" y1="{y3_mid}" x2="{no_line_x2}" y2="{y3_mid}" '
                 f'stroke="{no_stroke}" stroke-width="1.5" marker-end="url(#ah-no)"/>')
    no_label_x = (no_line_x1 + no_line_x2) // 2
    lines.append(f'<text x="{no_label_x}" y="{y3_mid - 6}" text-anchor="middle" '
                 f'font-size="12" font-family="system-ui,sans-serif" fill="{no_stroke}">No</text>')

    # No detection box
    box(no_cx, y3_mid - no_h // 2, no_w, no_h, no_fill, no_stroke, 'No detection created')

    # Step 4: Detection created (key outcome — prominent color)
    box(cx, y4, box_w, box_h, det_fill, det_stroke,
        'Detection created with risk score and MITRE mapping')
    arrow_down(cx, a4_top, a4_bot)

    # Step 5: Actions fire
    box(cx, y5, box_w, box_h, step_fill, step_stroke, 'Actions fire (block, screenshot, notify)')
    arrow_down(cx, a5_top, a5_bot)

    # Step 6: Decision — Raise incident enabled?
    box(cx, y6, dec_w, dec_h, dec_fill, dec_stroke, 'Raise incident enabled?')

    # Yes arrow (down)
    arrow_down(cx, a6_top, a6_bot)
    lines.append(f'<text x="{cx + 10}" y="{a6_top + arrow_len // 2 + 4}" '
                 f'font-size="12" font-family="system-ui,sans-serif" fill="{arrow_color}">Yes</text>')

    # No arrow (right from incident decision) + circle terminator
    inc_no_x1 = cx + dec_w // 2 + 2
    inc_no_x2 = inc_no_x1 + 60
    lines.append(f'<line x1="{inc_no_x1}" y1="{y6_mid}" x2="{inc_no_x2 - 4}" y2="{y6_mid}" '
                 f'stroke="{inc_stroke}" stroke-width="1.5"/>')
    lines.append(f'<text x="{(inc_no_x1 + inc_no_x2) // 2}" y="{y6_mid - 6}" text-anchor="middle" '
                 f'font-size="12" font-family="system-ui,sans-serif" fill="{inc_stroke}">No</text>')
    lines.append(f'<circle cx="{inc_no_x2}" cy="{y6_mid}" r="4" fill="{inc_stroke}"/>')

    # Step 7: Incident created (conditional — dashed border)
    inc_bx = cx - box_w // 2
    lines.append(f'<rect x="{inc_bx}" y="{y7}" width="{box_w}" height="{box_h2}" '
                 f'rx="{r}" fill="{inc_fill}" stroke="{inc_stroke}" stroke-dasharray="6,3"/>')
    lines.append(f'<text x="{cx}" y="{y7 + box_h2 // 2 - 6}" text-anchor="middle" '
                 f'font-size="13" font-family="system-ui,sans-serif" fill="{text_color}">Incident created</text>')
    lines.append(f'<text x="{cx}" y="{y7 + box_h2 // 2 + 10}" text-anchor="middle" '
                 f'font-size="12" font-family="system-ui,sans-serif" fill="{sub_color}">standalone or clustered by rule</text>')

    # Legend (right side, below "No detection" box)
    leg_x = no_cx - 30
    leg_sq = 10
    leg_gap = 18
    leg_y0 = 20
    lines.append(f'<text x="{leg_x}" y="{leg_y0 - 8}" font-size="11" '
                 f'font-family="system-ui,sans-serif" font-weight="bold" fill="{sub_color}">Legend</text>')
    legend_items = [
        (log_fill, log_stroke, None, 'Always logged'),
        (det_fill, det_stroke, None, 'Key outcome'),
        (dec_fill, dec_stroke, None, 'Decision point'),
        (inc_fill, inc_stroke, '4,2', 'Config-dependent'),
        (no_fill, no_stroke, None, 'No match'),
    ]
    for i, (fill, stroke, dash, label) in enumerate(legend_items):
        sy = leg_y0 + i * leg_gap
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ''
        lines.append(f'<rect x="{leg_x}" y="{sy}" width="{leg_sq}" height="{leg_sq}" '
                     f'rx="2" fill="{fill}" stroke="{stroke}"{dash_attr}/>')
        lines.append(f'<text x="{leg_x + leg_sq + 6}" y="{sy + leg_sq - 1}" font-size="10" '
                     f'font-family="system-ui,sans-serif" fill="{sub_color}">{label}</text>')

    lines.append('</svg>')
    return '\n'.join(lines)


def _risk_bar(score: int) -> str:
    """Generate a 10-char visual risk bar using block characters."""
    filled = round(score / 10)
    return "▓" * filled + "░" * (10 - filled)


_SEVERITY_CSS_CLASS = {
    "Critical": "risk-critical",
    "High": "risk-high",
    "Medium": "risk-medium",
    "Low": "risk-low",
    "Info": "risk-info",
}


def _slug(text: str) -> str:
    """Convert text to a GitHub-flavored markdown anchor slug."""
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    return slug


_OS_NAMES = {"windows": "Windows", "linux": "Linux", "darwin": "macOS"}


def _format_requirements(requirements: list) -> str:
    """Format policy requirements (OS, agent version) for display."""
    parts = []
    for req in requirements:
        if not isinstance(req, str):
            continue
        req = req.strip()
        if req.startswith("os=="):
            os_val = req[4:].strip()
            parts.append(_OS_NAMES.get(os_val, os_val.capitalize()))
        elif req.startswith("os!="):
            os_val = req[4:].strip()
            excluded = _OS_NAMES.get(os_val, os_val.capitalize())
            parts.append(f"Not {excluded}")
        elif "agent_version" in req:
            # Handle "agent_version>=X" and "agent_version >= X"
            version = re.sub(r"agent_version\s*>=?\s*", "", req).strip()
            if version:
                parts.append(f"Agent {version}+")
    return ", ".join(parts)


def _compact_explanation(policy: ParsedPolicy) -> list[str]:
    """Convert the structured explanation into compact inline format."""
    if not policy.explanation:
        return []

    lines = []
    current_section = None
    section_items = []

    for raw_line in policy.explanation.split("\n"):
        line = raw_line.strip()
        if not line:
            continue

        # Detect section headers
        if line.startswith("**Triggers when:**"):
            if current_section and section_items:
                lines.append(_format_compact_section(current_section, section_items))
            current_section = "Triggers"
            section_items = []
        elif line.startswith("**Content inspection:**"):
            if current_section and section_items:
                lines.append(_format_compact_section(current_section, section_items))
            current_section = "Content inspection"
            section_items = []
        elif line.startswith("**Exceptions (will not trigger):**"):
            if current_section and section_items:
                lines.append(_format_compact_section(current_section, section_items))
            current_section = "Exceptions"
            section_items = []
        elif line.startswith("**Additional settings:**"):
            if current_section and section_items:
                lines.append(_format_compact_section(current_section, section_items))
            current_section = "Settings"
            section_items = []
        elif line.startswith("**Customizable (not configured):**"):
            if current_section and section_items:
                lines.append(_format_compact_section(current_section, section_items))
            current_section = "Customizable"
            section_items = []
        elif line.startswith("- "):
            item = line[2:].strip()
            section_items.append(item)

    # Flush last section
    if current_section and section_items:
        lines.append(_format_compact_section(current_section, section_items))

    return lines


_ALWAYS_BULLET_SECTIONS = {"Exceptions"}


def _format_compact_section(section: str, items: list) -> str:
    """Format a section's items as a bulleted list."""
    # Customizable slots render as a single comma-separated line
    if section == "Customizable":
        return f"**{section}:** {', '.join(items)}"

    if len(items) == 1 and section not in _ALWAYS_BULLET_SECTIONS:
        return f"**{section}:** {items[0]}"

    bullet_lines = [f"**{section}:**"]
    for item in items:
        bullet_lines.append(f"  - {item}")
    return "\n".join(bullet_lines)


def _format_action_inline(policy: ParsedPolicy) -> str:
    """Format actions as a compact inline string."""
    if not policy.actions:
        return "Monitor only"

    parts = []
    for action in policy.actions:
        name = action.action_type
        detail = ""
        if action.config:
            if "title" in action.config:
                detail = f" \"{action.config['title']}\""
            extras = []
            if action.config.get("acknowledge_label"):
                extras.append("acknowledgement")
            if action.config.get("response_label"):
                extras.append("justification")
            if extras:
                detail += f" (requires {', '.join(extras)})"
        parts.append(f"{name}{detail}")
    return "; ".join(parts)


# --- Main report generation ---

def generate_markdown_report(
    groups: list[ParsedGroup],
    show_status: bool = False,
    verbose: bool = False,
) -> str:
    """Generate a professional Markdown report from parsed policy groups."""
    lines = []

    # Header
    lines.append("# FortiDLP Policy Summary Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%B %d, %Y at %I:%M %p')}")
    lines.append("")

    # Table of Contents — compact HTML list
    lines.append("---")
    lines.append("")
    lines.append("## Table of Contents")
    lines.append("")
    lines.append('<div class="toc">')
    lines.append('<p class="toc-actions">'
                 '<a href="#" onclick="document.querySelectorAll(\'.toc-policies\').forEach(u=>u.style.display=\'block\');document.querySelectorAll(\'.toc-toggle\').forEach(t=>t.textContent=\'hide\');return false">Expand all</a> | '
                 '<a href="#" onclick="document.querySelectorAll(\'.toc-policies\').forEach(u=>u.style.display=\'none\');document.querySelectorAll(\'.toc-toggle\').forEach(t=>t.textContent=\'show\');return false">Collapse all</a></p>')
    lines.append('<ol class="toc-groups">')
    lines.append('<li><a href="#how-to-read-this-report">How to Read This Report</a></li>')
    for g in sorted(groups, key=lambda g: g.name):
        g_slug = _slug(g.name)
        filtered_labels = [l for l in g.labels if l and l.lower() != "null"]
        badge = f' <span class="toc-badge">{", ".join(filtered_labels)}</span>' if filtered_labels else ' <span class="toc-badge">All systems</span>'
        policy_items = ""
        for policy in sorted(g.policies, key=lambda p: (-p.risk_score, p.name)):
            p_slug = _slug(policy.name)
            policy_items += f'<li><a href="#{p_slug}">{policy.name}</a></li>'
        lines.append(f'<li><a href="#{g_slug}">{g.name}</a>{badge} <span class="toc-count">{len(g.policies)} policies</span> <span class="toc-toggle" onclick="var ul=this.nextElementSibling;if(ul.style.display===\'block\'){{ul.style.display=\'none\';this.textContent=\'show\';}}else{{ul.style.display=\'block\';this.textContent=\'hide\';}}">show</span><ul class="toc-policies">{policy_items}</ul></li>')
    lines.append('</ol>')
    lines.append('</div>')
    lines.append("")

    # How to read this report — collapsible explainer (after TOC)
    lines.append("---")
    lines.append("")
    lines.append('<details id="how-to-read-this-report" class="group-section">')
    lines.append('<summary><h2>How to Read This Report</h2></summary>')
    lines.append("")
    lines.append("### How FortiDLP Policies Work")
    lines.append("")
    lines.append("FortiDLP policies monitor endpoint and user activity for security-relevant events. Each policy defines:")
    lines.append("")
    lines.append("- **What to detect** — conditions that identify risky or policy-violating activity")
    lines.append("- **How severe it is** — risk score and MITRE ATT&CK mapping for triage priority")
    lines.append("- **How to respond** — automated actions: block, notify, screenshot, or log only")
    lines.append("")
    lines.append("<h4>Detection Flow</h4>")
    lines.append("")
    lines.append(_generate_flowchart_svg())
    lines.append("")
    lines.append("<h4>Policy Groups and Targeting</h4>")
    lines.append("")
    lines.append('Policies are organized into **groups** scoped by **labels** \u2014 '
                 'e.g., a group labeled "Windows" applies only to matching endpoints. '
                 'Groups labeled "All systems" have no targeting restriction.')
    lines.append("")
    lines.append("<h4>How Policies Are Presented in This Report</h4>")
    lines.append("")
    lines.append("Each policy in this report includes:")
    lines.append("")
    lines.append('<div style="margin-left: 24px; border: 1px solid #e0e0e0; border-radius: 6px; padding: 16px 20px;">')
    lines.append('<h2 style="display:inline;margin:0;border-bottom:none;padding-bottom:0;">Example Group Name <span class="toc-badge">Label</span></h2>')
    lines.append('<p><strong>Policies in group:</strong> <em>&lt;# policies in group&gt;</em></p>')
    lines.append('<blockquote>Group-level description text \u2014 explains the purpose or scope of this policy group</blockquote>')
    lines.append('<div class="policy-card">')
    lines.append('<h3>Example Policy Name <span class="severity-badge risk-high">&nbsp;Risk Score&nbsp;</span></h3>')
    lines.append('<p><strong>Description:</strong> What the policy detects</p>')
    lines.append('<p><strong>Requirements:</strong> OS and minimum Agent version needed (if applicable)</p>')
    lines.append('<p><strong>Tags:</strong> Labels assigned to policies for filtering and cross-referencing in the FortiDLP console (e.g., <code>datatracking</code>, <code>removablemedia</code>, <code>Windows</code>)</p>')
    lines.append('<p><strong>Triggers:</strong> Conditions that cause a detection (what the policy watches for)</p>')
    lines.append('<p><strong>Content inspection:</strong> File content patterns or keywords that must match</p>')
    lines.append('<p><strong>Exceptions:</strong> Conditions that suppress detection (whitelisted items)</p>')
    lines.append('<p><strong>Settings:</strong> Additional configuration options for this policy</p>')
    lines.append('<p><strong>Customizable:</strong> Parameters you can configure to tailor detection (e.g., add IP addresses, domains, or usernames to monitor or exempt)</p>')
    lines.append('<p><strong>Detection:</strong> Indicates a policy with fixed detection logic defined in the agent (e.g., registry changes, attack signatures)</p>')
    lines.append('<p><strong>Response:</strong> Actions taken when the policy triggers (block, screenshot, message, etc.)</p>')
    lines.append('</div>')
    lines.append('</div>')
    lines.append("")
    lines.append("<h4>Tags</h4>")
    lines.append("")
    lines.append('Metadata categorizing what each policy monitors (e.g., '
                 '<code>datatracking</code>, <code>filecopy</code>, <code>removablemedia</code>). '
                 'Tags prefixed with <code>mitre:</code> map to MITRE ATT&amp;CK techniques. '
                 'Tags are informational \u2014 they do not affect detection behavior, but are useful '
                 'for filtering, searching, and understanding coverage across policy groups.')
    lines.append("")
    lines.append("<h4>Risk Score Scale</h4>")
    lines.append("")
    lines.append("Each policy has a risk score (0\u2013100) set by the policy template, "
                 "determining detection priority in the FortiDLP console. Higher-scored detections "
                 "surface first for analyst review and are typically paired with stronger response "
                 "actions (blocking, screenshots, notifications).")
    lines.append("")
    lines.append('<div style="margin: 0 24px;">')
    lines.append("<table>")
    lines.append("<tr><th>Score</th><th>Severity</th><th>Color</th></tr>")
    lines.append('<tr><td>90\u2013100</td><td>Critical</td><td><span class="severity-badge risk-critical">\u00a0</span></td></tr>')
    lines.append('<tr><td>70\u201389</td><td>High</td><td><span class="severity-badge risk-high">\u00a0</span></td></tr>')
    lines.append('<tr><td>40\u201369</td><td>Medium</td><td><span class="severity-badge risk-medium">\u00a0</span></td></tr>')
    lines.append('<tr><td>1\u201339</td><td>Low</td><td><span class="severity-badge risk-low">\u00a0</span></td></tr>')
    lines.append('<tr><td>0</td><td>Informational</td><td><span class="severity-badge risk-info">\u00a0</span></td></tr>')
    lines.append("</table>")
    lines.append("</div>")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    # Detailed sections per group
    for i, g in enumerate(groups):
        lines.append("---")
        lines.append("")
        if i == 0:
            lines.append('<p><a href="#" onclick="document.querySelectorAll(\'details.group-section\').forEach(d=>d.open=true);return false">Expand all</a> | <a href="#" onclick="document.querySelectorAll(\'details.group-section\').forEach(d=>d.open=false);return false">Collapse all</a></p>')
            lines.append("")
        lines.append('<details open class="group-section">')
        filtered_labels = [l for l in g.labels if l and l.lower() != "null"]
        label_text = ", ".join(filtered_labels) if filtered_labels else "All systems"
        label_badge = f' <span class="toc-badge">{label_text}</span>'
        lines.append(f'<summary><h2 id="{_slug(g.name)}">{g.name}{label_badge}</h2></summary>')
        lines.append("")
        if g.description:
            lines.append(f"> {g.description}")
            lines.append("")
        lines.append(f"**Policies in group:** {len(g.policies)}")
        lines.append("")

        for policy in sorted(g.policies, key=lambda p: (-p.risk_score, p.name)):
            lines.extend(_render_policy(
                policy,
                show_status=show_status,
                verbose=verbose,
            ))
        lines.append("</details>")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Report generated by FortiDLP Policy Summarizer*")
    lines.append("")

    return "\n".join(lines)


def _render_policy(
    policy: ParsedPolicy,
    show_status: bool = False,
    verbose: bool = False,
) -> list[str]:
    """Render a single policy as a compact card."""
    lines = ['<div class="policy-card">']

    # Policy name with risk score on the heading line
    bar = _risk_bar(policy.risk_score)
    heading = f"### {policy.name} — {bar} {policy.risk_score} {policy.severity}"
    if show_status and not policy.enabled:
        heading += " (DISABLED)"
    lines.append(heading)
    lines.append("")

    # Description — split off Note: sections and render them compact
    desc = policy.description.strip()
    if desc:
        parts = desc.split("\nNote:")
        lines.append(parts[0].strip())
        if len(parts) == 2:
            lines.append(f"<small>Note: {parts[1].strip()}</small>")
        elif len(parts) > 2:
            items = "".join(f"<li>{n.strip()}</li>" for n in parts[1:])
            lines.append(f"<small>Notes:<ul>{items}</ul></small>")
    lines.append("")

    # Requirements (OS and agent version)
    if policy.requirements:
        reqs = _format_requirements(policy.requirements)
        if reqs:
            lines.append(f"**Requirements:** {reqs}")
            lines.append("")

    # Tags
    if policy.tags:
        lines.append("**Tags:** " + " ".join(f"`{tag}`" for tag in policy.tags))
        lines.append("")

    # Compact explanation (triggers, content inspection, exceptions, settings)
    compact_lines = _compact_explanation(policy)
    if compact_lines:
        for cl in compact_lines:
            lines.append(cl)
    elif not any(p.get("name") not in ("action", "sensor") for p in policy.raw_parameters):
        lines.append("**Detection:** Built-in — no configurable parameters")
        lines.append("")

    # Response line
    response = _format_action_inline(policy)
    lines.append(f"**Response:** {response}")
    lines.append("")

    # Verbose: detection format + raw parameter dump
    if verbose and policy.detection_description_template:
        lines.append(f"**Detection format:** `{policy.detection_description_template}`")
        lines.append("")

    lines.append("")
    lines.append('</div>')
    return lines


# --- HTML generation ---

def markdown_to_html(markdown_text: str) -> str:
    """Convert markdown to styled HTML report."""
    try:
        import markdown as md
        body = md.markdown(markdown_text, extensions=["tables", "fenced_code", "toc"])
    except ImportError:
        body = _basic_markdown_to_html(markdown_text)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        max-width: 900px;
        margin: 40px auto;
        padding: 0 20px;
        color: #1a1a1a;
        line-height: 1.6;
        font-size: 14px;
    }}
    h1 {{
        color: #1d3557;
        border-bottom: 3px solid #457b9d;
        padding-bottom: 12px;
        font-size: 28px;
    }}
    h2 {{
        color: #1d3557;
        border-bottom: 1px solid #ddd;
        padding-bottom: 8px;
        margin-top: 40px;
        font-size: 22px;
    }}
    h3 {{
        color: #1d3557;
        margin-top: 32px;
        padding-top: 16px;
        border-top: 1px solid #eee;
        font-size: 18px;
    }}
    table {{
        border-collapse: collapse;
        width: 100%;
        margin: 16px 0;
    }}
    th, td {{
        border: 1px solid #ddd;
        padding: 8px 12px;
        text-align: left;
    }}
    th {{
        background-color: #1d3557;
        color: white;
        font-weight: 600;
    }}
    tr:nth-child(even) {{
        background-color: #f8f9fa;
    }}
    blockquote {{
        border-left: 4px solid #457b9d;
        margin: 16px 0;
        padding: 8px 16px;
        background-color: #f1faee;
        color: #1d3557;
    }}
    code {{
        background-color: #f0f0f0;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 13px;
    }}
    strong {{
        color: #1d3557;
    }}
    hr {{
        border: none;
        border-top: 1px solid #ddd;
        margin: 32px 0;
    }}
    ul {{
        padding-left: 24px;
    }}
    li {{
        margin-bottom: 4px;
    }}
    small {{
        display: block;
        font-size: 13px;
        color: #555;
        margin-top: 2px;
    }}
    small ul {{
        margin: 2px 0 0 0;
        padding-left: 24px;
    }}
    small li {{
        margin-bottom: 1px;
    }}
    .toc-actions {{
        margin: 0 0 8px 0;
        font-size: 12px;
        color: #888;
    }}
    .toc-groups {{
        margin: 0;
        padding-left: 28px;
    }}
    .toc-groups > li {{
        margin: 3px 0;
        line-height: 1.4;
    }}
    .toc-groups > li > a {{
        font-weight: 600;
        font-size: 15px;
    }}
    .toc-count {{
        color: #888;
        font-size: 13px;
        margin-left: 6px;
    }}
    .toc-badge {{
        background: #e8eef4;
        color: #457b9d;
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 11px;
        margin-left: 6px;
        vertical-align: middle;
    }}
    .toc-toggle {{
        font-size: 12px;
        color: #457b9d;
        cursor: pointer;
        margin-left: 8px;
        padding: 1px 8px;
        border: 1px solid #ccc;
        border-radius: 10px;
        background: #f8f9fa;
    }}
    .toc-toggle:hover {{
        background: #e8eef4;
        border-color: #457b9d;
    }}
    .toc-policies {{
        display: none;
        margin: 4px 0 4px 8px;
        padding-left: 16px;
    }}
    .toc-policies li {{
        font-size: 13px;
        margin: 2px 0;
    }}
    details {{
        margin-bottom: 8px;
    }}
    summary {{
        cursor: pointer;
        list-style: revert;
    }}
    summary h2 {{
        display: inline;
        margin: 0;
        border-bottom: none;
    }}
    details {{
        margin: 8px 0;
        padding: 8px;
        background: #f8f9fa;
        border-radius: 4px;
    }}
    details.group-section {{
        background: none;
        padding: 0;
    }}
    summary {{
        cursor: pointer;
    }}
    .severity-badge {{
        font-size: 12px;
        font-weight: 600;
        padding: 2px 10px;
        border-radius: 12px;
        color: white;
        vertical-align: middle;
    }}
    .risk-critical {{ background: #e63946; }}
    .risk-high {{ background: #f4a261; }}
    .risk-medium {{ background: #e9c46a; }}
    .risk-low {{ background: #457b9d; }}
    .risk-info {{ background: #adb5bd; }}
    .sample-card {{
        margin: 12px 24px;
        padding: 12px 16px;
        border-left: 3px solid #457b9d;
        background: #fafbfc;
        border-radius: 0 4px 4px 0;
        font-size: 13px;
    }}
    .sample-card h3 {{
        margin-top: 0;
        border-top: none;
        padding-top: 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .sample-card p {{
        margin: 4px 0;
    }}
    .policy-card {{
        margin: 16px 0 16px 24px;
        padding: 12px 16px;
        border-left: 3px solid #457b9d;
        background: #fafbfc;
        border-radius: 0 4px 4px 0;
        font-size: 13px;
        border-bottom: 1px solid #eee;
    }}
    .policy-card h3 {{
        margin-top: 0;
        border-top: none;
        padding-top: 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }}
    .policy-card p {{
        margin: 4px 0;
    }}
    .policy-card ul {{
        margin-top: 2px;
        margin-bottom: 2px;
    }}
    @media print {{
        body {{ margin: 20px; }}
        h2 {{ page-break-before: auto; }}
        h3 {{ page-break-after: avoid; }}
        table {{ page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def _basic_markdown_to_html(text: str) -> str:
    """Minimal markdown to HTML conversion without dependencies."""
    lines = text.split("\n")
    result = []
    in_table = False
    in_list = False
    in_nested = False
    in_code = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            if in_code:
                result.append("</code></pre>")
                in_code = False
            else:
                result.append("<pre><code>")
                in_code = True
            continue

        if in_code:
            result.append(html.escape(line))
            continue

        # Headers — add id for TOC anchoring
        if stripped.startswith("### "):
            if in_list:
                result.append("</ul>")
                in_list = False
            title = stripped[4:]
            # Parse risk info from heading: "Name — ▓▓▓░░ 90 Critical"
            risk_match = re.match(r"(.+?) — [▓░]+ (\d+) (\w+)(.*)", title)
            if risk_match:
                name = risk_match.group(1)
                anchor = _slug(name)
                score = int(risk_match.group(2))
                severity = risk_match.group(3)
                suffix = risk_match.group(4).strip()  # e.g. "(DISABLED)"
                css_class = _SEVERITY_CSS_CLASS.get(severity, "risk-info")
                badge = f'<span class="severity-badge {css_class}">{score} {severity}</span>'
                extra = f" {_inline_format(suffix)}" if suffix else ""
                result.append(f'<h3 id="{anchor}">{_inline_format(name)}{badge}{extra}</h3>')
            else:
                anchor = _slug(title)
                result.append(f'<h3 id="{anchor}">{_inline_format(title)}</h3>')
            continue
        if stripped.startswith("## "):
            if in_list:
                result.append("</ul>")
                in_list = False
            title = stripped[3:]
            anchor = _slug(title)
            result.append(f'<h2 id="{anchor}">{_inline_format(title)}</h2>')
            continue
        if stripped.startswith("# "):
            if in_list:
                result.append("</ul>")
                in_list = False
            title = stripped[2:]
            result.append(f"<h1>{_inline_format(title)}</h1>")
            continue

        if stripped == "---":
            if in_list:
                result.append("</ul>")
                in_list = False
            result.append("<hr>")
            continue

        if stripped.startswith("> "):
            result.append(f"<blockquote>{_inline_format(stripped[2:])}</blockquote>")
            continue

        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(c.replace("-", "").replace(":", "") == "" for c in cells):
                continue
            if not in_table:
                result.append("<table>")
                tag = "th"
                in_table = True
            else:
                tag = "td"
            row = "".join(f"<{tag}>{_inline_format(c)}</{tag}>" for c in cells)
            result.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            result.append("</table>")
            in_table = False

        # Risk bar detection — convert ▓░ text to styled HTML bar (per-policy)
        if stripped and stripped[0] in ("▓", "░"):
            bar_html = _render_html_risk_bar(stripped)
            if bar_html:
                result.append(bar_html)
                continue

        # Distribution chart bars — format: `Label    ████░░░░` **count**
        dist_match = re.match(r'^`(\w[\w\s]{9})(█+)(░*)`\s+\*\*(\d+)\*\*$', stripped)
        if dist_match:
            label, filled, empty, count = dist_match.groups()
            total_chars = len(filled) + len(empty)
            pct = round(len(filled) / total_chars * 100)
            sev_label = label.strip().lower()
            color_class = {"critical": "risk-critical", "high": "risk-high", "medium": "risk-medium", "low": "risk-low", "info": "risk-info"}.get(sev_label, "risk-info")
            result.append(
                f'<div class="risk-bar">'
                f'<span style="width:80px;display:inline-block">{label.strip()}</span>'
                f'<div class="risk-bar-track" style="width:200px"><div class="risk-bar-fill {color_class}" style="width:{pct}%"></div></div>'
                f'<strong>{count}</strong>'
                f'</div>'
            )
            continue

        # Nested list items (for TOC)
        if line.startswith("  - "):
            if not in_nested:
                result.append("<ul style='margin-top:2px;margin-bottom:2px'>")
                in_nested = True
            result.append(f"<li>{_inline_format(line.strip()[2:])}</li>")
            continue
        elif in_nested:
            result.append("</ul>")
            in_nested = False

        if stripped.startswith("- "):
            if not in_list:
                result.append("<ul>")
                in_list = True
            result.append(f"<li>{_inline_format(stripped[2:])}</li>")
            continue
        elif in_list and stripped == "":
            result.append("</ul>")
            in_list = False

        # Pass through raw HTML tags
        if stripped.startswith("<") and stripped.endswith(">"):
            result.append(stripped)
            continue
        if stripped.startswith("</") or stripped.startswith("<details") or stripped.startswith("<summary"):
            result.append(stripped)
            continue

        if stripped:
            result.append(f"<p>{_inline_format(stripped)}</p>")

    if in_table:
        result.append("</table>")
    if in_nested:
        result.append("</ul>")
    if in_list:
        result.append("</ul>")

    return "\n".join(result)


def _render_html_risk_bar(text: str) -> str:
    """Convert a risk bar line like '▓▓▓▓▓▓▓▓░░ **90** Critical | ...' to styled HTML."""
    # Parse: bar_chars SPACE **score** severity | categories...
    match = re.match(r'^([▓░]+)\s+\*\*(\d+)\*\*\s+(\w+)\s*\|?\s*(.*)', text)
    if not match:
        return ""
    bar_chars, score_str, severity, rest = match.groups()
    score = int(score_str)
    pct = min(100, max(0, score))

    color_class = {
        "Critical": "risk-critical",
        "High": "risk-high",
        "Medium": "risk-medium",
        "Low": "risk-low",
        "Informational": "risk-info",
    }.get(severity, "risk-info")

    rest_html = _inline_format(rest.strip()) if rest.strip() else ""
    sep = f" <span style='color:#888'>|</span> {rest_html}" if rest_html else ""

    return (
        f'<div class="risk-bar">'
        f'<div class="risk-bar-track"><div class="risk-bar-fill {color_class}" style="width:{pct}%"></div></div>'
        f'<strong>{score}</strong> {severity}{sep}'
        f'</div>'
    )


def _inline_format(text: str) -> str:
    """Apply inline markdown formatting, protecting code spans from bold/italic."""
    # Step 1: Extract code spans and replace with placeholders
    code_spans = []
    def _save_code(m):
        code_spans.append(html.escape(m.group(1)))
        return f"\x00CODE{len(code_spans) - 1}\x00"
    text = re.sub(r"`(.+?)`", _save_code, text)

    # Step 2: Apply bold, italic, links (safe now — code spans are protected)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2">\1</a>', text)

    # Step 3: Restore code spans
    for i, code in enumerate(code_spans):
        text = text.replace(f"\x00CODE{i}\x00", f"<code>{code}</code>")
    return text


def generate_html(markdown_text: str, output_path: Path):
    """Generate standalone HTML report."""
    html_content = markdown_to_html(markdown_text)
    output_path.write_text(html_content, encoding="utf-8")
