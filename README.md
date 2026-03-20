# FortiDLP Policy Summarizer

Parses FortiDLP `.policies` export files and generates professional summary reports in HTML. Provides clear explanations of detection logic, response actions, and policy configuration.

See [`examples/sample_report.html`](examples/sample_report.html) for an example of what a generated report looks like.

## Why It's Useful

- Documents deployed policies in a format that is easier to review, share, and archive than the FortiDLP console
- Translates policy logic into plain English so non-technical stakeholders can understand what's being monitored
- Summarizes detection rules, response actions, and risk scores in one place to speed up policy reviews
- Produces a self-contained HTML report that can be shared with teams that do not have console access
- Provides a point-in-time snapshot useful for audit preparation, internal reviews, and change tracking

Especially useful for post-deployment deliverables, security reviews, onboarding documentation, and customer handoffs.

## Requirements

- Python 3.9+
- No external dependencies

## Usage

```bash
# Single .policies file
python3 run_analyzer.py --policies path/to/export.policies

# Directory of .policies files
python3 run_analyzer.py --policies ./policies/

# Custom output path
python3 run_analyzer.py --policies ./policies/ --output my_report.html
```

### Caching Parsed Data

For large policy exports, you can cache the parsed data as JSON to avoid re-parsing when re-running with different flags:

```bash
# Parse once and save to JSON
python3 run_analyzer.py --policies ./policies/ --dump-json policies.json

# Re-generate the report from cache (much faster)
python3 run_analyzer.py --from-json policies.json

# Try different report options without re-parsing
python3 run_analyzer.py --from-json policies.json --verbose
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--policies PATH` | Path to `.policies` file or directory |
| `--from-json PATH` | Load pre-parsed policies from JSON cache |
| `--dump-json PATH` | Save parsed and enriched policies to JSON for re-use |
| `--output PATH` | Output file path (default: `report.html`) |
| `--show-status` | Show enabled/disabled status per policy |
| `--verbose` | Include raw parameter dump alongside explanations |

## What's in a Report

Each report includes:

- **Table of Contents** with policy group summaries
- **How to Read This Report** guide explaining the report format
- **Detection Flow** diagram showing how FortiDLP processes policies
- **Policy Cards** for each policy with:
  - Risk score and severity badge
  - Detection logic explanation (what triggers the policy)
  - Content inspection rules
  - Response actions (messages, screenshots, blocks, etc.)
  - Tags including MITRE ATT&CK indicators (when present in policy data)
  - Platform requirements

To save as PDF, open the HTML report in your browser and print to PDF.

## FortiDLP Policy Export Format

`.policies` files are exported from the FortiDLP console by navigating to **Policies** and selecting **Export** on a policy group. They are gzip-compressed tar archives containing policy definitions, group metadata, and configuration.

## Disclaimer

Reports are generated directly from FortiDLP policy export data and should accurately reflect your policy configuration. However, always verify report output against the FortiDLP console before making security decisions or presenting to stakeholders. This tool is provided as-is with no warranty — see [LICENSE](LICENSE) for full terms.

## License

MIT
