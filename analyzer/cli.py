"""CLI interface for FortiDLP Policy Summarizer."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .enricher import enrich_policies
from .models import ParsedGroup
from .parser import parse_all_policy_files, parse_policy_file
from .report import generate_html, generate_markdown_report


def main():
    parser = argparse.ArgumentParser(
        prog="fdlp-analyzer",
        description="FortiDLP Policy Summarizer - Parse, summarize, and report on FortiDLP policy exports",
    )
    parser.add_argument(
        "--policies",
        type=Path,
        default=None,
        help="Path to .policies file or directory containing .policies files",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        default=None,
        help="Load pre-parsed policies from JSON file (skip .policies extraction)",
    )
    parser.add_argument(
        "--dump-json",
        type=Path,
        default=None,
        help="Write parsed+enriched policies to JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("report.html"),
        help="Output file path (default: report.html)",
    )

    # Display options
    parser.add_argument("--show-status", action="store_true", help="Show enabled/disabled status on each policy")

    parser.add_argument("--verbose", action="store_true", help="Include raw parameter dump alongside explanations")

    args = parser.parse_args()

    # Load policies: either from JSON cache or from .policies files
    if args.from_json:
        if not args.from_json.exists():
            print(f"Error: {args.from_json} not found", file=sys.stderr)
            sys.exit(1)
        data = json.loads(args.from_json.read_text(encoding="utf-8"))
        groups = [ParsedGroup.from_dict(g) for g in data["groups"]]
        total_policies = sum(len(g.policies) for g in groups)
        print(f"Loaded {len(groups)} policy groups with {total_policies} total policies from {args.from_json}")
    elif args.policies:
        policies_path = args.policies
        if policies_path.is_dir():
            groups = parse_all_policy_files(policies_path)
        elif policies_path.is_file() and policies_path.suffix == ".policies":
            groups = parse_policy_file(policies_path)
        else:
            print(f"Error: {policies_path} is not a valid .policies file or directory", file=sys.stderr)
            sys.exit(1)

        if not groups:
            print("Error: No policy groups found", file=sys.stderr)
            sys.exit(1)

        total_policies = sum(len(g.policies) for g in groups)
        print(f"Parsed {len(groups)} policy groups with {total_policies} total policies")

        # Enrich with detection logic explanations
        groups = enrich_policies(groups)
    else:
        print("Error: either --policies or --from-json is required", file=sys.stderr)
        sys.exit(1)

    # Dump JSON if requested
    if args.dump_json:
        dump = {
            "generated": datetime.now().isoformat(),
            "groups": [g.to_dict() for g in groups],
        }
        args.dump_json.write_text(json.dumps(dump, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"JSON dump written to {args.dump_json}")

    # Generate report
    markdown = generate_markdown_report(
        groups,
        show_status=args.show_status,
        verbose=args.verbose,
    )

    generate_html(markdown, args.output)
    print(f"HTML report written to {args.output}")


if __name__ == "__main__":
    main()
