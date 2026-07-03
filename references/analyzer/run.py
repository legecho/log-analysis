#!/usr/bin/env python3
"""Log Preprocessor entry point. AI calls this script to analyze EDR JSON logs."""

import argparse
import io
import json
import os
import sys

# Force UTF-8 output (Windows GBK can't encode Unicode symbols)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Ensure module imports work regardless of how the script is invoked
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import layer0_stats
import layer1_ioc
import layer2_guid
import layer3_validate
import layer4_fallback
import output


def main():
    parser = argparse.ArgumentParser(description='EDR Log Preprocessor for AI Analysis')
    parser.add_argument('--file', required=True, help='Path to source JSON log file')
    parser.add_argument('--ioc', required=True, help='Comma-separated IOC list')
    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.file):
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Parse IOC list
    ioc_list = [ioc.strip() for ioc in args.ioc.split(',') if ioc.strip()]
    if not ioc_list:
        print("ERROR: No valid IOCs provided", file=sys.stderr)
        sys.exit(1)

    # Load data
    with open(args.file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Build indexed copy (don't mutate original)
    data = [{**record, '_idx': i} for i, record in enumerate(data)]

    # Layer 0: Global statistics
    stats = layer0_stats.analyze(data)

    # Layer 1: IOC search
    ioc_result = layer1_ioc.search(data, ioc_list)

    # Layer 2: GUID graph traversal
    guid_index = layer2_guid.build_guid_index(data)
    graph = layer2_guid.traverse(data, guid_index, ioc_result.initial_guids)

    # Layer 3: Validation
    validation = layer3_validate.check(graph.nodes, graph.edges)

    # Layer 4: Fallback review
    fallback = layer4_fallback.review(data, graph, original_iocs=ioc_list)

    # Output
    output.generate(stats, ioc_result, graph, validation, fallback, args.file, ioc_list)


if __name__ == '__main__':
    main()
