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
    parser.add_argument('--ioc', required=False, default='', help='Comma-separated IOC list (optional for auto-analysis)')
    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.file):
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Parse IOC list
    ioc_list = [ioc.strip() for ioc in args.ioc.split(',') if ioc.strip()] if args.ioc else []
    # Load data
    with open(args.file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Inject _idx for O(1) record positioning
    for i, record in enumerate(data):
        record['_idx'] = i

    # Layer 0: Global statistics
    stats = layer0_stats.analyze(data)

    # Layer 1: IOC search
    ioc_result = layer1_ioc.search(data, ioc_list)

    # Layer 2: GUID graph traversal
    guid_index = layer2_guid.build_guid_index(data)
    graph = layer2_guid.traverse(data, guid_index, ioc_result.initial_guids)

    # Layer 2.5: File落地回溯 — 扩展因文件系统关联而遗漏的上游进程
    graph = layer2_guid.expand_by_file_landing(data, graph, guid_index)

    # Layer 3: Validation
    validation = layer3_validate.check(graph.nodes, graph.edges)

    # Layer 4: Fallback review
    fallback = layer4_fallback.review(data, graph, original_iocs=ioc_list)

    # Output
    output.generate(stats, ioc_result, graph, validation, fallback, args.file, ioc_list)


if __name__ == '__main__':
    main()
