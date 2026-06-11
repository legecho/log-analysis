"""Output generation: text summary (stdout) + detailed JSON file."""

import json
import os
from collections import Counter, defaultdict

from layer0_stats import StatsResult
from layer1_ioc import IocResult
from layer2_guid import GraphResult
from layer3_validate import ValidationResult
from layer4_fallback import FallbackResult


def generate(stats: StatsResult, ioc_result: IocResult, graph: GraphResult,
             validation: ValidationResult, fallback: FallbackResult,
             source_file: str, ioc_list: list[str]) -> str:
    """
    Generate text summary to stdout and save detailed JSON.
    Returns the path to the detail JSON file.
    """
    source_dir = os.path.dirname(os.path.abspath(source_file))
    source_name = os.path.basename(source_file)
    detail_filename = f'pre_{source_name}'
    detail_path = os.path.join(source_dir, detail_filename)

    _print_summary(stats, ioc_result, graph, validation, fallback, detail_path, ioc_list)
    _save_detail_json(stats, ioc_result, graph, validation, fallback, detail_path)
    summary_path = detail_path.replace('pre_', 'summary_')
    _save_summary_json(stats, ioc_result, graph, validation, fallback, ioc_list, summary_path)

    return detail_path


def _print_summary(stats, ioc_result, graph, validation, fallback, detail_path, ioc_list):
    """Print structured text summary to stdout."""
    print("=== LOG PREPROCESSOR RESULT ===")

    # [META]
    hosts_str = ', '.join(stats.hosts[:5])
    if len(stats.hosts) > 5:
        hosts_str += f' (+{len(stats.hosts)-5} more)'
    print(f"[META] {stats.total_records} records | "
          f"{stats.time_range[0]} ~ {stats.time_range[1]} | "
          f"host: {hosts_str} | "
          f"{len(stats.event_type_dist)} event_types | "
          f"event_dist: {stats.event_type_dist}")
    print()

    # [IOC_HITS]
    for ioc in ioc_list:
        if ioc in ioc_result.hit_summary:
            field_counts = ioc_result.hit_summary[ioc]
            total = sum(field_counts.values())
            fields_str = ', '.join(f'{f}:{c}' for f, c in sorted(field_counts.items(), key=lambda x: -x[1]))
            print(f'[IOC_HITS] "{ioc}" -> {total} hits ({fields_str})')
        else:
            print(f'[IOC_HITS] "{ioc}" -> 0 hits')
    print()

    # [PROCESS_TREE]
    print("[PROCESS_TREE]")
    _print_tree(graph, validation)
    print()

    # [RISKS] — aggregated by risk_type
    if validation.findings:
        print("[RISKS]")
        _print_risks_aggregated(validation)
        print()

    # [NETWORK] — deduplicated
    network_events = [r for r in graph.related_records
                      if r.get('event_type') in ('IP_Event', 'DNS_Query')]
    if network_events:
        print("[NETWORK]")
        _print_network(network_events, graph.nodes)
        print()

    # [TIMELINE] — layered: core chain + context summary
    print("[TIMELINE]")
    _print_timeline_layered(graph, validation, ioc_result)
    print()

    # [BLIND_SPOTS]
    has_blind_spots = (fallback.unknown_events or fallback.broken_chains
                       or fallback.orphan_network or fallback.missing_event_types)
    if has_blind_spots:
        print("[BLIND_SPOTS]")
        if fallback.unknown_events:
            print(f"- Unknown/missing event_type: {len(fallback.unknown_events)} records")
        if fallback.broken_chains:
            print(f"- Broken parent chains: {len(fallback.broken_chains)} processes")
            for bc in fallback.broken_chains[:5]:
                print(f"    {bc['process_name']} ({bc['process_guid']}): parent {bc['missing_parent_guid']} not in log")
            if len(fallback.broken_chains) > 5:
                print(f"    ... and {len(fallback.broken_chains) - 5} more")
        if fallback.orphan_network:
            print(f"- Orphan network events: {len(fallback.orphan_network)} (no matching process_creation)")
        if fallback.missing_event_types:
            print(f"- Missing expected event types: {', '.join(fallback.missing_event_types)}")
        print()

    # [NEW_IOC_CANDIDATES]
    if fallback.new_ioc_candidates:
        print("[NEW_IOC_CANDIDATES]")
        for item in fallback.new_ioc_candidates[:20]:
            ioc_type, ioc_value = item[0], item[1]
            source_ctx = item[2] if len(item) > 2 else ''
            source_str = f' (source: {source_ctx})' if source_ctx else ''
            print(f"- {ioc_type}: {ioc_value}{source_str}")
        if len(fallback.new_ioc_candidates) > 20:
            print(f"  ... and {len(fallback.new_ioc_candidates) - 20} more")
        print()

    # [DETAIL_FILE]
    print(f"[DETAIL_FILE] {detail_path}")

    # [SUMMARY_FILE]
    summary_path = detail_path.replace('pre_', 'summary_')
    print(f"[SUMMARY_FILE] {summary_path}")


def _print_tree(graph, validation):
    """Print process tree with inline risk annotations. Collapse repetitive children."""
    risk_map = {}
    for f in validation.findings:
        risk_map.setdefault(f.guid, []).append(f.risk_type)

    # Build children map
    children = {}
    for src, dst, rel_type in graph.edges:
        if rel_type == 'spawn':
            children.setdefault(src, []).append(dst)

    # Build inject/access targets map
    inject_targets = {}
    for src, dst, rel_type in graph.edges:
        if rel_type == 'inject/access':
            inject_targets.setdefault(src, []).append(dst)

    # Print from root processes — with root-level same-name collapsing
    printed = set()

    # Collect all root-level GUIDs (roots + remaining unprinted)
    root_guids = list(graph.root_processes)
    remaining_guids = [g for g in graph.nodes if g not in set(root_guids)]
    all_root_level = root_guids + remaining_guids

    # Group root-level nodes by name for collapsing
    _print_roots_collapsed(graph.nodes, children, inject_targets, risk_map,
                           all_root_level, printed)


def _print_roots_collapsed(nodes, children, inject_targets, risk_map, root_guids, printed):
    """Collapse root-level same-name nodes that have no children into summary lines."""
    from collections import defaultdict

    # Separate: nodes with children (always print individually) vs leaf roots (collapse candidates)
    has_subtree = set()
    for g in root_guids:
        if children.get(g) or inject_targets.get(g):
            has_subtree.add(g)

    # Group leaf roots by name
    leaf_groups = defaultdict(list)
    ordered_names = []  # preserve first-seen order
    for g in root_guids:
        if g in has_subtree or g in printed:
            continue
        node = nodes.get(g)
        name = node.name if node else '(unknown)'
        if name not in leaf_groups:
            ordered_names.append(name)
        leaf_groups[name].append(g)

    # Print nodes with subtrees individually (in order)
    for g in root_guids:
        if g in has_subtree and g not in printed:
            _print_node(nodes, children, inject_targets, risk_map, g, indent=0, printed=printed)

    # Print leaf root groups — collapse 3+ same-name
    for name in ordered_names:
        guids = leaf_groups[name]
        # Filter out already printed
        guids = [g for g in guids if g not in printed]
        if not guids:
            continue
        if len(guids) >= 3:
            all_risks = set()
            for g in guids:
                if g in risk_map:
                    all_risks.update(risk_map[g])
                printed.add(g)
            risk_str = ' ' + ' '.join(f'⚠{rt}' for rt in sorted(all_risks)) if all_risks else ''
            print(f"{name} x{len(guids)}{risk_str}")
        else:
            for g in guids:
                _print_node(nodes, children, inject_targets, risk_map, g, indent=0, printed=printed)


def _print_node(nodes, children, inject_targets, risk_map, guid, indent, printed):
    """Recursively print a node and its children, collapsing repetitive same-name children."""
    if guid in printed:
        return
    printed.add(guid)

    node = nodes.get(guid)
    if not node:
        return

    prefix = "  " * indent + ("└─ " if indent > 0 else "")
    name = node.name or '(unknown)'
    user_str = f' ({node.user})' if node.user else ''
    guid_short = f' {{{guid}}}'

    risk_tags = ''
    if guid in risk_map:
        risk_tags = ' ' + ' '.join(f'⚠{rt}' for rt in risk_map[guid])

    print(f"{prefix}{name}{user_str}{guid_short}{risk_tags}")

    # Print injection/access targets
    for target_guid in inject_targets.get(guid, []):
        target_node = nodes.get(target_guid)
        target_name = target_node.name if target_node and target_node.name else target_guid
        t_prefix = "  " * (indent + 1) + "  -> [inject/access] "
        print(f"{t_prefix}{target_name} {{{target_guid}}}")
        printed.add(target_guid)

    # Print children — with collapsing for repetitive same-name children
    child_guids = children.get(guid, [])
    if child_guids:
        _print_children_collapsed(nodes, children, inject_targets, risk_map,
                                  child_guids, indent + 1, printed)


def _print_children_collapsed(nodes, children, inject_targets, risk_map,
                              child_guids, indent, printed):
    """Print children, collapsing groups of 3+ same-name nodes into a summary line."""
    # Group children by name
    name_groups = defaultdict(list)
    for cg in child_guids:
        if cg in printed:
            continue
        node = nodes.get(cg)
        name = node.name if node else '(unknown)'
        name_groups[name].append(cg)

    for name, guids in name_groups.items():
        if len(guids) >= 3:
            # Collapse: show summary line
            # Collect all risk types across the group
            all_risks = set()
            has_children = False
            for g in guids:
                if g in risk_map:
                    all_risks.update(risk_map[g])
                if children.get(g):
                    has_children = True
                printed.add(g)

            prefix = "  " * indent + "└─ "
            risk_str = ' ' + ' '.join(f'⚠{rt}' for rt in sorted(all_risks)) if all_risks else ''
            note = ' [has sub-processes]' if has_children else ''
            print(f"{prefix}{name} x{len(guids)}{risk_str}{note}")
        else:
            # Print individually (1-2 occurrences)
            for cg in guids:
                _print_node(nodes, children, inject_targets, risk_map, cg, indent, printed)


def _print_risks_aggregated(validation):
    """Print risks aggregated by risk_type, HIGH first, with top examples."""
    # Group by (severity, risk_type)
    groups = defaultdict(list)
    for f in validation.findings:
        groups[(f.severity, f.risk_type)].append(f)

    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    for (severity, risk_type), findings in sorted(groups.items(),
                                                   key=lambda x: severity_order.get(x[0][0], 3)):
        if len(findings) <= 3:
            # Few findings — show each
            for f in findings:
                print(f"- [{severity}] {risk_type} | {f.process_name} ({f.guid}): {f.description}")
        else:
            # Many findings — aggregate with top examples
            print(f"- [{severity}] {risk_type} | {len(findings)} processes:")
            for f in findings[:3]:
                print(f"    {f.process_name} ({f.guid}): {f.description}")
            print(f"    ... and {len(findings) - 3} more (see DETAIL_FILE)")


def _print_network(network_events, nodes):
    """Print network event summary, deduplicated and limited to top entries."""
    ip_connections = Counter()  # (guid, dst_ip, dst_port) → count
    dns_queries = {}  # (guid, domain) → result (deduplicated)

    for r in network_events:
        guid = r.get('process_guid', '?')
        if r.get('event_type') == 'IP_Event':
            dst = r.get('dst_ip_addr', '?')
            port = r.get('dst_port', '?')
            ip_connections[(guid, dst, port)] += 1
        elif r.get('event_type') == 'DNS_Query':
            domain = r.get('dns_host_name') or r.get('dns_query_name', '?')
            result = r.get('dns_query_results', '?')
            dns_queries[(guid, domain)] = result

    # Show top 20 IP connections
    top_ip = ip_connections.most_common(20)
    for (guid, dst, port), count in top_ip:
        proc_name = nodes[guid].name if guid in nodes else '?'
        print(f"- {proc_name} ({guid}) -> {dst}:{port} ({count} connections)")
    remaining_ip = len(ip_connections) - len(top_ip)
    if remaining_ip > 0:
        total_remaining_conns = sum(c for _, c in ip_connections.most_common()[20:])
        print(f"  ... and {remaining_ip} more unique destinations ({total_remaining_conns} total connections, see DETAIL_FILE)")

    # Show top 15 DNS queries
    dns_items = sorted(dns_queries.items())
    for (guid, domain), result in dns_items[:15]:
        proc_name = nodes[guid].name if guid in nodes else '?'
        print(f"- {proc_name} ({guid}) -> DNS: {domain} -> {result}")
    if len(dns_items) > 15:
        print(f"  ... and {len(dns_items) - 15} more unique DNS queries (see DETAIL_FILE)")


def _print_timeline_layered(graph, validation, ioc_result):
    """
    Layered timeline:
    - Core: events directly involving IOC-hit GUIDs and their immediate parent/children
    - Context: summary of other related events
    """
    # Identify core GUIDs: those from IOC hits + their direct parent/child
    ioc_guids = set(ioc_result.initial_guids)

    # Add direct parents and children of IOC GUIDs
    core_guids = set(ioc_guids)
    for src, dst, rel_type in graph.edges:
        if rel_type == 'spawn':
            if src in ioc_guids:
                core_guids.add(dst)  # children of IOC process
            if dst in ioc_guids:
                core_guids.add(src)  # parent of IOC process

    # Split related records into core vs context
    core_records = []
    context_records = []
    for r in graph.related_records:
        guid = r.get('process_guid', '')
        if guid in core_guids:
            core_records.append(r)
        else:
            context_records.append(r)

    # Print core timeline with consecutive same-type aggregation
    core_records.sort(key=lambda r: r.get('event_creation_date', ''))
    _print_timeline_aggregated(core_records)

    # Print context summary
    if context_records:
        # Summarize context by process name
        context_procs = Counter()
        for r in context_records:
            if r.get('event_type') == 'process_creation':
                parent = r.get('process_parent_name', '?')
                child = r.get('process_name', '?')
                context_procs[f"{parent} -> {child}"] += 1

        print(f"\n[TIMELINE_CONTEXT] ({len(context_records)} additional related events, see DETAIL_FILE)")
        if context_procs:
            for pair, count in context_procs.most_common(10):
                print(f"  {pair} x{count}")
            remaining = len(context_procs) - 10
            if remaining > 0:
                print(f"  ... and {remaining} more process pairs")


def _print_timeline_aggregated(records):
    """Print timeline with consecutive low-info events from same process collapsed."""
    if not records:
        return

    # Event types that are always printed individually (high info value)
    HIGH_INFO_TYPES = {'process_creation', 'DNS_Query', 'IP_Event', 'process_access',
                       'Process_Injection', 'user_logon', 'user_logoff', 'user_added',
                       'user_deleted', 'userpwd_changed', 'usergroup_changed',
                       'userinfo_changed', 'network_event', 'powershell'}

    i = 0
    while i < len(records):
        r = records[i]
        pname = r.get('process_name', '?')
        et = r.get('event_type', '?')

        # High-info events: always print individually
        if et in HIGH_INFO_TYPES:
            _print_timeline_line(r)
            i += 1
            continue

        # Low-info events: collect consecutive from same process
        j = i + 1
        while j < len(records):
            next_r = records[j]
            next_et = next_r.get('event_type', '?')
            next_pname = next_r.get('process_name', '?')
            if next_pname == pname and next_et not in HIGH_INFO_TYPES:
                j += 1
            else:
                break

        count = j - i
        if count >= 3:
            # Aggregate: summarize event types in the run
            first_time = r.get('event_creation_date', '?')
            last_time = records[j - 1].get('event_creation_date', '?')
            if '.' in first_time:
                first_time = first_time.split('.')[0]
            if '.' in last_time:
                last_time = last_time.split('.')[0]

            # Count sub-types
            sub_types = Counter(rec.get('event_type', '?') for rec in records[i:j])
            sub_str = ', '.join(f'{et}:{c}' for et, c in sub_types.most_common(5))
            if len(sub_types) > 5:
                sub_str += ', ...'

            if first_time == last_time:
                time_str = first_time
            else:
                time_str = f"{first_time}~{last_time.split(' ')[-1] if ' ' in last_time else last_time}"
            print(f"{time_str} {'[batch]':20s} | {pname} x{count} ({sub_str})")
        else:
            # Few events — print individually
            for k in range(i, j):
                _print_timeline_line(records[k])

        i = j


def _print_timeline_line(r):
    """Print a single timeline entry."""
    time_str = r.get('event_creation_date', '?')
    if '.' in time_str:
        time_str = time_str.split('.')[0]
    et = r.get('event_type', '?')
    pname = r.get('process_name', '?')

    desc = ''
    if et == 'process_creation':
        parent = r.get('process_parent_name', '?')
        desc = f'{parent} -> {pname}'
        cmd = r.get('process_command_line', '')
        if cmd and len(cmd) > 80:
            cmd = cmd[:77] + '...'
        if cmd:
            desc += f' [{cmd}]'
    elif et == 'IP_Event':
        desc = f'{pname} -> {r.get("dst_ip_addr", "?")}:{r.get("dst_port", "?")}'
    elif et == 'DNS_Query':
        desc = f'{pname} -> {r.get("dns_host_name", "?")} -> {r.get("dns_query_results", "?")}'
    elif et == 'process_access':
        desc = f'{pname} accessed target ({r.get("access_type", "?")})'
    else:
        desc = f'{pname} | {et}'

    print(f"{time_str} {et:20s} | {desc}")


def _save_detail_json(stats, ioc_result, graph, validation, fallback, detail_path):
    """Save full structured results to JSON file."""
    nodes_serial = {}
    for guid, node in graph.nodes.items():
        nodes_serial[guid] = {
            'guid': node.guid,
            'name': node.name,
            'path': node.path,
            'cmd': node.cmd,
            'user': node.user,
            'md5': node.md5,
            'sign': node.sign,
            'integrity': node.integrity,
            'first_seen': node.first_seen,
            'event_types': node.event_types,
        }

    detail = {
        'meta': {
            'total_records': stats.total_records,
            'time_range': list(stats.time_range),
            'hosts': stats.hosts,
            'users': stats.users,
            'event_type_dist': stats.event_type_dist,
            'process_freq': stats.process_freq,
            'low_freq_processes': stats.low_freq_processes,
        },
        'ioc_hits': [
            {
                'record_index': hit.record_index,
                'ioc': hit.ioc,
                'hit_fields': hit.hit_fields,
                'record': hit.record,
            }
            for hit in ioc_result.hits
        ],
        'process_tree': {
            'nodes': nodes_serial,
            'edges': [[src, dst, rel] for src, dst, rel in graph.edges],
            'root_processes': graph.root_processes,
        },
        'timeline_full': sorted(
            graph.related_records,
            key=lambda r: r.get('event_creation_date', '')
        ),
        'validation_results': [
            {
                'guid': f.guid,
                'process_name': f.process_name,
                'risk_type': f.risk_type,
                'description': f.description,
                'severity': f.severity,
            }
            for f in validation.findings
        ],
        'blind_spots': {
            'unknown_events': fallback.unknown_events,
            'broken_chains': fallback.broken_chains,
            'orphan_network': fallback.orphan_network,
            'missing_event_types': fallback.missing_event_types,
        },
        'new_ioc_candidates': fallback.new_ioc_candidates,
    }

    with open(detail_path, 'w', encoding='utf-8') as f:
        json.dump(detail, f, ensure_ascii=False, indent=2, default=str)


# =============================================================================
# Summary JSON: compressed output for AI first-pass reading (~3-7k tokens)
# =============================================================================

# High-information event types that must be preserved in full
HIGH_INFO_EVENT_TYPES = {
    'process_creation', 'DNS_Query', 'IP_Event', 'process_access',
    'Process_Injection', 'user_logon', 'user_logoff', 'user_added',
    'user_deleted', 'userpwd_changed', 'usergroup_changed',
    'userinfo_changed', 'network_event', 'powershell', 'powershell_script',
}

# Low-information event types that get compressed to counts only
LOW_INFO_EVENT_TYPES = {
    'file_read', 'file_write', 'file_create', 'image_loaded',
    'registry_set_value', 'registry_key_opened', 'pipe_create',
    'pipe_connected', 'process_terminate', 'im_files',
}


def _save_summary_json(stats, ioc_result, graph, validation, fallback, ioc_list, summary_path):
    """
    Save compressed summary JSON for AI first-pass reading.
    Contains all structural information (process tree, risks, IOC hits)
    but compresses timeline to only high-info events.
    Full data remains in pre_*.json for on-demand grep queries.
    """

    # --- Meta ---
    meta = {
        'total_records': stats.total_records,
        'time_range': list(stats.time_range),
        'hosts': stats.hosts,
        'users': stats.users,
        'event_type_dist': stats.event_type_dist,
        'process_freq': stats.process_freq,
        'low_freq_processes': stats.low_freq_processes,
    }

    # --- Process Tree (compact) ---
    nodes_compact = {}
    for guid, node in graph.nodes.items():
        nodes_compact[guid] = {
            'name': node.name,
            'path': node.path,
            'cmd': node.cmd[:200] if node.cmd else '',
            'user': node.user,
            'sign': node.sign,
            'integrity': node.integrity,
            'first_seen': node.first_seen,
            'event_types': node.event_types,
        }

    process_tree = {
        'nodes': nodes_compact,
        'edges': [[src, dst, rel] for src, dst, rel in graph.edges],
        'root_processes': graph.root_processes,
    }

    # --- IOC Hits (compact: no full record) ---
    ioc_hits_compact = []
    for hit in ioc_result.hits:
        # Extract only key fields from the record
        record = hit.record
        compact_record = {}
        for key in ('event_type', 'event_creation_date', 'process_name', 'process_guid',
                     'process_parent_name', 'process_command_line', 'dst_ip_addr', 'dst_port',
                     'dns_host_name', 'dns_query_results', 'file_name', 'access_type'):
            if key in record and record[key]:
                compact_record[key] = record[key]
        ioc_hits_compact.append({
            'record_index': hit.record_index,
            'ioc': hit.ioc,
            'hit_fields': hit.hit_fields,
            'record': compact_record,
        })

    # --- Validation Results ---
    validation_compact = [
        {
            'guid': f.guid,
            'process_name': f.process_name,
            'risk_type': f.risk_type,
            'description': f.description,
            'severity': f.severity,
        }
        for f in validation.findings
    ]

    # --- Timeline Compressed ---
    # Only high-info events in full, low-info compressed to counts
    all_records = sorted(graph.related_records, key=lambda r: r.get('event_creation_date', ''))

    timeline_high_info = []
    low_info_counts = Counter()  # (process_name, event_type) → count

    for r in all_records:
        et = r.get('event_type', '')
        if et in HIGH_INFO_EVENT_TYPES:
            # Keep high-info events but trim large fields
            compact = {}
            for key in ('event_creation_date', 'event_type', 'process_name', 'process_guid',
                         'process_parent_name', 'process_command_line', 'process_path',
                         'dst_ip_addr', 'dst_port', 'src_ip_addr', 'src_port',
                         'dns_host_name', 'dns_query_results', 'dns_query_type',
                         'access_type', 'target_process_name', 'target_process_guid',
                         'file_name', 'file_path'):
                if key in r and r[key]:
                    val = r[key]
                    if key == 'process_command_line' and isinstance(val, str) and len(val) > 200:
                        val = val[:200] + '...'
                    compact[key] = val
            timeline_high_info.append(compact)
        elif et:
            pname = r.get('process_name', '?')
            low_info_counts[(pname, et)] += 1

    # Convert low_info_counts to a sorted list
    low_info_summary = [
        {'process': pname, 'event_type': et, 'count': count}
        for (pname, et), count in low_info_counts.most_common(50)
    ]

    timeline_compressed = {
        'high_info_events': timeline_high_info,
        'low_info_summary': low_info_summary,
        'total_events': len(all_records),
        'high_info_count': len(timeline_high_info),
        'low_info_count': len(all_records) - len(timeline_high_info),
    }

    # --- Network Summary ---
    ip_connections = Counter()
    dns_queries = {}
    for r in all_records:
        if r.get('event_type') == 'IP_Event':
            guid = r.get('process_guid', '?')
            dst = r.get('dst_ip_addr', '?')
            port = r.get('dst_port', '?')
            ip_connections[(guid, dst, port)] += 1
        elif r.get('event_type') == 'DNS_Query':
            guid = r.get('process_guid', '?')
            domain = r.get('dns_host_name') or r.get('dns_query_name', '?')
            result = r.get('dns_query_results', '?')
            dns_queries[(guid, domain)] = result

    network_summary = {
        'ip_connections': [
            {'process': graph.nodes[guid].name if guid in graph.nodes else '?',
             'guid': guid, 'dst_ip': dst, 'dst_port': port, 'count': count}
            for (guid, dst, port), count in ip_connections.most_common(30)
        ],
        'dns_queries': [
            {'process': graph.nodes[guid].name if guid in graph.nodes else '?',
             'guid': guid, 'domain': domain, 'result': result}
            for (guid, domain), result in sorted(dns_queries.items())
        ],
    }

    # --- Blind Spots ---
    blind_spots = {
        'unknown_events_count': len(fallback.unknown_events),
        'broken_chains_count': len(fallback.broken_chains),
        'broken_chains': fallback.broken_chains[:10],
        'orphan_network_count': len(fallback.orphan_network),
        'missing_event_types': fallback.missing_event_types,
    }

    # --- File Landing Chains (new from expand_by_file_landing) ---
    file_landing = graph.file_landing_chains if graph.file_landing_chains else []

    # --- New IOC Candidates ---
    new_ioc_candidates = fallback.new_ioc_candidates

    # --- Assemble summary ---
    summary = {
        'meta': meta,
        'ioc_hits': ioc_hits_compact,
        'process_tree': process_tree,
        'timeline': timeline_compressed,
        'network': network_summary,
        'validation_results': validation_compact,
        'blind_spots': blind_spots,
        'file_landing_chains': file_landing,
        'new_ioc_candidates': new_ioc_candidates,
    }

    # Save summary file
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
