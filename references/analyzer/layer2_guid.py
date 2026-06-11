"""Layer 2: GUID index building, iterative graph traversal, process tree construction."""

import os
from collections import defaultdict
from dataclasses import dataclass, field

GUID_FIELDS = ['process_guid', 'process_parent_guid', 'target_process_guid', 'process_root_guid']


@dataclass
class ProcessNode:
    guid: str = ''
    name: str = ''
    path: str = ''
    cmd: str = ''
    user: str = ''
    md5: str = ''
    sign: str = ''
    integrity: str = ''
    first_seen: str = ''
    event_types: list = field(default_factory=list)


@dataclass
class GraphResult:
    related_records: list = field(default_factory=list)
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    root_processes: list = field(default_factory=list)
    traversal_depth: int = 0
    guid_count: int = 0
    file_landing_chains: list = field(default_factory=list)


def build_guid_index(data: list[dict]) -> dict[str, set[int]]:
    """
    Pre-build an index mapping each GUID value to the set of record indices containing it.
    Scans all 4 GUID fields.
    """
    index = defaultdict(set)
    for record in data:
        idx = record.get('_idx', 0)
        for gf in GUID_FIELDS:
            val = record.get(gf)
            if val:
                index[val].add(idx)
    return dict(index)


def _extract_guids_from_records(data: list[dict], indices: set[int]) -> set[str]:
    """Extract all GUID values from records at given indices."""
    guids = set()
    for idx in indices:
        record = data[idx]
        for gf in GUID_FIELDS:
            val = record.get(gf)
            if val:
                guids.add(val)
    return guids


def traverse(data: list[dict], guid_index: dict[str, set[int]], initial_guids: set[str], max_depth: int = 5) -> GraphResult:
    """
    Iterative graph traversal starting from initial_guids.
    Expands until no new GUIDs are discovered or max_depth is reached.
    """
    known_guids = set(initial_guids)
    collected_indices = set()

    depth = 0
    for depth in range(1, max_depth + 1):
        # Find all record indices related to known GUIDs
        new_indices = set()
        for guid in known_guids:
            if guid in guid_index:
                new_indices.update(guid_index[guid])

        # Only process indices we haven't seen before
        fresh_indices = new_indices - collected_indices
        if not fresh_indices:
            break

        collected_indices.update(fresh_indices)

        # Extract new GUIDs from fresh records
        new_guids = _extract_guids_from_records(data, fresh_indices) - known_guids
        if not new_guids:
            # Rollback: these indices produced no new GUIDs, remove them
            collected_indices -= fresh_indices
            break

        known_guids.update(new_guids)

    # Build related records list (deduplicated, ordered by _idx)
    related_records = [data[idx] for idx in sorted(collected_indices)]

    # Build process tree
    nodes, edges = _build_tree(related_records)

    # Identify root processes (nodes that are never a child in any edge)
    child_guids = {e[1] for e in edges}
    root_processes = [guid for guid in nodes if guid not in child_guids]

    return GraphResult(
        related_records=related_records,
        nodes=nodes,
        edges=edges,
        root_processes=root_processes,
        traversal_depth=depth,
        guid_count=len(known_guids),
    )


def expand_by_file_landing(data: list[dict], graph: GraphResult,
                           guid_index: dict[str, set[int]],
                           max_extra_depth: int = 2) -> GraphResult:
    """
    Expand traversal by file落地 relationships.

    After the main GUID traversal, some upstream processes (e.g. browser downloads)
    are missed because the connection is through the filesystem, not parent-child GUIDs.

    This function:
    1. Collects all process paths from the current graph
    2. Builds a file落地 index: file_name → creator process_guid
    3. Matches collected paths against this index
    4. Adds creator GUIDs and re-traverses
    """
    # Step 1: Collect all executable paths from current graph
    collected_paths = set()
    for guid, node in graph.nodes.items():
        if node.path:
            collected_paths.add(node.path.lower())
        if node.name:
            collected_paths.add(node.name.lower())

    if not collected_paths:
        return graph

    # Step 2: Build file落地 index from raw data
    # file_create/file_write events: file_name → set of creator process_guids
    file_creator_index = defaultdict(set)  # file_basename_lower → {creator_guid}
    file_full_index = defaultdict(set)     # file_full_path_lower → {creator_guid}

    for record in data:
        et = record.get('event_type', '')
        if et not in ('file_create', 'file_write', 'browser_files'):
            continue

        file_name = record.get('file_name', '') or record.get('target_file_name', '') or ''
        if not file_name:
            continue

        creator_guid = record.get('process_guid', '')
        if not creator_guid:
            continue

        file_lower = file_name.lower()
        file_full_index[file_lower].add(creator_guid)

        # Also index by basename
        basename = os.path.basename(file_lower).replace('/', '\\')
        file_creator_index[basename].add(creator_guid)

    # Step 3: Match collected paths against file落地 index
    new_creator_guids = set()
    file_landing_chains = []  # [(created_file, creator_guid, creator_process_name)]

    for path in collected_paths:
        basename = os.path.basename(path).replace('/', '\\')
        creators = file_creator_index.get(basename, set()) | file_full_index.get(path, set())
        for creator_guid in creators:
            if creator_guid not in graph.nodes:
                new_creator_guids.add(creator_guid)
                file_landing_chains.append({
                    'created_file': path,
                    'creator_guid': creator_guid,
                })

    if not new_creator_guids:
        return graph

    # Step 4: Re-traverse with expanded GUIDs
    known_guids = set(graph.nodes.keys()) | new_creator_guids
    collected_indices = {record.get('_idx', 0) for record in graph.related_records}

    for depth in range(1, max_extra_depth + 1):
        new_indices = set()
        for guid in known_guids:
            if guid in guid_index:
                new_indices.update(guid_index[guid])

        fresh_indices = new_indices - collected_indices
        if not fresh_indices:
            break

        collected_indices.update(fresh_indices)

        new_guids = _extract_guids_from_records(data, fresh_indices) - known_guids
        if not new_guids:
            collected_indices -= fresh_indices
            break

        known_guids.update(new_guids)

    # Rebuild
    related_records = [data[idx] for idx in sorted(collected_indices)]
    nodes, edges = _build_tree(related_records)
    child_guids_set = {e[1] for e in edges}
    root_processes = [guid for guid in nodes if guid not in child_guids_set]

    # Enrich file_landing_chains with creator process name
    for chain in file_landing_chains:
        creator_node = nodes.get(chain['creator_guid'])
        if creator_node:
            chain['creator_process'] = creator_node.name

    return GraphResult(
        related_records=related_records,
        nodes=nodes,
        edges=edges,
        root_processes=root_processes,
        traversal_depth=graph.traversal_depth + depth,
        guid_count=len(known_guids),
        file_landing_chains=file_landing_chains,
    )


def _build_tree(related_records: list[dict]) -> tuple[dict, list]:
    """Build process tree nodes and edges from related records."""
    nodes = {}
    edges_set = set()

    for r in related_records:
        guid = r.get('process_guid')
        if guid and guid not in nodes:
            nodes[guid] = ProcessNode(
                guid=guid,
                name=r.get('process_name', ''),
                path=r.get('process_path', ''),
                cmd=r.get('process_command_line', ''),
                user=r.get('process_user', ''),
                md5=r.get('process_md5', ''),
                sign=r.get('process_sign', ''),
                integrity=r.get('process_integrity_level', ''),
                first_seen=r.get('event_creation_date', ''),
                event_types=[],
            )

        if guid and guid in nodes:
            et = r.get('event_type', '')
            if et and et not in nodes[guid].event_types:
                nodes[guid].event_types.append(et)

        parent_guid = r.get('process_parent_guid')
        if guid and parent_guid:
            edge = (parent_guid, guid, 'spawn')
            edges_set.add(edge)
            if parent_guid not in nodes:
                nodes[parent_guid] = ProcessNode(
                    guid=parent_guid,
                    name=r.get('process_parent_name', ''),
                )

        target_guid = r.get('target_process_guid')
        if guid and target_guid:
            edge = (guid, target_guid, 'inject/access')
            edges_set.add(edge)
            if target_guid not in nodes:
                nodes[target_guid] = ProcessNode(guid=target_guid)

    return nodes, list(edges_set)
