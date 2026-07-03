"""Layer 2: GUID index building, iterative graph traversal, process tree construction."""

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
    cross_host_edges: list = field(default_factory=list)
    traversal_depth: int = 0
    guid_count: int = 0
    truncated: bool = False


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


def traverse(data: list[dict], guid_index: dict[str, set[int]], initial_guids: set[str],
             max_depth: int = 5, max_records: int = 50000) -> GraphResult:
    """
    Iterative graph traversal starting from initial_guids.
    Expands until no new GUIDs are discovered, max_depth is reached,
    or collected records exceed max_records.
    """
    known_guids = set(initial_guids)
    collected_indices = set()
    truncated = False

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

        # Check record limit
        if len(collected_indices) + len(fresh_indices) > max_records:
            allowed = max_records - len(collected_indices)
            fresh_indices = set(sorted(fresh_indices)[:allowed])
            collected_indices.update(fresh_indices)
            truncated = True
            break

        collected_indices.update(fresh_indices)

        # Extract new GUIDs from fresh records
        new_guids = _extract_guids_from_records(data, fresh_indices) - known_guids
        if not new_guids:
            break

        known_guids.update(new_guids)

    # Build related records list (deduplicated, ordered by _idx)
    related_records = [data[idx] for idx in sorted(collected_indices)]

    # Build process tree
    nodes, edges, cross_host_edges = _build_tree(related_records)

    # Identify root processes (nodes that are never a child in any edge)
    child_guids = {e[1] for e in edges}
    root_processes = [guid for guid in nodes if guid not in child_guids]

    return GraphResult(
        related_records=related_records,
        nodes=nodes,
        edges=edges,
        root_processes=root_processes,
        cross_host_edges=cross_host_edges,
        traversal_depth=depth,
        guid_count=len(known_guids),
        truncated=truncated,
    )


def _build_tree(related_records: list[dict]) -> tuple[dict, list, list]:
    """Build process tree nodes and edges from related records.
    Returns (nodes, edges, cross_host_edges).
    Cross-host edges are logged but NOT added to the main edges.
    """
    nodes = {}
    edges_set = set()
    cross_host_edges = []

    # Pre-build guid→host mapping for cross-host detection
    guid_hosts = {}  # guid → set of computer_name
    for r in related_records:
        g = r.get('process_guid')
        h = r.get('computer_name', '')
        if g and h:
            guid_hosts.setdefault(g, set()).add(h)

    for r in related_records:
        guid = r.get('process_guid')
        host = r.get('computer_name', '')

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
            # Cross-host detection: skip edge if parent is on a different host
            parent_hosts = guid_hosts.get(parent_guid, set())
            if parent_hosts and host and host not in parent_hosts:
                cross_host_edges.append({
                    'parent_guid': parent_guid,
                    'child_guid': guid,
                    'parent_hosts': sorted(parent_hosts),
                    'child_host': host,
                    'child_name': r.get('process_name', ''),
                    'reason': 'parent process lives on different host',
                })
            else:
                edges_set.add((parent_guid, guid, 'spawn'))
                if parent_guid not in nodes:
                    nodes[parent_guid] = ProcessNode(
                        guid=parent_guid,
                        name=r.get('process_parent_name', ''),
                    )

        target_guid = r.get('target_process_guid')
        if guid and target_guid:
            edges_set.add((guid, target_guid, 'inject/access'))
            if target_guid not in nodes:
                nodes[target_guid] = ProcessNode(guid=target_guid)

    return nodes, list(edges_set), cross_host_edges
