import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from layer2_guid import build_guid_index, traverse, GraphResult

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixture.json')

def load_fixture():
    with open(FIXTURE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for i, r in enumerate(data):
        r['_idx'] = i
    return data


def test_build_guid_index():
    data = load_fixture()
    index = build_guid_index(data)

    assert 'GUID-B' in index
    assert len(index['GUID-B']) > 1


def test_traverse_from_single_guid():
    data = load_fixture()
    index = build_guid_index(data)
    result = traverse(data, index, {'GUID-B'})

    assert isinstance(result, GraphResult)
    assert 'GUID-B' in result.nodes
    assert result.nodes['GUID-B'].name == 'evil.exe'
    assert 'GUID-C' in result.nodes
    assert 'GUID-D' in result.nodes
    assert len(result.edges) > 0
    assert 'GUID-A' in result.nodes
    assert result.traversal_depth >= 2


def test_traverse_finds_inject_target():
    data = load_fixture()
    index = build_guid_index(data)
    result = traverse(data, index, {'GUID-B'})

    # GUID-LSASS should be discovered via target_process_guid
    all_guids_in_edges = set()
    for e in result.edges:
        all_guids_in_edges.add(e[0])
        all_guids_in_edges.add(e[1])
    assert 'GUID-LSASS' in result.nodes or 'GUID-LSASS' in all_guids_in_edges


def test_root_processes_identified():
    data = load_fixture()
    index = build_guid_index(data)
    result = traverse(data, index, {'GUID-B'})

    assert len(result.root_processes) > 0


if __name__ == '__main__':
    test_build_guid_index()
    test_traverse_from_single_guid()
    test_traverse_finds_inject_target()
    test_root_processes_identified()
    print("PASS: test_layer2")
