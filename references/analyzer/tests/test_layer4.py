import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from layer4_fallback import review, FallbackResult
from layer2_guid import build_guid_index, traverse

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixture.json')

def load_fixture():
    with open(FIXTURE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for i, r in enumerate(data):
        r['_idx'] = i
    return data


def test_finds_unknown_events():
    data = load_fixture()
    index = build_guid_index(data)
    graph = traverse(data, index, {'GUID-B'})

    result = review(data, graph, original_iocs=['evil.exe'])

    assert isinstance(result, FallbackResult)
    assert len(result.unknown_events) >= 1
    assert any(r.get('uuid') == 'AAA-012' for r in result.unknown_events)


def test_finds_broken_chains():
    data = load_fixture()
    index = build_guid_index(data)
    graph = traverse(data, index, {'GUID-B'})

    result = review(data, graph, original_iocs=['evil.exe'])

    assert len(result.broken_chains) >= 1


def test_finds_orphan_network():
    data = load_fixture()
    index = build_guid_index(data)
    graph = traverse(data, index, {'GUID-B'})

    result = review(data, graph, original_iocs=['evil.exe'])

    assert len(result.orphan_network) >= 1


def test_finds_new_ioc_candidates():
    data = load_fixture()
    index = build_guid_index(data)
    graph = traverse(data, index, {'GUID-B'})

    result = review(data, graph, original_iocs=['evil.exe'])

    assert len(result.new_ioc_candidates) > 0
    # Each candidate is now (type, value, source_context)
    first = result.new_ioc_candidates[0]
    assert len(first) == 3
    assert first[0] in ('ip', 'domain', 'md5')
    assert first[2]  # source_context not empty


def test_finds_missing_event_types():
    data = load_fixture()
    index = build_guid_index(data)
    graph = traverse(data, index, {'GUID-B'})

    result = review(data, graph, original_iocs=['evil.exe'])

    # Fixture doesn't have all expected types (e.g., file_write, registry_set_value)
    assert len(result.missing_event_types) > 0
    assert 'file_write' in result.missing_event_types or 'registry_set_value' in result.missing_event_types


if __name__ == '__main__':
    test_finds_unknown_events()
    test_finds_broken_chains()
    test_finds_orphan_network()
    test_finds_new_ioc_candidates()
    test_finds_missing_event_types()
    print("PASS: test_layer4")
