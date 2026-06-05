import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from layer1_ioc import search, normalize_ioc, IocResult

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixture.json')

def load_fixture():
    with open(FIXTURE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for i, r in enumerate(data):
        r['_idx'] = i
    return data


def test_normalize_ioc():
    assert 'evil.com' in normalize_ioc('Evil.COM.')
    variants = normalize_ioc('C:\\Temp\\Evil.EXE')
    assert 'c:\\temp\\evil.exe' in variants
    assert 'evil.exe' in variants
    assert '1.2.3.4' in normalize_ioc('1.2.3.4')


def test_search_finds_ioc_in_all_fields():
    data = load_fixture()
    result = search(data, ['evil.exe'])

    assert isinstance(result, IocResult)
    assert len(result.hits) > 0
    fields_found = set()
    for hit in result.hits:
        fields_found.update(hit.hit_fields)
    assert 'process_name' in fields_found or 'process_command_line' in fields_found
    assert len(result.initial_guids) > 0
    assert 'GUID-B' in result.initial_guids


def test_search_ip_ioc():
    data = load_fixture()
    result = search(data, ['1.2.3.4'])

    assert len(result.hits) >= 2
    hit_fields = set()
    for hit in result.hits:
        hit_fields.update(hit.hit_fields)
    assert 'dst_ip_addr' in hit_fields or 'process_command_line' in hit_fields


def test_search_multiple_iocs():
    data = load_fixture()
    result = search(data, ['evil.exe', '1.2.3.4'])

    assert 'evil.exe' in result.hit_summary
    assert '1.2.3.4' in result.hit_summary


if __name__ == '__main__':
    test_normalize_ioc()
    test_search_finds_ioc_in_all_fields()
    test_search_ip_ioc()
    test_search_multiple_iocs()
    print("PASS: test_layer1")
