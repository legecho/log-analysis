import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from layer0_stats import analyze, StatsResult

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixture.json')

def test_analyze_returns_stats_result():
    with open(FIXTURE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for i, r in enumerate(data):
        r['_idx'] = i

    result = analyze(data)

    assert isinstance(result, StatsResult)
    assert result.total_records == 15
    assert result.time_range[0] <= result.time_range[1]
    assert 'LPT017598' in result.hosts
    assert 'process_creation' in result.event_type_dist
    assert result.event_type_dist['process_creation'] == 7
    assert 'evil.exe' in result.process_freq
    assert result.process_freq['evil.exe'] == 1
    assert 'evil.exe' in result.low_freq_processes
    assert 'process_guid' in result.all_fields
    assert 'some_custom_field' in result.all_fields


if __name__ == '__main__':
    test_analyze_returns_stats_result()
    print("PASS: test_layer0")
