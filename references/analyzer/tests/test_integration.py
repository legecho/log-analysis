"""Integration test: run the full pipeline and validate output structure."""

import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(SCRIPT_DIR, 'tests', 'fixture.json')
DETAIL_FILE = os.path.join(SCRIPT_DIR, 'tests', 'pre_fixture.json')


def test_full_pipeline():
    if os.path.exists(DETAIL_FILE):
        os.remove(DETAIL_FILE)

    result = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, 'run.py'),
         '--file', FIXTURE, '--ioc', 'evil.exe,1.2.3.4'],
        capture_output=True, text=True, cwd=SCRIPT_DIR, encoding='utf-8'
    )

    assert result.returncode == 0, f"Pipeline failed:\nSTDERR: {result.stderr}\nSTDOUT: {result.stdout}"

    stdout = result.stdout

    # Verify all expected sections
    assert '=== LOG PREPROCESSOR RESULT ===' in stdout
    assert '[META]' in stdout
    assert '[IOC_HITS]' in stdout
    assert '[PROCESS_TREE]' in stdout
    assert '[RISKS]' in stdout
    assert '[NETWORK]' in stdout
    assert '[TIMELINE]' in stdout
    assert '[DETAIL_FILE]' in stdout

    # Verify IOC hits reported
    assert 'evil.exe' in stdout
    assert '1.2.3.4' in stdout

    # Verify risk findings
    assert 'PATH_ABNORMAL' in stdout
    assert 'ENCODED_CMD' in stdout
    assert 'UNSIGNED' in stdout

    # Verify detail file created
    assert os.path.exists(DETAIL_FILE), "Detail JSON file not created"

    with open(DETAIL_FILE, 'r', encoding='utf-8') as f:
        detail = json.load(f)

    assert 'meta' in detail
    assert 'ioc_hits' in detail
    assert 'process_tree' in detail
    assert 'timeline_full' in detail
    assert 'validation_results' in detail
    assert 'blind_spots' in detail
    assert 'new_ioc_candidates' in detail

    assert detail['meta']['total_records'] == 15
    assert 'GUID-B' in detail['process_tree']['nodes']
    assert detail['process_tree']['nodes']['GUID-B']['name'] == 'evil.exe'
    assert len(detail['ioc_hits']) > 0
    assert len(detail['validation_results']) > 0

    # Clean up
    os.remove(DETAIL_FILE)
    print("PASS: test_integration")


if __name__ == '__main__':
    test_full_pipeline()
