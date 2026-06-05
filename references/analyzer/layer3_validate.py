"""Layer 3: Legitimacy validation — path, signature, parent-child relationship checks."""

import re
from dataclasses import dataclass, field

SYSTEM_PATHS = {
    'svchost.exe':    ['c:\\windows\\system32\\svchost.exe'],
    'lsass.exe':      ['c:\\windows\\system32\\lsass.exe'],
    'explorer.exe':   ['c:\\windows\\explorer.exe'],
    'csrss.exe':      ['c:\\windows\\system32\\csrss.exe'],
    'wininit.exe':    ['c:\\windows\\system32\\wininit.exe'],
    'services.exe':   ['c:\\windows\\system32\\services.exe'],
    'smss.exe':       ['c:\\windows\\system32\\smss.exe'],
    'powershell.exe': [
        'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe',
        'c:\\windows\\syswow64\\windowspowershell\\v1.0\\powershell.exe',
    ],
}

SUSPICIOUS_DIRS = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\downloads\\', '\\desktop\\', '\\public\\']

NORMAL_SVCHOST_PARENTS = {'services.exe', 'wininit.exe'}

LOLBINS = {'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'bitsadmin.exe',
            'wmic.exe', 'cmstp.exe', 'msbuild.exe'}

ABNORMAL_PARENT_CHILD = {
    'cmd.exe':        {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'},
    'powershell.exe': {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'},
    'mshta.exe':      {'winword.exe', 'excel.exe', 'chrome.exe', 'iexplore.exe'},
    'wscript.exe':    {'winword.exe', 'excel.exe'},
}

ENCODED_CMD_PATTERNS = [
    re.compile(r'-e(nc|ncodedcommand)\s+', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9+/=]{40,}'),
]


@dataclass
class RiskFinding:
    guid: str
    process_name: str
    risk_type: str
    description: str
    severity: str


@dataclass
class ValidationResult:
    findings: list = field(default_factory=list)


def check(nodes: dict, edges: list) -> ValidationResult:
    """Validate all process nodes for suspicious characteristics."""
    findings = []

    # Build parent lookup: child_guid → parent_node_name
    parent_map = {}
    for src, dst, rel_type in edges:
        if rel_type == 'spawn' and src in nodes:
            parent_map[dst] = nodes[src].name.lower() if nodes[src].name else ''

    for guid, node in nodes.items():
        name_lower = (node.name or '').lower()
        path_lower = (node.path or '').lower()
        cmd = node.cmd or ''
        sign = node.sign or ''

        if not name_lower:
            continue

        # 1. Path validation for known system processes
        if name_lower in SYSTEM_PATHS and path_lower:
            expected_paths = SYSTEM_PATHS[name_lower]
            if path_lower not in expected_paths:
                findings.append(RiskFinding(
                    guid=guid, process_name=node.name,
                    risk_type='PATH_ABNORMAL',
                    description=f'Expected {expected_paths}, actual: {node.path}',
                    severity='HIGH',
                ))

        # 2. Suspicious directory
        if path_lower:
            for sus_dir in SUSPICIOUS_DIRS:
                if sus_dir in path_lower:
                    findings.append(RiskFinding(
                        guid=guid, process_name=node.name,
                        risk_type='SUSPICIOUS_DIR',
                        description=f'Process in suspicious directory: {node.path}',
                        severity='MEDIUM',
                    ))
                    break

        # 3. Unsigned process (only flag if we have actual process data, not stub nodes)
        if path_lower and not sign.strip():
            findings.append(RiskFinding(
                guid=guid, process_name=node.name,
                risk_type='UNSIGNED',
                description='No digital signature',
                severity='MEDIUM',
            ))

        # 4. Encoded command detection
        if cmd:
            for pattern in ENCODED_CMD_PATTERNS:
                if pattern.search(cmd):
                    findings.append(RiskFinding(
                        guid=guid, process_name=node.name,
                        risk_type='ENCODED_CMD',
                        description='Encoded/obfuscated command line detected',
                        severity='HIGH',
                    ))
                    break

        # 5. LOLBin detection
        if name_lower in LOLBINS:
            findings.append(RiskFinding(
                guid=guid, process_name=node.name,
                risk_type='LOLBIN',
                description=f'LOLBin executed: {cmd[:100]}' if cmd else f'LOLBin: {node.name}',
                severity='MEDIUM',
            ))

        # 6. Abnormal parent-child relationship
        if guid in parent_map:
            parent_name = parent_map[guid]

            if name_lower == 'svchost.exe' and parent_name not in NORMAL_SVCHOST_PARENTS:
                findings.append(RiskFinding(
                    guid=guid, process_name=node.name,
                    risk_type='ABNORMAL_PARENT',
                    description=f'svchost.exe spawned by {parent_name} (expected: services.exe)',
                    severity='HIGH',
                ))

            if name_lower in ABNORMAL_PARENT_CHILD:
                if parent_name in ABNORMAL_PARENT_CHILD[name_lower]:
                    findings.append(RiskFinding(
                        guid=guid, process_name=node.name,
                        risk_type='ABNORMAL_PARENT',
                        description=f'{node.name} spawned by {parent_name}',
                        severity='HIGH',
                    ))

        # 7. SYSTEM user on non-system process
        if node.user and 'system' in node.user.lower():
            if name_lower not in SYSTEM_PATHS and name_lower not in {'taskhost.exe', 'taskhostw.exe',
                'conhost.exe', 'dllhost.exe', 'wuauclt.exe', 'spoolsv.exe', 'msiexec.exe'}:
                findings.append(RiskFinding(
                    guid=guid, process_name=node.name,
                    risk_type='SYSTEM_UNEXPECTED',
                    description='Running as SYSTEM but not a known system process',
                    severity='MEDIUM',
                ))

    return ValidationResult(findings=findings)
