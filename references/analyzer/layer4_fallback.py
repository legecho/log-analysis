"""Layer 4: Fallback review — unknown events, broken chains, orphan network, new IOC candidates."""

import ipaddress
from dataclasses import dataclass, field

SAFE_DOMAIN_SUFFIXES = (
    '.microsoft.com', '.windows.com', '.windowsupdate.com', '.msftconnecttest.com',
    '.office.com', '.office365.com', '.live.com', '.bing.com',
    '.google.com', '.googleapis.com', '.gstatic.com',
    '.apple.com', '.icloud.com',
    '.github.com', '.githubusercontent.com',
    '.cloudflare.com', '.akamai.net', '.amazonaws.com',
    '.azure.com', '.azureedge.net', '.windows.net',
    '.cloudfront.net',
    '.akamaized.net',
    '.sentry.io',
    '.vercel.app', '.vercel.com',
    '.netlify.app', '.netlify.com',
)

KNOWN_CLEAN_MD5 = {
    '7b88d0896fbf43469a9959d59824a514',
}

# Expected event types for 深信服 EDR — absence may indicate collection gap
EXPECTED_EVENT_TYPES = {
    'process_creation', 'process_terminate', 'IP_Event', 'DNS_Query',
    'file_write', 'file_create', 'registry_set_value', 'image_loaded',
}


@dataclass
class FallbackResult:
    unknown_events: list = field(default_factory=list)
    broken_chains: list = field(default_factory=list)
    orphan_network: list = field(default_factory=list)
    new_ioc_candidates: list = field(default_factory=list)  # [(type, value, source_context)]
    missing_event_types: list = field(default_factory=list)


def _is_internal_ip(ip_str: str) -> bool:
    """Check if IP is RFC1918/RFC6598/loopback/link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return True


def _is_safe_domain(domain: str) -> bool:
    """Check if domain matches known safe suffixes."""
    domain_lower = domain.lower().rstrip('.')
    for suffix in SAFE_DOMAIN_SUFFIXES:
        if domain_lower == suffix.lstrip('.') or domain_lower.endswith(suffix):
            return True
    return False


def review(data: list[dict], graph_result, original_iocs: list[str] = None) -> FallbackResult:
    """
    Fallback review: find unknown events, broken parent chains, orphan network events,
    and extract new IOC candidates from related records.
    """
    original_iocs_lower = {ioc.lower() for ioc in (original_iocs or [])}
    result = FallbackResult()

    # Collect all process_guids that have a process_creation event
    creation_guids = set()
    all_known_guids = set()
    observed_event_types = set()
    for r in data:
        pg = r.get('process_guid')
        if pg:
            all_known_guids.add(pg)
        if r.get('event_type') == 'process_creation' and pg:
            creation_guids.add(pg)
        et = r.get('event_type')
        if et:
            observed_event_types.add(et)

    # 1. Unknown/MISSING events
    for r in data:
        et = r.get('event_type')
        if not et or et.strip() == '' or et.lower() == 'unknown':
            result.unknown_events.append(r)

    # 2. Broken parent chains
    seen_parents = set()
    for r in data:
        parent_guid = r.get('process_parent_guid')
        if parent_guid and parent_guid not in all_known_guids and parent_guid not in seen_parents:
            seen_parents.add(parent_guid)
            result.broken_chains.append({
                'record_index': r.get('_idx'),
                'process_name': r.get('process_name'),
                'process_guid': r.get('process_guid'),
                'missing_parent_guid': parent_guid,
                'note': 'Parent process GUID not found in any record in this log window',
            })

    # 3. Orphan network events
    for r in data:
        if r.get('event_type') in ('IP_Event', 'DNS_Query'):
            pg = r.get('process_guid')
            if pg and pg not in creation_guids:
                result.orphan_network.append(r)

    # 4. New IOC candidates from graph-related records (with source context)
    candidate_map = {}  # (type, value) → source_context
    for r in graph_result.related_records:
        proc_name = r.get('process_name', '?')
        guid = r.get('process_guid', '?')
        source = f"{proc_name} ({guid})"

        for ip_field in ('dst_ip_addr', 'src_ip_addr'):
            ip_val = r.get(ip_field)
            if ip_val and not _is_internal_ip(ip_val):
                if ip_val.lower() not in original_iocs_lower:
                    key = ('ip', ip_val)
                    if key not in candidate_map:
                        candidate_map[key] = source

        domain = r.get('dns_host_name') or r.get('dns_query_name')
        if domain and not _is_safe_domain(domain):
            if domain.lower() not in original_iocs_lower:
                key = ('domain', domain)
                if key not in candidate_map:
                    candidate_map[key] = source

        for md5_field in ('process_md5', 'file_md5'):
            md5_val = r.get(md5_field)
            if md5_val and md5_val.lower() not in KNOWN_CLEAN_MD5:
                if md5_val.lower() not in original_iocs_lower:
                    key = ('md5', md5_val)
                    if key not in candidate_map:
                        candidate_map[key] = source

    result.new_ioc_candidates = sorted(
        [(t, v, ctx) for (t, v), ctx in candidate_map.items()]
    )

    # 5. Missing event types
    result.missing_event_types = sorted(EXPECTED_EVENT_TYPES - observed_event_types)

    return result
