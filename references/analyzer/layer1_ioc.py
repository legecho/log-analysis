"""Layer 1: IOC full-field search with normalization."""

import re
from collections import defaultdict
from dataclasses import dataclass, field

GUID_FIELDS = ['process_guid', 'process_parent_guid', 'target_process_guid', 'process_root_guid']


@dataclass
class IocHit:
    record_index: int
    record: dict
    ioc: str
    hit_fields: list


@dataclass
class IocResult:
    hits: list = field(default_factory=list)
    initial_guids: set = field(default_factory=set)
    hit_summary: dict = field(default_factory=dict)


def normalize_ioc(ioc: str) -> list[str]:
    """
    Return a list of normalized variants to search for.
    Each IOC may produce multiple search forms.
    """
    variants = set()
    ioc_stripped = ioc.strip()
    lower = ioc_stripped.lower()
    variants.add(lower)

    # Domain: strip trailing dot
    if lower.endswith('.'):
        variants.add(lower.rstrip('.'))

    # File path: extract basename
    if '\\' in lower or '/' in lower:
        basename = lower.replace('/', '\\').split('\\')[-1]
        variants.add(basename)
        variants.add(lower)

    # IP address: also add integer representation
    ip_match = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ioc_stripped)
    if ip_match:
        octets = [int(o) for o in ip_match.groups()]
        if all(0 <= o <= 255 for o in octets):
            int_val = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
            variants.add(str(int_val))

    return list(variants)


def search(data: list[dict], ioc_list: list[str]) -> IocResult:
    """
    Search all fields of all records for each IOC.
    Returns hits, initial GUIDs, and summary statistics.
    """
    # Pre-compute normalized variants for each IOC
    ioc_variants = {}
    for ioc in ioc_list:
        ioc_variants[ioc] = normalize_ioc(ioc)

    hits = []
    hit_summary = defaultdict(lambda: defaultdict(int))
    guid_set = set()

    for record in data:
        idx = record.get('_idx', 0)

        # Build field→lowercase string value map
        field_values = {}
        for fld, val in record.items():
            if fld == '_idx' or val is None:
                continue
            field_values[fld] = str(val).lower()

        # Check each IOC against all fields
        for ioc in ioc_list:
            variants = ioc_variants[ioc]
            hit_fields = []

            for fld, str_val in field_values.items():
                for variant in variants:
                    if variant in str_val:
                        hit_fields.append(fld)
                        break

            if hit_fields:
                hits.append(IocHit(
                    record_index=idx,
                    record=record,
                    ioc=ioc,
                    hit_fields=hit_fields,
                ))
                for fld in hit_fields:
                    hit_summary[ioc][fld] += 1

                # Extract GUIDs from hit record
                for gf in GUID_FIELDS:
                    gval = record.get(gf)
                    if gval:
                        guid_set.add(gval)

    return IocResult(
        hits=hits,
        initial_guids=guid_set,
        hit_summary=dict(hit_summary),
    )
