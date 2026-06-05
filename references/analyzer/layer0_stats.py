"""Layer 0: Global statistics — single-pass collection of log metadata."""

from collections import Counter
from dataclasses import dataclass, field


@dataclass
class StatsResult:
    total_records: int = 0
    time_range: tuple = ('', '')
    hosts: list = field(default_factory=list)
    users: list = field(default_factory=list)
    event_type_dist: dict = field(default_factory=dict)
    process_freq: dict = field(default_factory=dict)
    low_freq_processes: list = field(default_factory=list)
    all_fields: list = field(default_factory=list)


def analyze(data: list[dict]) -> StatsResult:
    """Single-pass analysis of all records to build global statistics."""
    event_types = Counter()
    process_names = Counter()
    hosts = set()
    users = set()
    all_fields = set()
    min_time = None
    max_time = None

    for record in data:
        all_fields.update(record.keys())

        et = record.get('event_type', '') or ''
        event_types[et if et else 'MISSING'] += 1

        host = record.get('computer_name')
        if host:
            hosts.add(host)
        user = record.get('process_user')
        if user:
            users.add(user)

        if et == 'process_creation':
            pname = record.get('process_name', '')
            if pname:
                process_names[pname] += 1

        t = record.get('event_creation_date', '')
        if t:
            if min_time is None or t < min_time:
                min_time = t
            if max_time is None or t > max_time:
                max_time = t

    low_freq = [name for name, count in process_names.items() if count <= 2]

    return StatsResult(
        total_records=len(data),
        time_range=(min_time or '', max_time or ''),
        hosts=sorted(hosts),
        users=sorted(users),
        event_type_dist=dict(event_types.most_common()),
        process_freq=dict(process_names.most_common()),
        low_freq_processes=sorted(low_freq),
        all_fields=sorted(all_fields - {'_idx'}),
    )
