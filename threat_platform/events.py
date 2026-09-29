"""Version-one contract and deterministic synthetic event fixtures."""

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = 1
FIELDS = {'event_id', 'timestamp', 'duration_ms', 'packets', 'bytes',
          'protocol', 'label', 'simulated'}


def validate_event(event):
    """Validate one offline, labelled event; return its parsed UTC timestamp."""
    if not isinstance(event, dict) or set(event) != FIELDS:
        raise ValueError('event must contain exactly the documented fields')
    if not isinstance(event['event_id'], str) or not event['event_id'].strip():
        raise ValueError('event_id must be a nonempty string')
    if not isinstance(event['timestamp'], str):
        raise ValueError('timestamp must be an ISO-8601 string')
    try:
        timestamp = datetime.fromisoformat(event['timestamp'])
    except ValueError as exc:
        raise ValueError('invalid ISO-8601 timestamp') from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
        raise ValueError('timestamp must explicitly use UTC')
    for field in ('duration_ms', 'packets', 'bytes'):
        if type(event[field]) is not int or event[field] < 0:
            raise ValueError(f'{field} must be a nonnegative integer')
    if event['protocol'] not in ('TCP', 'UDP', 'ICMP'):
        raise ValueError('protocol must be TCP, UDP, or ICMP')
    if type(event['label']) is not int or event['label'] not in (0, 1):
        raise ValueError('label must be integer 0 or 1')
    if event['simulated'] is not True:
        raise ValueError('Step 1 requires simulated=true')
    return timestamp


def generate_events(count=1000, seed=42):
    """Synthetic fixtures, not an empirical network-traffic model."""
    if type(count) is not int or not 1 <= count <= 1_000_000:
        raise ValueError('count must be an integer from 1 to 1000000')
    if type(seed) is not int:
        raise ValueError('seed must be an integer')
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(count):
        suspicious = int(rng.random() < 0.08)
        packets = rng.randint(1, 150 if suspicious else 100)
        yield {
            'event_id': f'sim-{index:08d}',
            'timestamp': (start + timedelta(seconds=index * 60)).isoformat(),
            'duration_ms': rng.randint(1, 20000),
            'packets': packets,
            'bytes': packets * rng.randint(40, 1500),
            'protocol': rng.choice(['TCP', 'UDP', 'ICMP']),
            'label': suspicious,
            'simulated': True,
        }


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f'nonstandard JSON number: {value}')


def inspect_dataset(path):
    """Fail on the first bad row; hash exact bytes, inspect without modifying."""
    ids, fingerprints = set(), set()
    first = previous = None
    rows = positives = 0
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for line_number, raw in enumerate(source, 1):
            digest.update(raw)
            try:
                event = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_keys,
                                   parse_constant=_reject_constant)
                timestamp = validate_event(event)
                if event['event_id'] in ids:
                    raise ValueError('duplicate event_id')
                # Canonicalize equivalent UTC spellings; ignore ID and label.
                content = {k: v for k, v in event.items() if k not in ('event_id', 'label')}
                content['timestamp'] = timestamp.isoformat()
                fingerprint = json.dumps(content, sort_keys=True)
                if fingerprint in fingerprints:
                    raise ValueError('duplicate event content, ignoring ID and label')
                if previous is not None and timestamp < previous:
                    raise ValueError('events must be in nondecreasing timestamp order')
                ids.add(event['event_id'])
                fingerprints.add(fingerprint)
                first = timestamp if first is None else first
                previous = timestamp
                rows += 1
                positives += event['label']
            except (ValueError, TypeError, OverflowError) as exc:
                raise ValueError(f'line {line_number}: {exc}') from exc
    if rows == 0:
        raise ValueError('dataset is empty')
    return {
        'schema_version': SCHEMA_VERSION,
        'rows': rows,
        'suspicious_rows': positives,
        'benign_rows': rows - positives,
        'first_timestamp': first.isoformat(),
        'last_timestamp': previous.isoformat(),
        'sha256': digest.hexdigest(),
        'simulated': True,
    }


def write_dataset(path, count=1000, seed=42):
    # Validate arguments before creating a file. Exclusive creation avoids clobbering.
    events = generate_events(count, seed)
    first = next(events)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as target:
        target.write(json.dumps(first, sort_keys=True) + '\n')
        for event in events:
            target.write(json.dumps(event, sort_keys=True) + '\n')
    return inspect_dataset(path)
