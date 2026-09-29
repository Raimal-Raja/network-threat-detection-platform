"""Auditable ingestion of CTU-13 scenario 11, using only the standard library."""

import csv
import hashlib
import ipaddress
import json
import os
import platform
import re
import sqlite3
import ssl
import tempfile
import urllib.request
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

DATASET_ID = 'ctu13-scenario11'
SOURCE_URL = ('https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/'
              'detailed-bidirectional-flow-labels/capture20110818-2.binetflow')
SOURCE_SHA256 = 'cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c'
SOURCE_BYTES = 14_596_615
SOURCE_PAGE = 'https://www.stratosphereips.org/datasets-ctu13'
SOURCE_README = 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/README.md'
LICENSE_URL = 'https://creativecommons.org/licenses/by/2.0/'
ATTRIBUTION = ('Garcia, Sebastian. Malware Capture Facility Project. '
               'Stratosphere Laboratory, Czech Technical University. '
               'https://www.stratosphereips.org/datasets-ctu13')
HEADER = ['StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir', 'DstAddr',
          'Dport', 'State', 'sTos', 'dTos', 'TotPkts', 'TotBytes', 'SrcBytes', 'Label']
MAX_DOWNLOAD_BYTES = 30_000_000


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _json_line(value):
    return json.dumps(value, sort_keys=True, allow_nan=False) + '\n'


def download_source(destination, ca_file=None):
    """Download the pinned flow CSV only; verify before publishing the file."""
    destination = Path(destination)
    if destination.exists():
        if sha256_file(destination) != SOURCE_SHA256:
            raise ValueError('existing source checksum mismatch; choose another path')
        return {'cached': True, 'sha256': SOURCE_SHA256, 'bytes': destination.stat().st_size}
    destination.parent.mkdir(parents=True, exist_ok=True)
    context = ssl.create_default_context()
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    descriptor, temporary_name = tempfile.mkstemp(prefix='.download-', dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            request = urllib.request.Request(SOURCE_URL, headers={'User-Agent': 'threat-platform-learning/0.2'})
            with urllib.request.urlopen(request, context=context, timeout=30) as source:
                total = 0
                while block := source.read(1024 * 1024):
                    total += len(block)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError('source exceeds the download size limit')
                    target.write(block)
        if temporary.stat().st_size != SOURCE_BYTES or sha256_file(temporary) != SOURCE_SHA256:
            raise ValueError('download checksum/size mismatch; no source published')
        # Same-filesystem hard link publishes verified bytes atomically and
        # refuses to overwrite. NTFS and common Linux filesystems support it.
        os.link(temporary, destination)
        return {'cached': False, 'sha256': SOURCE_SHA256, 'bytes': SOURCE_BYTES}
    finally:
        temporary.unlink(missing_ok=True)


def _nonnegative_integer(value, field):
    if not re.fullmatch(r'[0-9]+', value):
        raise ValueError(f'invalid_{field}')
    return int(value)


def convert_row(row, line_number):
    """Return a v2 event or a disposition reason. Unknown labels are not benign."""
    if None in row or any(value is None for value in row.values()):
        raise ValueError('wrong_column_count')
    row = {key: value.strip() for key, value in row.items()}
    # Resolve only explicitly labelled originating traffic, per source README.
    match = re.fullmatch(r'flow=From-(Normal|Botnet)(?:-.*)?', row['Label'])
    if not match:
        return None, 'unlabelled_or_ambiguous'
    protocol = row['Proto'].upper()
    if protocol not in ('TCP', 'UDP', 'ICMP'):
        return None, 'unsupported_protocol'
    try:
        naive = datetime.strptime(row['StartTime'], '%Y/%m/%d %H:%M:%S.%f')
    except ValueError as exc:
        raise ValueError('invalid_timestamp') from exc
    if naive.date().isoformat() != '2011-08-18':
        raise ValueError('timestamp_outside_scenario_date')
    # Scenario timeline says CEST: UTC+02:00 on this single capture date.
    timestamp = naive.replace(tzinfo=timezone(timedelta(hours=2))).astimezone(timezone.utc)
    try:
        duration = Decimal(row['Dur'])
        microseconds = duration * 1_000_000
        if (not duration.is_finite() or duration < 0 or duration > 86400
                or microseconds != microseconds.to_integral_value()):
            raise ValueError('invalid_duration')
    except InvalidOperation as exc:
        raise ValueError('invalid_duration') from exc
    packets = _nonnegative_integer(row['TotPkts'], 'packets')
    total_bytes = _nonnegative_integer(row['TotBytes'], 'bytes')
    source_bytes = _nonnegative_integer(row['SrcBytes'], 'source_bytes')
    if source_bytes > total_bytes:
        raise ValueError('source_bytes_exceed_total')
    try:
        endpoints = [str(ipaddress.ip_address(row[name])) for name in ('SrcAddr', 'DstAddr')]
    except ValueError as exc:
        raise ValueError('invalid_ip_address') from exc
    # Include all source columns except label: distinct flows must not collapse
    # merely because a small projected feature set happens to match.
    identity = {key: value for key, value in row.items() if key != 'Label'}
    identity['StartTime'] = timestamp.isoformat(timespec='microseconds')
    identity['Dur'] = str(int(microseconds))
    for name in ('TotPkts', 'TotBytes', 'SrcBytes'):
        identity[name] = str(int(identity[name]))
    fingerprint = hashlib.sha256(_json_line(identity).encode()).hexdigest()
    host_ids = [hashlib.sha256((DATASET_ID + ':' + address).encode()).hexdigest() for address in endpoints]
    event = {
        'schema_version': 2,
        'event_id': DATASET_ID + ':' + fingerprint,
        'timestamp': timestamp.isoformat(timespec='microseconds'),
        'duration_us': int(microseconds),
        'packets': packets,
        'bytes': total_bytes,
        'protocol': protocol,
        'label': int(match[1] == 'Botnet'),
        'simulated': True,
        'source_kind': 'public_capture_for_simulated_replay',
        'dataset_id': DATASET_ID,
        'source_line': line_number,
        'source_label': row['Label'],
        'source_host_id': host_ids[0],
        'destination_host_id': host_ids[1],
    }
    return event, None


def ingest_source(source_path, output_dir):
    """Verify pinned input, stage all outputs, then publish a complete directory."""
    source_path, output_dir = Path(source_path), Path(output_dir)
    if output_dir.exists():
        raise ValueError('output directory already exists; choose a new run directory')
    if sha256_file(source_path) != SOURCE_SHA256:
        raise ValueError('source checksum mismatch; refusing ingestion')
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.ingest-', dir=output_dir.parent)).resolve()
    # Cleanup is restricted to this newly created staging directory.
    if stage.parent != output_dir.parent.resolve():
        raise ValueError('staging directory escaped output parent')
    counts, labels = Counter(), Counter()
    prior_time = None
    inversions = 0
    try:
        database = stage / 'staging.sqlite'
        with closing(sqlite3.connect(database)) as connection:
            connection.execute('CREATE TABLE events (id TEXT PRIMARY KEY, timestamp TEXT, label INTEGER, payload TEXT)')
            with source_path.open(encoding='utf-8', newline='') as source, (stage / 'quarantine.jsonl').open('w', encoding='utf-8', newline='\n') as quarantine:
                reader = csv.DictReader(source, strict=True)
                if reader.fieldnames != HEADER:
                    raise ValueError('source header mismatch')
                for row in reader:
                    counts['source_rows'] += 1
                    labels[row.get('Label') or '<missing>'] += 1
                    try:
                        event, reason = convert_row(row, reader.line_num)
                    except (ValueError, OverflowError) as exc:
                        event, reason = None, str(exc)
                        counts['invalid_rows'] += 1
                    if reason:
                        counts['excluded_rows'] += 1
                        counts['reason:' + reason] += 1
                        quarantine.write(_json_line({'source_line': reader.line_num, 'reason': reason}))
                        continue
                    existing = connection.execute('SELECT label FROM events WHERE id=?', (event['event_id'],)).fetchone()
                    if existing:
                        if existing[0] != event['label']:
                            raise ValueError(f'conflicting labels for duplicate flow at line {reader.line_num}')
                        counts['excluded_rows'] += 1
                        counts['reason:duplicate_flow'] += 1
                        quarantine.write(_json_line({'source_line': reader.line_num, 'reason': 'duplicate_flow'}))
                        continue
                    if prior_time is not None and event['timestamp'] < prior_time:
                        inversions += 1
                    prior_time = event['timestamp']
                    connection.execute('INSERT INTO events VALUES (?, ?, ?, ?)',
                                       (event['event_id'], event['timestamp'], event['label'], _json_line(event)))
                    counts['accepted_rows'] += 1
                    counts['suspicious_rows' if event['label'] else 'benign_rows'] += 1
                connection.commit()
            if not counts['accepted_rows']:
                raise ValueError('no usable labelled events; no run published')
            with (stage / 'events.jsonl').open('w', encoding='utf-8', newline='\n') as output:
                for (payload,) in connection.execute('SELECT payload FROM events ORDER BY timestamp, id'):
                    output.write(payload)
            first, last = connection.execute('SELECT MIN(timestamp), MAX(timestamp) FROM events').fetchone()
        database.unlink()
        if sha256_file(source_path) != SOURCE_SHA256:
            raise ValueError('source changed during ingestion')
        assert counts['source_rows'] == counts['accepted_rows'] + counts['excluded_rows']
        code_hashes = {path.name: sha256_file(path) for path in sorted(Path(__file__).parent.glob('*.py'))}
        manifest = {
            'manifest_version': 1, 'event_schema_version': 2, 'dataset_id': DATASET_ID,
            'source': {'url': SOURCE_URL, 'sha256': SOURCE_SHA256, 'bytes': source_path.stat().st_size,
                       'checksum_origin': 'project-observed pin, not publisher-signed',
                       'description_url': SOURCE_PAGE, 'scenario_readme_url': SOURCE_README,
                       'license_url': LICENSE_URL, 'attribution': ATTRIBUTION},
            'transform': {'adapter': 'ctu13-scenario11-v1', 'source_timezone': 'CEST UTC+02:00',
                          'timezone_basis': 'scenario README timeline; fixed to 2011-08-18',
                          'output_timezone': 'UTC', 'duration_unit': 'integer microseconds',
                          'positive_label': 'flow=From-Botnet-*', 'negative_label': 'flow=From-Normal-*',
                          'other_labels': 'excluded, never assumed benign',
                          'sort': ['timestamp', 'event_id'], 'simulated': True},
            'counts': {key: counts[key] for key in ('source_rows', 'accepted_rows', 'excluded_rows', 'invalid_rows', 'benign_rows', 'suspicious_rows')},
            'exclusion_reasons': {key[7:]: value for key, value in sorted(counts.items()) if key.startswith('reason:')},
            'source_label_counts': dict(sorted(labels.items())),
            'accepted_input_time_inversions': inversions,
            'first_timestamp': first, 'last_timestamp': last,
            'runtime': {'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version},
            'code_sha256': code_hashes,
            'outputs': {name: {'sha256': sha256_file(stage / name), 'bytes': (stage / name).stat().st_size}
                        for name in ('events.jsonl', 'quarantine.jsonl')},
            'limitations': ['One short capture, not a representative benchmark.',
                            'Labels and host identifiers must not be model features.',
                            'Host hashes are pseudonyms, not guaranteed anonymization.',
                            'No training, leakage-free split, or detection metrics yet.'],
        }
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
        os.rename(stage, output_dir)
        return manifest
    finally:
        if stage.exists():
            # Only artifacts created above; never recurse into arbitrary paths.
            for artifact in stage.iterdir():
                artifact.unlink()
            stage.rmdir()


def verify_run(output_dir):
    """Check a published run against its manifest without modifying it."""
    output_dir = Path(output_dir)
    manifest = json.loads((output_dir / 'manifest.json').read_text(encoding='utf-8'))
    if (manifest.get('manifest_version') != 1 or manifest.get('event_schema_version') != 2
            or manifest.get('dataset_id') != DATASET_ID
            or manifest.get('source', {}).get('sha256') != SOURCE_SHA256):
        raise ValueError('unsupported manifest or source identity')
    for name in ('events.jsonl', 'quarantine.jsonl'):
        expected = manifest['outputs'][name]
        if ((output_dir / name).stat().st_size != expected['bytes']
                or sha256_file(output_dir / name) != expected['sha256']):
            raise ValueError(f'output checksum/size mismatch: {name}')
    counts, reasons, seen = Counter(), Counter(), set()
    previous = None
    with (output_dir / 'events.jsonl').open(encoding='utf-8') as source:
        for raw in source:
            event = json.loads(raw)
            if (event['schema_version'] != 2 or event['simulated'] is not True
                    or type(event['label']) is not int or event['label'] not in (0, 1)
                    or event['protocol'] not in ('TCP', 'UDP', 'ICMP')
                    or any(type(event[key]) is not int or event[key] < 0 for key in ('duration_us', 'packets', 'bytes'))):
                raise ValueError('invalid processed event')
            timestamp = datetime.fromisoformat(event['timestamp'])
            if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
                raise ValueError('processed timestamp must be UTC')
            key = (timestamp, event['event_id'])
            if previous is not None and key < previous:
                raise ValueError('processed events are out of order')
            if event['event_id'] in seen:
                raise ValueError('duplicate processed event')
            previous = key
            seen.add(event['event_id'])
            counts['accepted_rows'] += 1
            counts['suspicious_rows' if event['label'] else 'benign_rows'] += 1
    with (output_dir / 'quarantine.jsonl').open(encoding='utf-8') as source:
        for raw in source:
            reasons[json.loads(raw)['reason']] += 1
            counts['excluded_rows'] += 1
    if (any(counts[key] != manifest['counts'][key] for key in ('accepted_rows', 'excluded_rows', 'suspicious_rows', 'benign_rows'))
            or counts['accepted_rows'] + counts['excluded_rows'] != manifest['counts']['source_rows']
            or dict(reasons) != manifest['exclusion_reasons']):
        raise ValueError('manifest row accounting mismatch')
    return {'verified': True, 'dataset_id': DATASET_ID, 'counts': manifest['counts'],
            'events_sha256': manifest['outputs']['events.jsonl']['sha256'], 'simulated': True}
