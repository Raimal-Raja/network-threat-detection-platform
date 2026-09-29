import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_platform import ingestion as ing


def fixture(**changes):
    row = dict(zip(ing.HEADER, ['2011/08/18 15:40:00.123456', '0.000123', 'tcp',
        '192.0.2.1', '12000', ' ->', '198.51.100.2', '443', 'CON', '0', '0',
        '3', '200', '120', 'flow=From-Normal-Test']))
    return dict(row, **changes)


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.csv'
        self.output = self.root / 'run'

    def source_file(self, rows, header=None):
        with self.source.open('w', encoding='utf-8', newline='') as out:
            writer = csv.DictWriter(out, fieldnames=header or ing.HEADER)
            writer.writeheader()
            writer.writerows(rows)
        return patch.object(ing, 'SOURCE_SHA256', ing.sha256_file(self.source))

    def test_units_timezone_and_provenance(self):
        event, reason = ing.convert_row(fixture(), 2)
        self.assertIsNone(reason)
        self.assertEqual(event['timestamp'], '2011-08-18T13:40:00.123456+00:00')
        self.assertEqual(event['duration_us'], 123)
        self.assertEqual(event['label'], 0)
        self.assertEqual(event['source_line'], 2)
        self.assertTrue(event['simulated'])
        self.assertNotIn('192.0.2.1', json.dumps(event))

    def test_background_and_direction_are_not_assumed_benign(self):
        for label in ('flow=Background', 'flow=To-Botnet-X', 'flow=To-Normal-X',
                      'flow=Normal-X', '', 'flow=From-Botnetish'):
            with self.subTest(label=label):
                event, reason = ing.convert_row(fixture(Label=label), 2)
                self.assertIsNone(event)
                self.assertEqual(reason, 'unlabelled_or_ambiguous')
        event, _ = ing.convert_row(fixture(Label='flow=From-Botnet-X'), 2)
        self.assertEqual(event['label'], 1)

    def test_invalid_measurements(self):
        for changes in ({'Dur': 'NaN'}, {'Dur': '-1'}, {'Dur': 'inf'},
                        {'Dur': '0.0000001'}, {'TotPkts': '3.5'},
                        {'TotBytes': '-1'}, {'SrcBytes': '201'},
                        {'SrcAddr': 'bad'}, {'StartTime': 'bad'},
                        {'StartTime': '2012/08/18 15:40:00.123456'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ing.convert_row(fixture(**changes), 2)

    def test_malformed_columns(self):
        for row in (fixture(Dur=None), dict(fixture(), **{})):
            if row['Dur'] is not None:
                row[None] = ['unexpected']
            with self.assertRaisesRegex(ValueError, 'column_count'):
                ing.convert_row(row, 2)

    def test_unsupported_protocol(self):
        self.assertEqual(ing.convert_row(fixture(Proto='arp'), 2)[1], 'unsupported_protocol')

    def test_pipeline_accounting_dedup_sort_and_reproducibility(self):
        later = fixture(StartTime='2011/08/18 15:41:00.000000', Label='flow=From-Botnet-X')
        rows = [later, fixture(), fixture(), fixture(Label='flow=Background'), fixture(Dur='NaN')]
        with self.source_file(rows):
            first = ing.ingest_source(self.source, self.output)
            second = ing.ingest_source(self.source, self.root / 'second')
        self.assertEqual(first, second)
        self.assertEqual(first['counts'], dict(source_rows=5, accepted_rows=2, excluded_rows=3,
                                              invalid_rows=1, benign_rows=1, suspicious_rows=1))
        self.assertEqual(first['accepted_input_time_inversions'], 1)
        events = [json.loads(line) for line in (self.output / 'events.jsonl').read_text().splitlines()]
        self.assertEqual([event['label'] for event in events], [0, 1])
        for name, metadata in first['outputs'].items():
            self.assertEqual(ing.sha256_file(self.output / name), metadata['sha256'])
        self.assertEqual(len(list(self.output.iterdir())), 3)

    def test_conflicting_duplicate_fails_without_publishing(self):
        with self.source_file([fixture(), fixture(Label='flow=From-Botnet-X')]):
            with self.assertRaisesRegex(ValueError, 'conflicting labels'):
                ing.ingest_source(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.ingest-*')))

    def test_verify_detects_changed_artifacts_and_manifest_counts(self):
        with self.source_file([fixture()]):
            ing.ingest_source(self.source, self.output)
            self.assertTrue(ing.verify_run(self.output)['verified'])
            manifest_path = self.output / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['counts']['source_rows'] += 1
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'accounting'):
                ing.verify_run(self.output)
            (self.output / 'events.jsonl').write_text('modified')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                ing.verify_run(self.output)

    def test_bad_pin_and_empty_usable_input(self):
        self.source.write_text('not the pinned file')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            ing.ingest_source(self.source, self.output)
        with self.source_file([fixture(Label='flow=Background')]):
            with self.assertRaisesRegex(ValueError, 'no usable'):
                ing.ingest_source(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_schema_mismatch_is_fatal(self):
        self.source.write_text('wrong,header\n1,2\n')
        with patch.object(ing, 'SOURCE_SHA256', ing.sha256_file(self.source)):
            with self.assertRaisesRegex(ValueError, 'header mismatch'):
                ing.ingest_source(self.source, self.output)

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        marker = self.output / 'keep.txt'
        marker.write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            ing.ingest_source(self.source, self.output)
        self.assertEqual(marker.read_text(), 'preserve')

    def test_download_verification_cache_and_corruption(self):
        payload = b'public flow fixture\n'
        import hashlib
        with patch.object(ing, 'SOURCE_SHA256', hashlib.sha256(payload).hexdigest()), \
             patch.object(ing, 'SOURCE_BYTES', len(payload)), \
             patch.object(ing.urllib.request, 'urlopen', return_value=io.BytesIO(payload)) as mocked:
            self.assertFalse(ing.download_source(self.source)['cached'])
            self.assertTrue(ing.download_source(self.source)['cached'])
            self.assertEqual(mocked.call_count, 1)
            self.source.write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                ing.download_source(self.source)

    def test_bad_download_never_publishes(self):
        with patch.object(ing.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad')):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                ing.download_source(self.source)
        self.assertFalse(self.source.exists())
        self.assertFalse(list(self.root.glob('.download-*')))

    def test_network_error_and_size_limit_cleanup(self):
        with patch.object(ing.urllib.request, 'urlopen', side_effect=OSError('offline')):
            with self.assertRaises(OSError):
                ing.download_source(self.source)
        with patch.object(ing, 'MAX_DOWNLOAD_BYTES', 2), \
             patch.object(ing.urllib.request, 'urlopen', return_value=io.BytesIO(b'too big')):
            with self.assertRaisesRegex(ValueError, 'size limit'):
                ing.download_source(self.source)
        self.assertFalse(self.source.exists())
        self.assertFalse(list(self.root.glob('.download-*')))


if __name__ == '__main__':
    unittest.main()
