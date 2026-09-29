import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from threat_platform.events import generate_events, inspect_dataset, validate_event, write_dataset


class EventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'events.jsonl'
        self.events = list(generate_events(3, 42))

    def write(self, events):
        self.path.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')

    def test_repeatability_including_bytes(self):
        a = write_dataset(self.path, 100, 42)
        b = write_dataset(self.path.with_name('other.jsonl'), 100, 42)
        self.assertEqual(a, b)

    def test_different_seed_changes_data(self):
        self.assertNotEqual(list(generate_events(10, 42)), list(generate_events(10, 43)))

    def test_valid_summary(self):
        self.write(self.events)
        report = inspect_dataset(self.path)
        self.assertEqual(report['rows'], 3)
        self.assertEqual(report['suspicious_rows'], sum(e['label'] for e in self.events))
        self.assertEqual(len(report['sha256']), 64)

    def test_invalid_fields(self):
        for field, value in [('event_id', ''), ('packets', -1), ('bytes', True),
                             ('duration_ms', 1.2), ('label', True), ('label', 2),
                             ('protocol', 'UNKNOWN'), ('simulated', False),
                             ('timestamp', '2026-01-01T00:00:00'),
                             ('timestamp', '2026-01-01T00:00:00+05:00'),
                             ('timestamp', 'invalid')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_event(dict(self.events[0], **{field: value}))

    def test_missing_extra_and_nonobject(self):
        missing = dict(self.events[0])
        del missing['label']
        for event in (missing, dict(self.events[0], extra=1), [], None):
            with self.subTest(event=event), self.assertRaises(ValueError):
                validate_event(event)

    def test_duplicate_id(self):
        self.write([self.events[0], dict(self.events[1], event_id=self.events[0]['event_id'])])
        with self.assertRaisesRegex(ValueError, 'line 2: duplicate event_id'):
            inspect_dataset(self.path)

    def test_duplicate_content_despite_new_id_label_and_timestamp_spelling(self):
        copy = dict(self.events[0], event_id='copy', label=1-self.events[0]['label'])
        copy['timestamp'] = copy['timestamp'].replace('+00:00', 'Z')
        self.write([self.events[0], copy])
        with self.assertRaisesRegex(ValueError, 'duplicate event content'):
            inspect_dataset(self.path)

    def test_out_of_order(self):
        self.write(list(reversed(self.events)))
        with self.assertRaisesRegex(ValueError, 'timestamp order'):
            inspect_dataset(self.path)

    def test_bad_json_and_empty_input(self):
        for content in ('', '\n', '{bad json}', '{"a":1,"a":2}', '{"a":NaN}'):
            self.path.write_text(content, encoding='utf-8')
            with self.subTest(content=content), self.assertRaises(ValueError):
                inspect_dataset(self.path)

    def test_invalid_utf8(self):
        self.path.write_bytes(b'\xff\n')
        with self.assertRaisesRegex(ValueError, 'line 1'):
            inspect_dataset(self.path)

    def test_refuses_overwrite(self):
        write_dataset(self.path, 3)
        original = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            write_dataset(self.path, 5)
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_count_leaves_no_file(self):
        for count in (0, -1, 1_000_001, True):
            with self.subTest(count=count), self.assertRaises(ValueError):
                write_dataset(self.path, count)
            self.assertFalse(self.path.exists())

    def test_cli_generate_validate_and_failure(self):
        prefix = [sys.executable, '-m', 'threat_platform']
        result = subprocess.run(prefix + ['generate', '--output', str(self.path), '--count', '12'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['rows'], 12)
        checked = subprocess.run(prefix + ['validate', str(self.path)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)['sha256'], json.loads(result.stdout)['sha256'])
        failed = subprocess.run(prefix + ['generate', '--output', str(self.path)], capture_output=True, text=True)
        self.assertEqual(failed.returncode, 2)


if __name__ == '__main__':
    unittest.main()
