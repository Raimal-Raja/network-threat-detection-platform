"""Run from the repository root with python -m threat_platform."""

import argparse
import json
import platform
from pathlib import Path

from .events import inspect_dataset, write_dataset


def main():
    parser = argparse.ArgumentParser(description='SIMULATED network-event learning project')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('generate', help='create a synthetic JSONL dataset')
    create.add_argument('--output', type=Path, default=Path('data/simulated.jsonl'))
    create.add_argument('--count', type=int, default=1000)
    create.add_argument('--seed', type=int, default=42)
    check = sub.add_parser('validate', help='validate an existing dataset without changing it')
    check.add_argument('path', type=Path)
    fetch = sub.add_parser('download-ctu13', help='fetch and verify the pinned public flow CSV')
    fetch.add_argument('--output', type=Path, default=Path('data/raw/ctu13-scenario11.binetflow'))
    fetch.add_argument('--ca-file', type=Path, help='optional trusted PEM CA bundle; TLS verification remains enabled')
    ingest = sub.add_parser('ingest-ctu13', help='build a versioned, audited public-data run')
    ingest.add_argument('--source', type=Path, default=Path('data/raw/ctu13-scenario11.binetflow'))
    ingest.add_argument('--output', type=Path, default=Path('data/processed/ctu13-scenario11-v1'))
    verify = sub.add_parser('verify-ingestion', help='verify a v2 processed run against its manifest')
    verify.add_argument('path', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'generate':
            report = write_dataset(args.output, args.count, args.seed)
            report.update(generator='synthetic-v1', seed=args.seed,
                          python_version=platform.python_version())
        elif args.command == 'validate':
            report = inspect_dataset(args.path)
        elif args.command == 'download-ctu13':
            from .ingestion import download_source
            report = download_source(args.output, args.ca_file)
        elif args.command == 'ingest-ctu13':
            from .ingestion import ingest_source
            report = ingest_source(args.source, args.output)
        else:
            from .ingestion import verify_run
            report = verify_run(args.path)
        print(json.dumps(report, indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f'Failed: {exc}\n')


if __name__ == '__main__':
    main()
