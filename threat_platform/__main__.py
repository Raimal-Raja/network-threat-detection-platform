"""Run from the repository root with python -m threat_platform."""

import argparse
import json
import platform
from pathlib import Path

from .events import inspect_dataset, write_dataset


def main():
    parser = argparse.ArgumentParser(description='SIMULATED network-event project, Step 1')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('generate', help='create a synthetic JSONL dataset')
    create.add_argument('--output', type=Path, default=Path('data/simulated.jsonl'))
    create.add_argument('--count', type=int, default=1000)
    create.add_argument('--seed', type=int, default=42)
    check = sub.add_parser('validate', help='validate an existing dataset without changing it')
    check.add_argument('path', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'generate':
            report = write_dataset(args.output, args.count, args.seed)
            report.update(generator='synthetic-v1', seed=args.seed,
                          python_version=platform.python_version())
        else:
            report = inspect_dataset(args.path)
        print(json.dumps(report, indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(2, f'Failed: {exc}\n')


if __name__ == '__main__':
    main()
