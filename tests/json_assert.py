#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


def load(path: str):
    return json.loads(Path(path).read_text())


def parse_expected(raw: str):
    lowered = raw.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    try:
        if raw.startswith("0") and raw not in ("0", "0.0") and not raw.startswith("0."):
            raise ValueError
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def walk(doc, path: str):
    cur = doc
    for part in path.split('.'):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file")
    parser.add_argument("path")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--equals")
    group.add_argument("--type", dest="expected_type")
    group.add_argument("--len", dest="expected_len", type=int)
    group.add_argument("--contains")
    args = parser.parse_args()

    doc = load(args.json_file)
    value = walk(doc, args.path)

    if args.equals is not None:
        expected = parse_expected(args.equals)
        if value != expected:
            print(f"assert_json failed: {args.path} expected {expected!r}, got {value!r}", file=sys.stderr)
            return 1
        return 0
    if args.expected_type is not None:
        mapping = {
            "str": str,
            "int": int,
            "float": (int, float),
            "bool": bool,
            "list": list,
            "dict": dict,
            "null": type(None),
        }
        if args.expected_type not in mapping:
            print(f"unsupported type {args.expected_type}", file=sys.stderr)
            return 2
        if not isinstance(value, mapping[args.expected_type]):
            print(f"assert_json failed: {args.path} expected type {args.expected_type}, got {type(value).__name__}", file=sys.stderr)
            return 1
        return 0
    if args.expected_len is not None:
        if len(value) != args.expected_len:
            print(f"assert_json failed: {args.path} expected len {args.expected_len}, got {len(value)}", file=sys.stderr)
            return 1
        return 0
    if args.contains is not None:
        hay = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        if args.contains not in hay:
            print(f"assert_json failed: {args.path} did not contain {args.contains!r}", file=sys.stderr)
            return 1
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
