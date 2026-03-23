#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


TIMESTAMP_PATTERNS = (
    re.compile(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b"),
)


def normalize_string(value: str, case_dir: str) -> str:
    normalized = value.replace(case_dir, "__CASE_DIR__")
    for pattern in TIMESTAMP_PATTERNS:
        normalized = pattern.sub("<TS>", normalized)
    return normalized


def normalize_json(value, case_dir: str):
    if isinstance(value, dict):
        return {key: normalize_json(inner, case_dir) for key, inner in value.items()}
    if isinstance(value, list):
        return [normalize_json(inner, case_dir) for inner in value]
    if isinstance(value, str):
        return normalize_string(value, case_dir)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("json", "text"), required=True)
    parser.add_argument("--case-dir", required=True)
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    args = parser.parse_args()

    raw = Path(args.input_file).read_text()
    output_path = Path(args.output_file)

    if args.mode == "json":
        doc = json.loads(raw)
        normalized = normalize_json(doc, args.case_dir)
        output_path.write_text(json.dumps(normalized, indent=2) + "\n")
    else:
        output_path.write_text(normalize_string(raw, args.case_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
