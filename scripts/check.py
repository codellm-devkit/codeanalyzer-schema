#!/usr/bin/env python3
"""Check every schema in this repo is a valid JSON Schema, and validate the
documents it claims to cover.

A schema validates any *.sample.json sitting in its own directory, plus every
file matched by the globs in its x-cldk.validates list (relative to the schema).

    python3 scripts/check.py            # all versions
    python3 scripts/check.py v1/java    # one directory
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent


def check(schema_path: Path) -> int:
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    rel = schema_path.relative_to(ROOT)
    print(f"ok    {rel}")

    covered = list(schema_path.parent.glob("*.sample.json"))
    for pattern in schema.get("x-cldk", {}).get("validates", []):
        covered += schema_path.parent.glob(pattern)

    failures = 0
    validator = Draft202012Validator(schema)
    for sample in sorted(set(covered)):
        errors = sorted(validator.iter_errors(json.loads(sample.read_text())),
                        key=lambda e: list(e.absolute_path))
        if errors:
            failures += 1
            print(f"FAIL  {sample.relative_to(ROOT)}: {len(errors)} error(s)")
            for e in errors[:5]:
                where = "/".join(str(p) for p in e.absolute_path) or "<root>"
                print(f"        {where}: {e.message[:160]}")
        else:
            print(f"ok    {sample.relative_to(ROOT)}")
    return failures


def main() -> int:
    where = ROOT / sys.argv[1] if len(sys.argv) > 1 else ROOT
    schemas = sorted(where.rglob("*.schema.json"))
    if not schemas:
        print(f"no schemas under {where}")
        return 1
    return min(sum(check(s) for s in schemas), 1)


if __name__ == "__main__":
    raise SystemExit(main())
