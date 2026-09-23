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
from referencing import Registry, Resource

if __package__:
    from .check_iac import assert_monotone, check_catalog, check_document
else:
    from check_iac import assert_monotone, check_catalog, check_document

ROOT = Path(__file__).resolve().parent.parent


def registry() -> Registry:
    """Resolve cross-file $refs against the schemas in this repo, by their $id.

    The v2 per-language schemas $ref the canonical spine by its published URL,
    which is not fetchable offline (and must not be fetched: the file on disk is
    the thing under test).
    """
    resources = []
    for path in ROOT.rglob("*.schema.json"):
        schema = json.loads(path.read_text())
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


REGISTRY = registry()


def check(schema_path: Path) -> int:
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    rel = schema_path.relative_to(ROOT)
    print(f"ok    {rel}")

    covered = list(schema_path.parent.glob("*.sample.json"))
    for pattern in schema.get("x-cldk", {}).get("validates", []):
        covered += schema_path.parent.glob(pattern)

    failures = 0
    validator = Draft202012Validator(schema, registry=REGISTRY)
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


def selected_iac_root(where: Path) -> Path | None:
    """Return the IaC contract root only when the selected path includes it."""
    iac_root = ROOT / "v2/iac"
    if not iac_root.exists():
        return None
    try:
        iac_root.relative_to(where)
        return iac_root
    except ValueError:
        pass
    try:
        where.relative_to(iac_root)
        return iac_root
    except ValueError:
        return None


def check_iac_contract(iac_root: Path) -> int:
    """Run semantic and level-monotonicity checks for the IaC contract."""
    failures = 0
    analysis_paths = sorted((iac_root / "json").glob("analysis.l*.sample.json"))
    analyses: list[tuple[Path, dict]] = []

    for path in analysis_paths:
        document = json.loads(path.read_text())
        analyses.append((path, document))
        errors = check_document(document)
        if errors:
            failures += 1
            print(f"FAIL  {path.relative_to(ROOT)}: {len(errors)} semantic error(s)")
            for error in errors:
                print(f"        {error}")
        else:
            print(f"ok    {path.relative_to(ROOT)} (semantic)")

    catalog_path = iac_root / "neo4j/schema.neo4j.sample.json"
    if catalog_path.exists():
        errors = check_catalog(json.loads(catalog_path.read_text()))
        if errors:
            failures += 1
            print(f"FAIL  {catalog_path.relative_to(ROOT)}: {len(errors)} semantic error(s)")
            for error in errors:
                print(f"        {error}")
        else:
            print(f"ok    {catalog_path.relative_to(ROOT)} (semantic)")

    for (lower_path, lower), (higher_path, higher) in zip(analyses, analyses[1:]):
        errors = assert_monotone(lower, higher)
        label = f"{lower_path.name} <= {higher_path.name}"
        if errors:
            failures += 1
            print(f"FAIL  {label}: {len(errors)} monotonicity error(s)")
            for error in errors:
                print(f"        {error}")
        else:
            print(f"ok    {label} (monotone)")

    return failures


def main() -> int:
    where = ROOT / sys.argv[1] if len(sys.argv) > 1 else ROOT
    schemas = sorted(where.rglob("*.schema.json"))
    if not schemas:
        print(f"no schemas under {where}")
        return 1
    failures = sum(check(schema) for schema in schemas)
    if failures:
        return 1
    iac_root = selected_iac_root(where)
    if iac_root is not None:
        failures += check_iac_contract(iac_root)
    return min(failures, 1)


if __name__ == "__main__":
    raise SystemExit(main())
