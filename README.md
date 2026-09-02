# codeanalyzer-schema

Versioned contracts for CodeLLM analyzers and SDK consumers.

## v1 snapshots

The `v1/` tree contains the published language-analysis and Neo4j contracts.
These files are compatibility snapshots: new schema-v2 work must not rewrite
them. A path selector can validate one snapshot independently, for example:

```bash
python3 scripts/check.py v1/json/java
```

## IaC schema v2 contract

The files under `v2/iac/` are the normative contract for
`codeanalyzer-iac`:

- `v2/iac/json/analysis.schema.json` is the normative JSON output schema.
  Analyzer golden outputs must validate against it at their declared analysis
  level and must also pass `scripts/check_iac.py` semantic validation.
- `v2/iac/json/analysis.l1.sample.json`, `analysis.l2.sample.json`, and
  `analysis.l3.sample.json` demonstrate the additive level contract. Higher
  levels preserve every lower-level fact; resolution fields may be added but
  existing facts may not be replaced.
- `v2/iac/neo4j/contract.schema.json` describes the graph-catalog format.
  The `codeanalyzer-iac` catalog must byte-match
  `v2/iac/neo4j/schema.neo4j.sample.json`.

Draft 2020-12 validation covers document structure. The repository semantic
gate additionally enforces globally unique node IDs across all named
collections, real edge endpoints, source digests and span bounds, relative
artifact paths, contiguous render-profile layer ordinals, hash-only Secret
data, and `Package.id == Package.purl`. Every identity alias—including a Helm
Chart alias—must target a collected canonical node, must not self-target or
target another alias, and must have exactly one matching `iac_alias_of` edge.
The graph catalog admits only the shared neutral relationships
`HAS_ARTIFACT` and `DEFINES_CONFIG`; IaC-owned names use the `IAC_*` namespace,
relationship properties are empty, and all referenced labels must exist.

Install the checker dependency once, then run the repository gates:

```bash
python3 -m pip install jsonschema
python3 scripts/check.py
python3 -m unittest discover -s tests -v
```

The unit and repository check suites use only checked-in files and stay
network-free. The two live repositories are a downstream backend-consumer
gate, not inputs fetched by this repository: preserve emitted JSON from each
pinned consumer, validate it with `v2/iac/json/analysis.schema.json`, and run
it through `scripts/check_iac.py` without weakening either contract.
