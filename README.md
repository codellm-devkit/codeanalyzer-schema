# codeanalyzer-schema

Versioned schemas for what a codeanalyzer emits: the `analysis.json` payload and
the Neo4j graph contract, one directory per schema line.

```
v1/   the pre-canonical line: each analyzer's own v1 shape, descriptive
v2/   the canonical line: one shared spine + per-language schemas, prescriptive
```

## v1 snapshots

The `v1/` tree contains the published language-analysis and Neo4j contracts.
These files are compatibility snapshots: new schema-v2 work must not rewrite
them. A path selector can validate one snapshot independently, for example:

```bash
python3 scripts/check.py v1/json/java
```

## v2 layout

```
v2/json/analysis.schema.json        the canonical spine (permissive, open nodes)
v2/json/<lang>/analysis.schema.json the language's schema: $ref the spine, add its own
                                    fields, close with unevaluatedProperties: false
v2/json/<lang>/*.sample.json        real analyzer output the schema is checked against
v2/neo4j/contract.schema.json       meta-schema for the graph contract
v2/neo4j/<lang>/schema.neo4j.json   byte-identical copy of the analyzer's contract
v2/iac/                             the IaC contract (see below)
```

The split is the point. The spine states the invariant shape: the containment
tree `application -> module -> type -> callable -> body`, the edge families, and
the `can://` identity. It leaves every node **open**, so a language may add fields.
Each language schema then **closes** its nodes: a field an analyzer starts
emitting that nobody recorded fails validation there. Where the three analyzers
genuinely disagree, the spine states the intersection and the disagreement is
recorded verbatim under `x-cldk.divergences` rather than papered over.

Sources for the current v2 files: codeanalyzer-java v3.3.3, codeanalyzer-python
v1.5.4, codeanalyzer-typescript v1.6.3. All three are on analysis schema and graph
contract `2.0.0`.

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

These live repositories are downstream backend-consumer gates, not inputs
fetched by this repository:

- `sample-daytrader/sample.daytrader.microservices@8a68b59430a94a242c54384763da9eb7682728b4`:
  each emitted document
  must pass structural validation with `v2/iac/json/analysis.schema.json` and
  semantic `scripts/check_iac.py` validation.
- `quarkuscoffeeshop/quarkuscoffeeshop-helm@aa3c842658e0fc7e44fa25132d8b817eab225cbe`:
  each emitted document must pass
  structural validation with `v2/iac/json/analysis.schema.json` and semantic
  `scripts/check_iac.py` validation.

Preserve the emitted JSON from both pinned repositories and do not weaken
either contract to admit a consumer output.

## Checking

Install the checker dependency once, then run the repository gates:

```bash
python3 -m pip install jsonschema
python3 scripts/check.py            # every schema, every sample
python3 scripts/check.py v2/json    # one subtree
python3 -m unittest discover -s tests -v
```

Each schema is checked as a valid JSON Schema, then used to validate the
`*.sample.json` files beside it plus anything its `x-cldk.validates` globs match.
Cross-file `$ref`s resolve against the files in this repo by `$id`. Nothing is
fetched over the network, so the unit and repository check suites stay
network-free.

## Refreshing the v2 samples

Each analyzer's release workflow opens a pull request here with its graph
contract and samples. To refresh by hand, follow the steps below.

The samples are unedited analyzer output on the analyzers' own test fixtures.
Each language keeps an `-a 4` sample for the full level ladder, plus whatever
extra runs are needed to reach parts of the tree the first one never populates:

| Sample | Analyzer / fixture | Level | Covers |
| --- | --- | --- | --- |
| `java/analysis.l4.sample.json` | java, `test-applications/dataflow-test` | 4 | body, cfg/cdg/ddg, param edges |
| `java/analysis.enum-record.sample.json` | java, `test-applications/enum-record-bodies-test` | 2 | `enum_constants`, `record_components` |
| `python/analysis.l4.sample.json` | python, `whole_applications/manifests_app` | 4 | artifacts, config keys, dependencies |
| `python/analysis.dataflow.sample.json` | python, `single_functionalities/dataflow` | 4 | classes, attributes, `raise`/`handler` body nodes |
| `python/analysis.entrypoints.sample.json` | python, `single_functionalities/entrypoints_local` | 2 | `entrypoints`, `external_symbols` |
| `typescript/analysis.l4.sample.json` | typescript, `test/fixtures/sample-app` | 4 | interfaces, enums, namespaces, decorators, dataflow |

```
java -jar codeanalyzer-<ver>.jar -i <fixture> -o <out> -a 4   # java
canpy -i <fixture> -o <out> -a 4                              # python
bun run src/index.ts -i <fixture> -o <out> -a 4               # typescript
```

Run each analyzer on the fixture **in place, inside a checkout of the release
tag**. Do not run it on a copy:

- The application id is the fixture directory's name.
- TypeScript resolves the fixture's external packages from the checkout's
  `node_modules`.
- Python records the fixture's absolute path and the checkout's git revision.

Copy the graph contract from the release's `schema.neo4j.json` (java,
typescript) or `schema.json` (python) asset.

Copy the resulting `analysis.json` over the sample it replaces and re-run the
check. A new failure means the analyzer moved and the schema has
not. Fix the schema, or the analyzer, on purpose.
