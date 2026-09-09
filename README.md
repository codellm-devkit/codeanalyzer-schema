# codeanalyzer-schema

Versioned schemas for what a codeanalyzer emits: the `analysis.json` payload and
the Neo4j graph contract, one directory per schema line.

```
v1/   the pre-canonical line: each analyzer's own v1 shape, descriptive
v2/   the canonical line: one shared spine + per-language schemas, prescriptive
```

## v2 layout

```
v2/json/analysis.schema.json        the canonical spine (permissive, open nodes)
v2/json/<lang>/analysis.schema.json the language's schema: $ref the spine, add its own
                                    fields, close with unevaluatedProperties: false
v2/json/<lang>/*.sample.json        real analyzer output the schema is checked against
v2/neo4j/contract.schema.json       meta-schema for the graph contract
v2/neo4j/<lang>/schema.neo4j.json   byte-identical copy of the analyzer's contract
```

The split is the point. The spine states the invariant shape — the containment
tree `application -> module -> type -> callable -> body`, the edge families, the
`can://` identity — and leaves every node **open**, so a language may add fields.
Each language schema then **closes** its nodes: a field an analyzer starts
emitting that nobody recorded fails validation there. Where the three analyzers
genuinely disagree, the spine states the intersection and the disagreement is
recorded verbatim under `x-cldk.divergences` rather than papered over.

Sources for the current v2 files: codeanalyzer-java v3.1.2, codeanalyzer-python
v1.5.1, codeanalyzer-typescript v1.5.3 — all three on analysis schema and graph
contract `2.0.0`.

## Checking

```
python3 scripts/check.py            # every schema, every sample
python3 scripts/check.py v2/json    # one subtree
```

Each schema is checked as a valid JSON Schema, then used to validate the
`*.sample.json` files beside it plus anything its `x-cldk.validates` globs match.
Cross-file `$ref`s resolve against the files in this repo by `$id` — nothing is
fetched over the network.

## Refreshing the v2 samples

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
java -jar build/libs/codeanalyzer-<ver>.jar -i <fixture> -o <out> -a 4   # java
canpy -i <fixture> -o <out> -a 4                                        # python
bun run src/main.ts -i <fixture> -o <out> -a 4                          # typescript
```

Copy the resulting `analysis.json` over the sample it replaces and re-run the
check. A new failure means the analyzer moved and the schema has
not — fix the schema, or the analyzer, on purpose.
