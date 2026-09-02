from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.check_iac import assert_monotone, check_catalog, check_document, collect_nodes


ROOT = Path(__file__).resolve().parents[1]


class CheckIaCTest(unittest.TestCase):
    def load(self, level: int) -> dict:
        path = ROOT / f"v2/iac/json/analysis.l{level}.sample.json"
        return json.loads(path.read_text())

    def load_catalog(self) -> dict:
        path = ROOT / "v2/iac/neo4j/schema.neo4j.sample.json"
        return json.loads(path.read_text())

    def run_checker_copy(self, mutate=None, selector="v2/iac") -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            shutil.copytree(ROOT / "scripts", checkout / "scripts")
            shutil.copytree(ROOT / "v1", checkout / "v1")
            shutil.copytree(ROOT / "v2" / "iac", checkout / "v2" / "iac")
            if mutate is not None:
                mutate(checkout)
            return subprocess.run(
                [sys.executable, "scripts/check.py", selector],
                cwd=checkout,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_fixtures_satisfy_semantic_contract(self):
        for level in (1, 2, 3):
            with self.subTest(level=level):
                self.assertEqual([], check_document(self.load(level)))
        self.assertEqual([], check_catalog(self.load_catalog()))

    def test_repository_checker_rejects_semantically_invalid_iac_fixture(self):
        def corrupt_digest(checkout: Path) -> None:
            path = checkout / "v2/iac/json/analysis.l1.sample.json"
            document = json.loads(path.read_text())
            document["application"]["artifacts"]["README.md"]["source"] += "changed"
            path.write_text(json.dumps(document))

        result = self.run_checker_copy(corrupt_digest)
        self.assertEqual(1, result.returncode)
        self.assertIn("sha256 does not match source", result.stdout)

    def test_v1_selector_does_not_run_iac_semantic_checks(self):
        def corrupt_digest(checkout: Path) -> None:
            path = checkout / "v2/iac/json/analysis.l1.sample.json"
            document = json.loads(path.read_text())
            document["application"]["artifacts"]["README.md"]["source"] += "changed"
            path.write_text(json.dumps(document))

        result = self.run_checker_copy(corrupt_digest, "v1/json/java")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("sha256 does not match source", result.stdout)

    def test_collects_nodes_recursively(self):
        nodes = collect_nodes(self.load(3)["application"])
        self.assertIn("can://iac/payments", nodes)
        self.assertIn(
            "can://iac/payments/helm/render/charts/api/default/kubernetes/core/Secret/default/api-credentials",
            nodes,
        )

    def test_rejects_duplicate_ids_across_named_collections(self):
        doc = self.load(2)
        duplicate = doc["application"]["external_chart_references"]["bitnami/postgresql"]
        duplicate["id"] = doc["application"]["artifacts"]["README.md"]["id"]
        self.assertIn("duplicate node id", "\n".join(check_document(doc)))

    def test_rejects_dangling_edge(self):
        doc = self.load(2)
        doc["application"]["edges"]["iac_references_value"]["bad"] = {
            "src": "can://iac/payments/missing",
            "dst": "can://artifact/payments/charts/api/values.yaml@key/image.tag",
        }
        self.assertIn("dangling edge source", "\n".join(check_document(doc)))

    def test_returns_violations_in_sorted_order(self):
        doc = self.load(2)
        edges = doc["application"]["edges"]["iac_references_value"]
        edges["z"] = {"src": "can://z", "dst": "can://artifact/payments/README.md"}
        edges["a"] = {"src": "can://a", "dst": "can://artifact/payments/README.md"}
        errors = check_document(doc)
        self.assertEqual(sorted(errors), errors)

    def test_rejects_alias_chain(self):
        doc = self.load(1)
        alias = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["aliases"][0]
        alias["target"] = alias["id"]
        self.assertIn("alias target is not canonical", "\n".join(check_document(doc)))

    def test_rejects_alias_targeting_another_alias(self):
        doc = self.load(1)
        aliases = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["aliases"]
        aliases.append(
            {
                "id": "can://iac/payments/helm/chart/second",
                "kind": "helm_chart",
                "target": aliases[0]["id"],
            }
        )
        self.assertIn("alias target is not canonical", "\n".join(check_document(doc)))

    def test_requires_exactly_one_matching_alias_edge(self):
        doc = self.load(1)
        doc["application"]["edges"]["iac_alias_of"].clear()
        self.assertIn("alias must have exactly one matching iac_alias_of edge", "\n".join(check_document(doc)))

    def test_rejects_duplicate_matching_alias_edges(self):
        doc = self.load(1)
        edges = doc["application"]["edges"]["iac_alias_of"]
        edges["duplicate"] = deepcopy(next(iter(edges.values())))
        self.assertIn("alias must have exactly one matching iac_alias_of edge", "\n".join(check_document(doc)))

    def test_rejects_bad_source_digest(self):
        doc = self.load(1)
        doc["application"]["artifacts"]["README.md"]["source"] += "changed"
        self.assertIn("sha256 does not match source", "\n".join(check_document(doc)))

    def test_empty_artifact_source_is_digest_ineligible(self):
        doc = self.load(1)
        artifact = doc["application"]["artifacts"]["README.md"]
        artifact["source"] = ""
        self.assertNotIn("sha256 does not match source", "\n".join(check_document(doc)))

    def test_rejects_absolute_artifact_path(self):
        doc = self.load(1)
        doc["application"]["artifacts"]["README.md"]["path"] = "/README.md"
        self.assertIn("artifact path is not relative", "\n".join(check_document(doc)))

    def test_rejects_artifact_path_dot_segment(self):
        doc = self.load(1)
        doc["application"]["artifacts"]["README.md"]["path"] = "./README.md"
        self.assertIn("artifact path is not relative", "\n".join(check_document(doc)))

    def test_rejects_span_outside_artifact_source(self):
        doc = self.load(1)
        span = doc["application"]["artifacts"]["charts/api/values.yaml"]["config_keys"]["image.tag"]["span"]
        span["bytes"] = [9, 10_000]
        self.assertIn("span bytes out of bounds", "\n".join(check_document(doc)))

    def test_rejects_non_contiguous_profile_layer_ordinals(self):
        doc = self.load(3)
        profile = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]["render_profiles"]["default"]
        profile["value_layers"]["0001"]["ordinal"] = 3
        self.assertIn("profile layer ordinals must be contiguous from zero", "\n".join(check_document(doc)))

    def test_rejects_package_id_different_from_purl(self):
        doc = self.load(3)
        doc["application"]["packages"]["postgresql"] = {
            "id": "can://package/postgresql",
            "kind": "package",
            "purl": "pkg:helm/postgresql@12.1.0",
        }
        self.assertIn("package id must equal purl", "\n".join(check_document(doc)))

    def test_rejects_plaintext_secret_amplification(self):
        doc = self.load(3)
        resources = next(
            iter(doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]["renders"].values())
        )["resources"]
        secret = next(value for value in resources.values() if value["resource_kind"] == "Secret")
        secret["secret_data"]["password"]["value"] = "hunter2"
        self.assertIn("Secret data must contain only key and sha256", "\n".join(check_document(doc)))

    def test_monotonic_fixtures_only_add_information(self):
        self.assertEqual([], assert_monotone(self.load(1), self.load(2)))
        self.assertEqual([], assert_monotone(self.load(2), self.load(3)))

    def test_monotonicity_rejects_changed_lower_level_value(self):
        lower = self.load(1)
        higher = deepcopy(self.load(2))
        higher["application"]["artifacts"]["README.md"]["path"] = "renamed.md"
        self.assertIn("value changed at application/artifacts/README.md/path", assert_monotone(lower, higher))

    def test_catalog_relationships_are_identity_only(self):
        catalog = self.load_catalog()
        catalog["relationship_types"][0]["properties"]["ordinal"] = "integer"
        self.assertIn("relationship properties must be empty", "\n".join(check_catalog(catalog)))

    def test_catalog_rejects_duplicate_labels_and_types(self):
        catalog = self.load_catalog()
        catalog["node_labels"].append(deepcopy(catalog["node_labels"][0]))
        catalog["relationship_types"].append(deepcopy(catalog["relationship_types"][0]))
        errors = "\n".join(check_catalog(catalog))
        self.assertIn("duplicate node label", errors)
        self.assertIn("duplicate relationship type", errors)

    def test_catalog_rejects_unknown_endpoint_labels(self):
        catalog = self.load_catalog()
        catalog["relationship_types"][0]["from"].append("MissingLabel")
        self.assertIn("unknown relationship endpoint label", "\n".join(check_catalog(catalog)))

    def test_catalog_rejects_non_allowlisted_neutral_relationship(self):
        catalog = self.load_catalog()
        catalog["relationship_types"][2]["type"] = "PART_OF_CHART"
        self.assertIn("relationship type must be IAC_* or neutral allowlisted", "\n".join(check_catalog(catalog)))

    def test_catalog_rejects_constraint_and_index_for_unknown_label(self):
        catalog = self.load_catalog()
        catalog["constraints"].append(
            "CREATE CONSTRAINT missing_id IF NOT EXISTS FOR (n:MissingLabel) REQUIRE n.id IS UNIQUE"
        )
        catalog["indexes"].append("CREATE INDEX missing_name IF NOT EXISTS FOR (n:AlsoMissing) ON (n.name)")
        errors = "\n".join(check_catalog(catalog))
        self.assertIn("constraint mentions unknown label", errors)
        self.assertIn("index mentions unknown label", errors)


if __name__ == "__main__":
    unittest.main()
