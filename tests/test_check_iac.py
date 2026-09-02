from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

from scripts.check_iac import assert_monotone, check_catalog, check_document, collect_nodes


ROOT = Path(__file__).resolve().parents[1]


OWNERSHIP_PROPERTIES = {
    "neutral": {},
    "shared_facet": {
        "iac_producer": "string",
        "iac_analyzer_version": "string",
        "iac_app_id": "string",
    },
    "owned": {
        "producer": "string",
        "analyzer_version": "string",
        "iac_app_id": "string",
    },
}


# Normative JSON-kind/facet -> Neo4j projection table. Each entry names the
# complete label stack, the label whose property contract is checked, its
# ownership posture, and every JSON field projected onto that label.
EXPECTED_NODE_PROJECTIONS = {
    "application:neutral": {
        "definition": "Application",
        "labels": ["Application"],
        "catalog_label": "Application",
        "ownership": "neutral",
        "fields": {"id": ("id", "string")},
        "omitted": {"kind", "artifacts", "packages", "external_chart_references", "kubernetes_resource_addresses", "diagnostics", "edges"},
    },
    "application:iac": {
        "definition": None,
        "labels": ["Application", "IaCApplication"],
        "catalog_label": "IaCApplication",
        "ownership": "shared_facet",
        "fields": {"$node_id": ("id", "string")},
        "omitted": set(),
    },
    "artifact:neutral": {
        "definition": "Artifact",
        "labels": ["Artifact"],
        "catalog_label": "Artifact",
        "ownership": "neutral",
        "fields": {
            "id": ("id", "string"),
            "path": ("path", "string"),
            "format": ("format", "string"),
            "source": ("source", "string"),
            "sha256": ("sha256", "string"),
            "size_bytes": ("size_bytes", "integer"),
        },
        "omitted": {"kind", "config_keys", "aliases", "iac", "codeanalyzer_iac_config"},
    },
    "artifact:iac": {
        "definition": None,
        "labels": ["Artifact", "IaCArtifact"],
        "catalog_label": "IaCArtifact",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"),
            "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"),
            "status": ("iac_status", "string"),
        },
        "omitted": set(),
    },
    "artifact:helm": {
        "definition": None,
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact"],
        "catalog_label": "HelmArtifact",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"),
            "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"),
            "status": ("iac_status", "string"),
        },
        "omitted": set(),
    },
    "helm_chart": {
        "definition": "HelmChart",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmChart"],
        "catalog_label": "HelmChart",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"),
            "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"),
            "status": ("iac_status", "string"),
            "api_version": ("helm_api_version", "string"),
            "name": ("helm_name", "string"),
            "version": ("helm_version", "string"),
            "kube_version": ("helm_kube_version", "string"),
            "description": ("helm_description", "string"),
            "chart_type": ("helm_chart_type", "string"),
            "keywords": ("helm_keywords", "string[]"),
            "home": ("helm_home", "string"),
            "sources": ("helm_sources", "string[]"),
            "maintainers": ("helm_maintainers_json", "string"),
            "icon": ("helm_icon", "string"),
            "app_version": ("helm_app_version", "string"),
            "deprecated": ("helm_deprecated", "boolean"),
            "annotations": ("helm_annotations_json", "string"),
        },
        "omitted": {"dependencies", "render_profiles", "renders"},
    },
    "helm_requirements": {
        "definition": "HelmRequirements",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmRequirements"],
        "catalog_label": "HelmRequirements",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": {"dependencies"},
    },
    "helm_lock": {
        "definition": "HelmLock",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmLock"],
        "catalog_label": "HelmLock",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": {"dependencies"},
    },
    "helm_values": {
        "definition": "HelmValues",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmValues"],
        "catalog_label": "HelmValues",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": set(),
    },
    "helm_values_schema": {
        "definition": "HelmValuesSchema",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmValuesSchema"],
        "catalog_label": "HelmValuesSchema",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": set(),
    },
    "helm_template": {
        "definition": "HelmTemplate",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmTemplate"],
        "catalog_label": "HelmTemplate",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": {"named_templates", "template_calls", "value_references", "resource_templates", "lookup_references"},
    },
    "helm_crd": {
        "definition": "HelmCRD",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmCRD"],
        "catalog_label": "HelmCRD",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": set(),
    },
    "helm_ignore": {
        "definition": "HelmIgnore",
        "labels": ["Artifact", "IaCArtifact", "HelmArtifact", "HelmIgnore"],
        "catalog_label": "HelmIgnore",
        "ownership": "shared_facet",
        "fields": {
            "$node_id": ("id", "string"), "dialect": ("iac_dialect", "string"),
            "kind": ("iac_kind", "string"), "status": ("iac_status", "string"),
            "roles": ("helm_roles", "string[]"),
        },
        "omitted": set(),
    },
    "config_key:neutral": {
        "definition": "ConfigKey",
        "labels": ["ConfigKey"],
        "catalog_label": "ConfigKey",
        "ownership": "neutral",
        "fields": {
            "id": ("id", "string"), "name": ("name", "string"),
            "path": ("path", "string"), "span": ("span_json", "string"),
        },
        "omitted": {"kind", "iac"},
    },
    "config_key:iac_value": {
        "definition": "HelmValueFacet",
        "labels": ["ConfigKey", "IaCValue"],
        "catalog_label": "IaCValue",
        "ownership": "shared_facet",
        "fields": {"$node_id": ("id", "string"), "kind": ("iac_kind", "string")},
        "omitted": set(),
    },
    "config_key:helm_value": {
        "definition": "HelmValueFacet",
        "labels": ["ConfigKey", "IaCValue", "HelmValue"],
        "catalog_label": "HelmValue",
        "ownership": "shared_facet",
        "fields": {"$node_id": ("id", "string"), "kind": ("iac_kind", "string")},
        "omitted": set(),
    },
    "codeanalyzer_iac_config": {
        "definition": "CodeAnalyzerIaCConfig",
        "labels": ["Artifact", "CodeAnalyzerIaCConfig"],
        "catalog_label": "CodeAnalyzerIaCConfig",
        "ownership": "shared_facet",
        "fields": {"$node_id": ("id", "string"), "config_version": ("iac_config_version", "integer")},
        "omitted": {"kind", "render_profiles"},
    },
    "helm_dependency": {
        "definition": "HelmDependency", "labels": ["HelmDependency"], "catalog_label": "HelmDependency", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "name": ("name", "string"), "version_constraint": ("version_constraint", "string"),
            "alias": ("alias", "string"), "repository": ("repository", "string"), "condition": ("condition", "string"),
            "tags": ("tags", "string[]"), "import_values": ("import_values_json", "string"), "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "helm_chart_reference": {
        "definition": "HelmChartReference", "labels": ["HelmChartReference"], "catalog_label": "HelmChartReference", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "name": ("name", "string"), "version_constraint": ("version_constraint", "string"),
            "repository": ("repository", "string"), "purl": ("purl", "string"), "resolved_chart_id": ("resolved_chart_id", "string"),
        }, "omitted": {"kind"},
    },
    "helm_named_template": {
        "definition": "HelmNamedTemplate", "labels": ["HelmNamedTemplate"], "catalog_label": "HelmNamedTemplate", "ownership": "owned",
        "fields": {"id": ("id", "string"), "name": ("name", "string"), "span": ("span_json", "string")}, "omitted": {"kind"},
    },
    "helm_template_call": {
        "definition": "HelmTemplateCall", "labels": ["HelmTemplateCall"], "catalog_label": "HelmTemplateCall", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "call_kind": ("call_kind", "string"), "name_expression": ("name_expression", "string"),
            "target_id": ("target_id", "string"), "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "helm_value_reference": {
        "definition": "HelmValueReference", "labels": ["HelmValueReference"], "catalog_label": "HelmValueReference", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "path_expression": ("path_expression", "string"),
            "target_id": ("target_id", "string"), "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "helm_resource_template": {
        "definition": "HelmResourceTemplate", "labels": ["HelmResourceTemplate"], "catalog_label": "HelmResourceTemplate", "ownership": "owned",
        "fields": {"id": ("id", "string"), "document_index": ("document_index", "integer"), "span": ("span_json", "string")}, "omitted": {"kind"},
    },
    "helm_lookup_reference": {
        "definition": "HelmLookupReference", "labels": ["HelmLookupReference"], "catalog_label": "HelmLookupReference", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "group_expression": ("group_expression", "string"),
            "version_expression": ("version_expression", "string"), "resource_kind_expression": ("resource_kind_expression", "string"),
            "namespace_expression": ("namespace_expression", "string"), "name_expression": ("name_expression", "string"),
            "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "helm_render_profile": {
        "definition": "HelmRenderProfile", "labels": ["HelmRenderProfile"], "catalog_label": "HelmRenderProfile", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "name": ("name", "string"), "origin": ("origin", "string"), "chart_id": ("chart_id", "string"),
            "release_name": ("release_name", "string"), "namespace": ("namespace", "string"), "api_versions": ("api_versions", "string[]"),
            "kube_version": ("kube_version", "string"),
        }, "omitted": {"kind", "value_layers"},
    },
    "helm_value_layer": {
        "definition": "HelmValueLayer", "labels": ["HelmValueLayer"], "catalog_label": "HelmValueLayer", "ownership": "owned",
        "fields": {"id": ("id", "string"), "ordinal": ("ordinal", "integer"), "source_id": ("source_id", "string")}, "omitted": {"kind"},
    },
    "helm_render": {
        "definition": "HelmRender", "labels": ["HelmRender"], "catalog_label": "HelmRender", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "status": ("status", "string"), "profile_id": ("profile_id", "string"),
            "renderer_name": ("renderer_name", "string"), "renderer_version": ("renderer_version", "string"),
            "value_layer_ids": ("value_layer_ids", "string[]"), "effective_values_sha256": ("effective_values_sha256", "string"),
            "phase": ("phase", "string"),
        }, "omitted": {"kind", "diagnostics", "resources"},
    },
    "diagnostic:iac": {
        "definition": "Diagnostic", "labels": ["IaCDiagnostic"], "catalog_label": "IaCDiagnostic", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "severity": ("severity", "string"), "code": ("code", "string"), "message": ("message", "string"),
            "phase": ("phase", "string"), "artifact_id": ("artifact_id", "string"), "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "diagnostic:helm": {
        "definition": "Diagnostic", "labels": ["IaCDiagnostic", "HelmDiagnostic"], "catalog_label": "HelmDiagnostic", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "severity": ("severity", "string"), "code": ("code", "string"), "message": ("message", "string"),
            "phase": ("phase", "string"), "artifact_id": ("artifact_id", "string"), "span": ("span_json", "string"),
        }, "omitted": {"kind"},
    },
    "kubernetes_resource": {
        "definition": "KubernetesResource", "labels": ["KubernetesResource"], "catalog_label": "KubernetesResource", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "api_version": ("api_version", "string"), "resource_kind": ("resource_kind", "string"),
            "manifest_sha256": ("manifest_sha256", "string"), "render_id": ("render_id", "string"), "origin_ids": ("origin_ids", "string[]"),
            "namespace": ("namespace", "string"), "name": ("name", "string"), "generate_name": ("generate_name", "string"),
            "labels": ("labels_json", "string"), "annotations": ("annotations_json", "string"), "plural": ("plural", "string"),
            "address_id": ("address_id", "string"), "secret_data": ("secret_data_json", "string"),
        }, "omitted": {"kind"},
    },
    "kubernetes_resource_address": {
        "definition": "KubernetesResourceAddress", "labels": ["KubernetesResourceAddress"], "catalog_label": "KubernetesResourceAddress", "ownership": "owned",
        "fields": {
            "id": ("id", "string"), "group": ("group", "string"), "resource_kind": ("resource_kind", "string"),
            "namespace": ("namespace", "string"), "name": ("name", "string"), "plural": ("plural", "string"),
        }, "omitted": {"kind"},
    },
    "identity_alias:neutral": {
        "definition": "IdentityAlias", "labels": ["IdentityAlias"], "catalog_label": "IdentityAlias", "ownership": "owned",
        "fields": {"id": ("id", "string"), "kind": ("iac_kind", "string"), "target": ("target", "string")}, "omitted": set(),
    },
    "identity_alias:iac": {
        "definition": "IdentityAlias", "labels": ["IdentityAlias", "IaCAlias"], "catalog_label": "IaCAlias", "ownership": "owned",
        "fields": {"id": ("id", "string"), "kind": ("iac_kind", "string"), "target": ("target", "string")}, "omitted": set(),
    },
    "package": {
        "definition": "Package", "labels": ["Package"], "catalog_label": "Package", "ownership": "neutral",
        "fields": {"id": ("id", "string"), "purl": ("purl", "string")}, "omitted": {"kind"},
    },
}


class CheckIaCTest(unittest.TestCase):
    def load(self, level: int) -> dict:
        path = ROOT / f"v2/iac/json/analysis.l{level}.sample.json"
        return json.loads(path.read_text())

    def load_schema(self) -> dict:
        path = ROOT / "v2/iac/json/analysis.schema.json"
        return json.loads(path.read_text())

    def load_catalog(self) -> dict:
        path = ROOT / "v2/iac/neo4j/schema.neo4j.sample.json"
        return json.loads(path.read_text())

    def schema_errors(self, document: dict) -> list[str]:
        validator = Draft202012Validator(self.load_schema())
        return [error.message for error in validator.iter_errors(document)]

    def definition_errors(self, definition: str, value: object) -> list[str]:
        schema = self.load_schema()
        validator = Draft202012Validator(
            {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": f"#/$defs/{definition}",
            }
        )
        return [error.message for error in validator.iter_errors(value)]

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
                self.assertEqual([], self.schema_errors(self.load(level)))
                self.assertEqual([], check_document(self.load(level)))
        self.assertEqual([], check_catalog(self.load_catalog()))

    def test_resolved_vendored_chart_uses_canonical_artifact_identity(self):
        document = self.load(2)
        reference = document["application"]["external_chart_references"]["bitnami/postgresql"]
        self.assertEqual(
            "can://artifact/payments/charts/api/charts/postgresql/Chart.yaml",
            reference.get("resolved_chart_id"),
        )
        self.assertEqual([], self.schema_errors(document))

        reference["resolved_chart_id"] = "can://iac/payments/helm/chart/charts/api/charts/postgresql"
        self.assertTrue(self.schema_errors(document))

    def test_canonical_id_definitions_reject_noncanonical_text(self):
        cases = {
            "ApplicationId": (
                "can://iac/payments",
                ["can://iac/payments/extra", "can://iac/pay ments", "can://iac/payments\n"],
            ),
            "ArtifactId": (
                "can://artifact/pay%20ments/charts/api/Chart.yaml",
                [
                    "can://artifact/payments/charts//Chart.yaml",
                    "can://artifact/payments/charts/%ZZ.yaml",
                    "can://artifact/payments/charts/api?x/Chart.yaml",
                    "can://artifact/payments/charts/api/Chart.yaml\r",
                ],
            ),
            "ConfigKeyId": (
                "can://artifact/payments/charts/api/values.yaml@key/image.tag",
                [
                    "can://artifact/payments/charts/api/values.yaml@key/",
                    "can://artifact/payments/charts/api/values.yaml@key/image tag",
                    "can://artifact/payments/charts/api/values.yaml@key/image/%GG",
                ],
            ),
            "SemanticId": (
                "can://iac/payments/helm/templates/deployment.yaml/template-call@6:11",
                [
                    "can://iac/payments/helm//template-call",
                    "can://iac/payments/helm/bad name",
                    "can://iac/payments/helm/%XX",
                    "can://iac/payments/helm/template-call@6:11\n",
                ],
            ),
        }
        for definition, (valid, invalid_values) in cases.items():
            self.assertIn(definition, self.load_schema()["$defs"])
            with self.subTest(definition=definition, value=valid):
                self.assertEqual([], self.definition_errors(definition, valid))
            for invalid in invalid_values:
                with self.subTest(definition=definition, value=invalid):
                    self.assertTrue(self.definition_errors(definition, invalid))

    def test_reference_fields_use_complete_canonical_id_definitions(self):
        schema = self.load_schema()["$defs"]
        direct_refs = {
            ("Artifact", "id"): "ArtifactId",
            ("ConfigKey", "id"): "ConfigKeyId",
            ("IdentityAlias", "id"): "SemanticId",
            ("IdentityAlias", "target"): "AliasTargetId",
            ("Diagnostic", "id"): "SemanticId",
            ("Diagnostic", "artifact_id"): "ArtifactId",
            ("Package", "id"): "Purl",
            ("Package", "purl"): "Purl",
            ("Edge", "src"): "NodeId",
            ("Edge", "dst"): "NodeId",
            ("HelmDependency", "id"): "SemanticId",
            ("HelmNamedTemplate", "id"): "SemanticId",
            ("HelmTemplateCall", "id"): "SemanticId",
            ("HelmTemplateCall", "target_id"): "SemanticId",
            ("HelmValueReference", "id"): "SemanticId",
            ("HelmValueReference", "target_id"): "ConfigKeyId",
            ("HelmResourceTemplate", "id"): "SemanticId",
            ("HelmLookupReference", "id"): "SemanticId",
            ("HelmChartReference", "id"): "SemanticId",
            ("HelmChartReference", "purl"): "Purl",
            ("HelmChartReference", "resolved_chart_id"): "ArtifactId",
            ("HelmRenderProfile", "id"): "SemanticId",
            ("HelmRenderProfile", "chart_id"): "ArtifactId",
            ("HelmValueLayer", "id"): "SemanticId",
            ("HelmValueLayer", "source_id"): "ValueSourceId",
            ("HelmRender", "id"): "SemanticId",
            ("HelmRender", "profile_id"): "SemanticId",
            ("KubernetesResource", "id"): "SemanticId",
            ("KubernetesResource", "render_id"): "SemanticId",
            ("KubernetesResource", "address_id"): "SemanticId",
            ("KubernetesResourceAddress", "id"): "SemanticId",
        }
        for (definition, field), target in direct_refs.items():
            with self.subTest(definition=definition, field=field):
                self.assertEqual(
                    {"$ref": f"#/$defs/{target}"},
                    schema[definition]["properties"][field],
                )

        array_refs = {
            ("HelmRender", "value_layer_ids"): "SemanticId",
            ("KubernetesResource", "origin_ids"): "OriginId",
        }
        for (definition, field), target in array_refs.items():
            with self.subTest(definition=definition, field=field):
                self.assertEqual(
                    {"$ref": f"#/$defs/{target}"},
                    schema[definition]["properties"][field]["items"],
                )

    def test_purl_contract_supports_only_registered_oci_type(self):
        self.assertIn("Purl", self.load_schema()["$defs"])
        self.assertEqual([], self.definition_errors("Purl", "pkg:oci/postgresql@sha256%3Aabcd"))
        for invalid in ("pkg:helm/postgresql@12.1.0", "pkg:generic/postgresql@12.1.0", "pkg:npm/postgresql"):
            with self.subTest(invalid=invalid):
                self.assertTrue(self.definition_errors("Purl", invalid))

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

    def test_rejects_edge_family_endpoint_type_violation(self):
        doc = self.load(2)
        edge = doc["application"]["edges"]["iac_calls_template"][
            "charts/api/templates/deployment.yaml@6:11"
        ]
        edge["dst"] = "can://artifact/payments/README.md"
        self.assertIn("edge endpoint type violation", "\n".join(check_document(doc)))

    def test_requires_scalar_reference_edge_counterparts(self):
        doc = self.load(3)
        chart = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]
        chart["renders"]["default"]["profile_id"] = chart["render_profiles"]["default"]["id"]
        doc["application"]["edges"]["iac_configured_by"].pop("default")
        self.assertIn(
            "profile_id must have exactly one matching iac_configured_by edge",
            "\n".join(check_document(doc)),
        )

    def test_requires_dependency_target_edge_counterpart(self):
        doc = self.load(2)
        chart = doc["application"]["artifacts"]["charts/api/Chart.yaml"]
        dependency_id = "can://iac/payments/helm/charts/api/dependency/postgresql"
        chart["iac"]["dependencies"]["postgresql"] = {
            "id": dependency_id,
            "kind": "helm_dependency",
            "name": "postgresql",
            "version_constraint": "12.1.0",
            "span": {"start": [1, 1], "end": [1, 2], "bytes": [0, 1]},
        }
        doc["application"]["edges"].setdefault("iac_declares_dependency", {})[
            "charts/api/Chart.yaml:postgresql"
        ] = {"src": chart["id"], "dst": dependency_id}

        self.assertEqual([], self.schema_errors(doc))
        self.assertIn(
            "dependency must have exactly one iac_targets_chart_reference edge",
            "\n".join(check_document(doc)),
        )

    def test_rejects_diagnostic_artifact_reference_to_non_artifact(self):
        doc = self.load(3)
        diagnostic = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]["renders"]["explicit"]["diagnostics"]["render-failed"]
        diagnostic["artifact_id"] = "can://iac/payments/helm/render-profile/config/explicit"
        self.assertIn("artifact_id must target an Artifact", "\n".join(check_document(doc)))

    def test_rejects_resource_outside_its_containing_render(self):
        doc = self.load(3)
        chart = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]
        resource = chart["renders"]["default"]["resources"]["apps/Deployment/default/api"]
        resource["render_id"] = chart["renders"]["explicit"]["id"]
        self.assertIn("resource render_id differs from containing render", "\n".join(check_document(doc)))

    def test_rejects_resource_produced_by_multiple_renders(self):
        doc = self.load(3)
        chart = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]
        resource = chart["renders"]["default"]["resources"]["apps/Deployment/default/api"]
        doc["application"]["edges"]["iac_produces"]["explicit@deployment"] = {
            "src": chart["renders"]["explicit"]["id"],
            "dst": resource["id"],
        }
        self.assertIn(
            "resource must have exactly one containing iac_produces edge",
            "\n".join(check_document(doc)),
        )

    def test_requires_address_and_origin_targets_and_edges(self):
        doc = self.load(3)
        resource = doc["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]["renders"]["default"]["resources"]["apps/Deployment/default/api"]
        resource["address_id"] = "can://iac/payments/kubernetes/address/core/Secret/default/api-credentials"
        resource["origin_ids"] = ["can://artifact/payments/charts/api/values.yaml"]
        errors = "\n".join(check_document(doc))
        self.assertIn("address_id must have exactly one matching iac_targets_resource edge", errors)
        self.assertIn("origin_id must target a HelmResourceTemplate", errors)

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
        artifact["size_bytes"] = 0
        self.assertNotIn("sha256 does not match source", "\n".join(check_document(doc)))

    def test_rejects_empty_source_with_semantic_enrichment(self):
        doc = self.load(1)
        artifact = doc["application"]["artifacts"]["charts/api/Chart.yaml"]
        artifact["source"] = ""
        artifact["size_bytes"] = 0
        self.assertIn("empty-source artifact must remain raw", "\n".join(check_document(doc)))

    def test_rejects_size_bytes_different_from_utf8_source_length(self):
        doc = self.load(1)
        artifact = doc["application"]["artifacts"]["README.md"]
        artifact["source"] = "café\n"
        artifact["sha256"] = "7b49b9e063bd91a4f9252b413261f5557b9c570aa61516989499f64a62dbcdd6"
        artifact["size_bytes"] = len(artifact["source"])
        self.assertIn("size_bytes does not match UTF-8 source length", "\n".join(check_document(doc)))

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
        profile = doc["application"]["artifacts"]["codeanalyzer-iac.yaml"]["codeanalyzer_iac_config"]["render_profiles"]["explicit"]
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

    def test_rejects_unsupported_purl_type_even_when_id_equals_purl(self):
        doc = self.load(2)
        doc["application"]["packages"]["postgresql"] = {
            "id": "pkg:helm/postgresql@12.1.0",
            "kind": "package",
            "purl": "pkg:helm/postgresql@12.1.0",
        }
        self.assertIn("unsupported package URL type", "\n".join(check_document(doc)))

    def test_rejects_resolution_facts_below_level_two(self):
        doc = self.load(2)
        doc["max_level"] = 1
        errors = "\n".join(check_document(doc))
        self.assertIn("fact requires max_level 2: helm_chart_reference", errors)
        self.assertIn("fact requires max_level 2: target_id", errors)
        self.assertIn("edge requires max_level 2: iac_calls_template", errors)

    def test_rejects_evaluation_facts_below_level_three(self):
        doc = self.load(3)
        doc["max_level"] = 2
        errors = "\n".join(check_document(doc))
        for fact in (
            "codeanalyzer_iac_config",
            "helm_render_profile",
            "helm_value_layer",
            "helm_render",
            "kubernetes_resource",
            "kubernetes_resource_address",
        ):
            with self.subTest(fact=fact):
                self.assertIn(f"fact requires max_level 3: {fact}", errors)

    def test_render_status_requires_truthful_phase_shape(self):
        document = self.load(3)
        chart = document["application"]["artifacts"]["charts/api/Chart.yaml"]["iac"]
        failed = chart["renders"]["explicit"]
        self.assertEqual("template", failed.get("phase"))
        self.assertTrue(failed.get("diagnostics"))
        self.assertEqual([], self.schema_errors(document))

        failed.pop("phase", None)
        self.assertTrue(self.schema_errors(document))

        succeeded = chart["renders"]["default"]
        succeeded["phase"] = "template"
        self.assertTrue(self.schema_errors(document))

    def test_profiles_keep_configuration_layers_out_of_default_render(self):
        doc = self.load(3)
        artifacts = doc["application"]["artifacts"]
        chart = artifacts["charts/api/Chart.yaml"]["iac"]
        config = artifacts["codeanalyzer-iac.yaml"]
        default_profile = chart["render_profiles"]["default"]
        explicit_profile = config["codeanalyzer_iac_config"]["render_profiles"]["explicit"]

        self.assertEqual(
            ["can://artifact/payments/charts/api/values.yaml"],
            [layer["source_id"] for layer in default_profile["value_layers"].values()],
        )
        explicit_sources = [layer["source_id"] for layer in explicit_profile["value_layers"].values()]
        self.assertEqual("can://artifact/payments/charts/api/values.yaml", explicit_sources[0])
        self.assertIn(explicit_sources[1], {key["id"] for key in config["config_keys"].values()})

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

    def test_monotonicity_allows_absent_target_id_to_be_added(self):
        lower = {"max_level": 1, "reference": {}}
        higher = {"max_level": 2, "reference": {"target_id": "can://iac/payments/target"}}
        self.assertEqual([], assert_monotone(lower, higher))

    def test_monotonicity_rejects_present_null_target_id_replacement(self):
        lower = {"max_level": 1, "reference": {"target_id": None}}
        higher = {"max_level": 2, "reference": {"target_id": "can://iac/payments/target"}}
        self.assertEqual(
            ["value changed at reference/target_id"],
            assert_monotone(lower, higher),
        )

    def test_monotonicity_rejects_changed_target_id(self):
        lower = {"max_level": 1, "reference": {"target_id": "can://iac/payments/one"}}
        higher = {"max_level": 2, "reference": {"target_id": "can://iac/payments/two"}}
        self.assertEqual(
            ["value changed at reference/target_id"],
            assert_monotone(lower, higher),
        )

    def test_catalog_relationships_are_identity_only(self):
        catalog = self.load_catalog()
        catalog["relationship_types"][0]["properties"]["ordinal"] = "integer"
        self.assertIn("relationship properties must be empty", "\n".join(check_catalog(catalog)))

    def test_catalog_exactly_matches_node_projection_table(self):
        catalog = self.load_catalog()
        actual = {entry["label"]: entry for entry in catalog["node_labels"]}
        self.assertEqual(
            {entry["catalog_label"] for entry in EXPECTED_NODE_PROJECTIONS.values()},
            set(actual),
        )
        for projection_name, projection in EXPECTED_NODE_PROJECTIONS.items():
            expected_properties = {
                graph_name: graph_type
                for graph_name, graph_type in projection["fields"].values()
            }
            expected_properties.update(OWNERSHIP_PROPERTIES[projection["ownership"]])
            entry = actual[projection["catalog_label"]]
            with self.subTest(projection=projection_name):
                self.assertEqual("id", entry["key"])
                self.assertEqual(expected_properties, entry["properties"])

    def test_projection_table_covers_each_json_node_property(self):
        definitions = self.load_schema()["$defs"]
        for projection_name, projection in EXPECTED_NODE_PROJECTIONS.items():
            definition_name = projection["definition"]
            if definition_name is None:
                continue
            json_fields = {name for name in projection["fields"] if not name.startswith("$")}
            expected_fields = json_fields | projection["omitted"]
            with self.subTest(projection=projection_name):
                self.assertEqual(
                    expected_fields,
                    set(definitions[definition_name]["properties"]),
                )

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
