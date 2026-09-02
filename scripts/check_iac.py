#!/usr/bin/env python3
"""Semantic conformance checks for the schema-v2 IaC contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


NEUTRAL_RELATIONSHIP_TYPES = {"DEFINES_CONFIG", "HAS_ARTIFACT"}
SUPPORTED_PURL_PREFIX = "pkg:oci/"
_LABEL_REFERENCE = re.compile(r":\s*`?([A-Za-z][A-Za-z0-9_]*)`?")
_CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "v2"
    / "iac"
    / "neo4j"
    / "schema.neo4j.sample.json"
)

_FACET_LABELS = {
    "helm_chart": "HelmChart",
    "helm_requirements": "HelmRequirements",
    "helm_lock": "HelmLock",
    "helm_values": "HelmValues",
    "helm_values_schema": "HelmValuesSchema",
    "helm_template": "HelmTemplate",
    "helm_crd": "HelmCRD",
    "helm_ignore": "HelmIgnore",
}
_KIND_LABELS = {
    "helm_dependency": {"HelmDependency"},
    "helm_chart_reference": {"HelmChartReference"},
    "helm_named_template": {"HelmNamedTemplate"},
    "helm_template_call": {"HelmTemplateCall"},
    "helm_value_reference": {"HelmValueReference"},
    "helm_resource_template": {"HelmResourceTemplate"},
    "helm_lookup_reference": {"HelmLookupReference"},
    "helm_render_profile": {"HelmRenderProfile"},
    "helm_value_layer": {"HelmValueLayer"},
    "helm_render": {"HelmRender"},
    "diagnostic": {"IaCDiagnostic", "HelmDiagnostic"},
    "kubernetes_resource": {"KubernetesResource"},
    "kubernetes_resource_address": {"KubernetesResourceAddress"},
    "package": {"Package"},
}
_L2_KINDS = {"helm_chart_reference", "package"}
_L3_KINDS = {
    "helm_render_profile",
    "helm_value_layer",
    "helm_render",
    "kubernetes_resource",
    "kubernetes_resource_address",
}
_L2_EDGES = {
    "iac_part_of_chart",
    "iac_targets_chart_reference",
    "iac_resolves_to_chart",
    "iac_identified_by_package",
    "iac_calls_template",
    "iac_references_value",
}
_L3_EDGES = {
    "iac_declares_profile",
    "iac_renders_chart",
    "iac_has_value_layer",
    "iac_reads_from",
    "iac_has_render",
    "iac_configured_by",
    "iac_produces",
    "iac_targets_resource",
    "iac_derived_from",
}


def _walk(value: object):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _node_items(application: dict):
    for value in _walk(application):
        if not isinstance(value, dict):
            continue
        node_id = value.get("id")
        kind = value.get("kind")
        if isinstance(node_id, str) and isinstance(kind, str):
            yield node_id, value


def collect_nodes(application: dict) -> dict[str, dict]:
    """Collect all recursively nested nodes and reject every duplicate ID."""
    nodes: dict[str, dict] = {}
    duplicate_ids: set[str] = set()
    for node_id, node in _node_items(application):
        if node_id in nodes:
            duplicate_ids.add(node_id)
        else:
            nodes[node_id] = node
    if duplicate_ids:
        raise ValueError(
            "\n".join(f"duplicate node id: {node_id}" for node_id in sorted(duplicate_ids))
        )
    return nodes


def _aliases(application: dict):
    for value in _walk(application):
        if not isinstance(value, dict):
            continue
        aliases = value.get("aliases")
        if isinstance(aliases, list):
            yield from (alias for alias in aliases if isinstance(alias, dict))


def _edges(application: dict):
    edge_groups = application.get("edges", {})
    if not isinstance(edge_groups, dict):
        return
    for edge_type, edge_map in edge_groups.items():
        if not isinstance(edge_map, dict):
            continue
        for edge_name, edge in edge_map.items():
            if isinstance(edge, dict):
                yield edge_type, edge_name, edge


def _path_is_relative(path: str) -> bool:
    parsed = PurePosixPath(path)
    return (
        bool(path)
        and not parsed.is_absolute()
        and "\\" not in path
        and all(part not in {".", ".."} for part in path.split("/"))
    )


def _check_artifact(artifact: dict, errors: list[str]) -> None:
    artifact_id = artifact.get("id", "<unknown>")
    path = artifact.get("path")
    if isinstance(path, str) and not _path_is_relative(path):
        errors.append(f"artifact path is not relative: {artifact_id}: {path}")

    source = artifact.get("source")
    if not isinstance(source, str):
        return
    source_bytes = source.encode("utf-8")
    if artifact.get("size_bytes") != len(source_bytes):
        errors.append(f"artifact size_bytes does not match UTF-8 source length: {artifact_id}")
    if not source and any(
        (
            artifact.get("iac") is not None,
            artifact.get("codeanalyzer_iac_config") is not None,
            bool(artifact.get("config_keys")),
            bool(artifact.get("aliases")),
        )
    ):
        errors.append(f"empty-source artifact must remain raw: {artifact_id}")
    if source:
        digest = hashlib.sha256(source_bytes).hexdigest()
        if artifact.get("sha256") != digest:
            errors.append(f"artifact sha256 does not match source: {artifact_id}")

    for value in _walk(artifact):
        if not isinstance(value, dict) or not isinstance(value.get("span"), dict):
            continue
        byte_range = value["span"].get("bytes")
        if (
            not isinstance(byte_range, list)
            or len(byte_range) != 2
            or not all(isinstance(offset, int) for offset in byte_range)
            or byte_range[0] < 0
            or byte_range[0] > byte_range[1]
            or byte_range[1] > len(source_bytes)
        ):
            node_id = value.get("id", "<unknown>")
            errors.append(f"span bytes out of bounds: {node_id} in {artifact_id}")


def _projected_labels(node_id: str, node: dict, alias_ids: set[object]) -> set[str]:
    if node_id in alias_ids:
        return {"IdentityAlias", "IaCAlias"}
    kind = node.get("kind")
    if kind == "application":
        return {"Application", "IaCApplication"}
    if kind == "artifact":
        labels = {"Artifact"}
        facet = node.get("iac")
        if isinstance(facet, dict):
            labels.update({"IaCArtifact", "HelmArtifact"})
            label = _FACET_LABELS.get(facet.get("kind"))
            if label:
                labels.add(label)
        if isinstance(node.get("codeanalyzer_iac_config"), dict):
            labels.add("CodeAnalyzerIaCConfig")
        return labels
    if kind == "config_key":
        labels = {"ConfigKey"}
        facet = node.get("iac")
        if isinstance(facet, dict) and facet.get("kind") == "helm_value":
            labels.update({"IaCValue", "HelmValue"})
        return labels
    return set(_KIND_LABELS.get(kind, ()))


def _relationship_contract() -> dict[str, dict]:
    catalog = json.loads(_CATALOG_PATH.read_text())
    return {
        relationship["type"].lower(): relationship
        for relationship in catalog.get("relationship_types", [])
        if isinstance(relationship, dict) and isinstance(relationship.get("type"), str)
    }


def _edge_count(edge_rows: list[tuple[str, str, dict]], edge_type: str, src: object, dst: object) -> int:
    return sum(
        candidate_type == edge_type
        and edge.get("src") == src
        and edge.get("dst") == dst
        for candidate_type, _, edge in edge_rows
    )


def _require_edge(
    edge_rows: list[tuple[str, str, dict]],
    edge_type: str,
    src: object,
    dst: object,
    description: str,
    errors: list[str],
) -> None:
    count = _edge_count(edge_rows, edge_type, src, dst)
    if count != 1:
        errors.append(f"{description} must have exactly one matching {edge_type} edge: {src}: {dst}: found {count}")


def _check_level(document: dict, application: dict, errors: list[str]) -> None:
    max_level = document.get("max_level")
    if not isinstance(max_level, int):
        return

    if max_level < 2:
        for _, node in _node_items(application):
            kind = node.get("kind")
            if kind in _L2_KINDS:
                errors.append(f"fact requires max_level 2: {kind}")
            if "target_id" in node:
                errors.append("fact requires max_level 2: target_id")
            if kind == "helm_chart_reference" and any(
                field in node for field in ("purl", "resolved_chart_id")
            ):
                errors.append("fact requires max_level 2: helm_chart_reference resolution")
        for edge_type, _, _ in _edges(application):
            if edge_type in _L2_EDGES:
                errors.append(f"edge requires max_level 2: {edge_type}")

    if max_level < 3:
        for _, node in _node_items(application):
            kind = node.get("kind")
            if kind in _L3_KINDS:
                errors.append(f"fact requires max_level 3: {kind}")
        for artifact in application.get("artifacts", {}).values():
            if isinstance(artifact, dict) and "codeanalyzer_iac_config" in artifact:
                errors.append("fact requires max_level 3: codeanalyzer_iac_config")
        for edge_type, _, _ in _edges(application):
            if edge_type in _L3_EDGES:
                errors.append(f"edge requires max_level 3: {edge_type}")


def _check_scalar_references(
    nodes: dict[str, dict],
    alias_ids: set[object],
    edge_rows: list[tuple[str, str, dict]],
    errors: list[str],
) -> None:
    def has_label(node_id: object, label: str) -> bool:
        node = nodes.get(node_id)
        return isinstance(node, dict) and label in _projected_labels(str(node_id), node, alias_ids)

    for node_id, node in nodes.items():
        kind = node.get("kind")
        if kind == "helm_template_call" and "target_id" in node:
            target = node.get("target_id")
            if not has_label(target, "HelmNamedTemplate"):
                errors.append(f"template target_id must target a HelmNamedTemplate: {node_id}: {target}")
            _require_edge(edge_rows, "iac_calls_template", node_id, target, "target_id", errors)
        elif kind == "helm_value_reference" and "target_id" in node:
            target = node.get("target_id")
            if not has_label(target, "HelmValue"):
                errors.append(f"value target_id must target a HelmValue: {node_id}: {target}")
            _require_edge(edge_rows, "iac_references_value", node_id, target, "target_id", errors)
        elif kind == "helm_chart_reference":
            target = node.get("resolved_chart_id")
            if target is not None:
                if not has_label(target, "HelmChart"):
                    errors.append(f"resolved_chart_id must target a HelmChart Artifact: {node_id}: {target}")
                _require_edge(edge_rows, "iac_resolves_to_chart", node_id, target, "resolved_chart_id", errors)
            purl = node.get("purl")
            if purl is not None:
                if not has_label(purl, "Package"):
                    errors.append(f"purl must target a Package: {node_id}: {purl}")
                _require_edge(edge_rows, "iac_identified_by_package", node_id, purl, "purl", errors)
        elif kind == "helm_render_profile":
            chart_id = node.get("chart_id")
            if not has_label(chart_id, "HelmChart"):
                errors.append(f"chart_id must target a HelmChart Artifact: {node_id}: {chart_id}")
            _require_edge(edge_rows, "iac_renders_chart", node_id, chart_id, "chart_id", errors)
            layers = node.get("value_layers", {})
            if isinstance(layers, dict):
                for layer in layers.values():
                    if not isinstance(layer, dict):
                        continue
                    layer_id = layer.get("id")
                    source_id = layer.get("source_id")
                    _require_edge(edge_rows, "iac_has_value_layer", node_id, layer_id, "value layer", errors)
                    if not (has_label(source_id, "Artifact") or has_label(source_id, "ConfigKey")):
                        errors.append(f"source_id must target an Artifact or ConfigKey: {layer_id}: {source_id}")
                    _require_edge(edge_rows, "iac_reads_from", layer_id, source_id, "source_id", errors)
        elif kind == "helm_render":
            profile_id = node.get("profile_id")
            if not has_label(profile_id, "HelmRenderProfile"):
                errors.append(f"profile_id must target a HelmRenderProfile: {node_id}: {profile_id}")
            _require_edge(edge_rows, "iac_configured_by", node_id, profile_id, "profile_id", errors)
            profile = nodes.get(profile_id)
            if isinstance(profile, dict):
                layers = profile.get("value_layers", {})
                if isinstance(layers, dict):
                    expected = [
                        layer.get("id")
                        for layer in sorted(
                            (value for value in layers.values() if isinstance(value, dict)),
                            key=lambda value: value.get("ordinal", -1),
                        )
                    ]
                    if node.get("value_layer_ids") != expected:
                        errors.append(f"render value_layer_ids do not match profile layers: {node_id}")
        elif kind == "diagnostic" and "artifact_id" in node:
            artifact_id = node.get("artifact_id")
            if not has_label(artifact_id, "Artifact"):
                errors.append(f"artifact_id must target an Artifact: {node_id}: {artifact_id}")
        elif kind == "kubernetes_resource":
            address_id = node.get("address_id")
            if address_id is not None:
                if not has_label(address_id, "KubernetesResourceAddress"):
                    errors.append(f"address_id must target a KubernetesResourceAddress: {node_id}: {address_id}")
                _require_edge(edge_rows, "iac_targets_resource", node_id, address_id, "address_id", errors)
            for origin_id in node.get("origin_ids", []):
                if not has_label(origin_id, "HelmResourceTemplate"):
                    errors.append(f"origin_id must target a HelmResourceTemplate: {node_id}: {origin_id}")
                _require_edge(edge_rows, "iac_derived_from", node_id, origin_id, "origin_id", errors)


def _check_containment(
    application: dict,
    edge_rows: list[tuple[str, str, dict]],
    max_level: object,
    errors: list[str],
) -> None:
    app_id = application.get("id")
    artifacts = application.get("artifacts", {})
    if not isinstance(artifacts, dict):
        return

    chart_artifacts: list[tuple[str, str]] = []
    for path, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            continue
        facet = artifact.get("iac")
        if isinstance(facet, dict) and facet.get("kind") == "helm_chart":
            chart_artifacts.append((str(PurePosixPath(path).parent), artifact.get("id")))

    for path, artifact in artifacts.items():
        if not isinstance(artifact, dict):
            continue
        artifact_id = artifact.get("id")
        _require_edge(edge_rows, "has_artifact", app_id, artifact_id, "artifact containment", errors)
        for config_key in artifact.get("config_keys", {}).values():
            if isinstance(config_key, dict):
                _require_edge(edge_rows, "defines_config", artifact_id, config_key.get("id"), "config-key containment", errors)

        facet = artifact.get("iac")
        if isinstance(facet, dict):
            facet_kind = facet.get("kind")
            if facet_kind == "helm_template":
                for child in facet.get("named_templates", {}).values():
                    if isinstance(child, dict):
                        _require_edge(edge_rows, "iac_defines_template", artifact_id, child.get("id"), "named-template containment", errors)
                for child in facet.get("template_calls", {}).values():
                    if isinstance(child, dict):
                        _require_edge(edge_rows, "iac_has_template_call", artifact_id, child.get("id"), "template-call containment", errors)
                for child in facet.get("value_references", {}).values():
                    if isinstance(child, dict):
                        _require_edge(edge_rows, "iac_has_value_reference", artifact_id, child.get("id"), "value-reference containment", errors)
            elif facet_kind == "helm_chart":
                for child in facet.get("dependencies", {}).values():
                    if isinstance(child, dict):
                        dependency_id = child.get("id")
                        _require_edge(
                            edge_rows,
                            "iac_declares_dependency",
                            artifact_id,
                            dependency_id,
                            "dependency containment",
                            errors,
                        )
                        if isinstance(max_level, int) and max_level >= 2:
                            target_count = sum(
                                edge_type == "iac_targets_chart_reference"
                                and edge.get("src") == dependency_id
                                for edge_type, _, edge in edge_rows
                            )
                            if target_count != 1:
                                errors.append(
                                    "dependency must have exactly one "
                                    "iac_targets_chart_reference edge: "
                                    f"{dependency_id}: found {target_count}"
                                )
                for child in facet.get("render_profiles", {}).values():
                    if isinstance(child, dict):
                        _require_edge(edge_rows, "iac_declares_profile", artifact_id, child.get("id"), "profile containment", errors)
                for render in facet.get("renders", {}).values():
                    if not isinstance(render, dict):
                        continue
                    render_id = render.get("id")
                    _require_edge(edge_rows, "iac_has_render", artifact_id, render_id, "render containment", errors)
                    for diagnostic in render.get("diagnostics", {}).values():
                        if isinstance(diagnostic, dict):
                            _require_edge(edge_rows, "iac_has_diagnostic", render_id, diagnostic.get("id"), "diagnostic containment", errors)
                    for resource in render.get("resources", {}).values():
                        if not isinstance(resource, dict):
                            continue
                        resource_id = resource.get("id")
                        if resource.get("render_id") != render_id:
                            errors.append(f"resource render_id differs from containing render: {resource_id}")
                        _require_edge(edge_rows, "iac_produces", render_id, resource_id, "resource containment", errors)
                        producing_edges = sum(
                            edge_type == "iac_produces"
                            and edge.get("dst") == resource_id
                            for edge_type, _, edge in edge_rows
                        )
                        if producing_edges != 1:
                            errors.append(
                                "resource must have exactly one containing "
                                f"iac_produces edge: {resource_id}: found {producing_edges}"
                            )

            if facet_kind != "helm_chart" and isinstance(max_level, int) and max_level >= 2:
                artifact_parent = str(PurePosixPath(path).parent)
                candidates = [
                    (chart_dir, chart_id)
                    for chart_dir, chart_id in chart_artifacts
                    if artifact_parent == chart_dir or artifact_parent.startswith(f"{chart_dir}/")
                ]
                if candidates:
                    _, chart_id = max(candidates, key=lambda candidate: len(candidate[0]))
                    _require_edge(edge_rows, "iac_part_of_chart", artifact_id, chart_id, "chart membership", errors)

        config_facet = artifact.get("codeanalyzer_iac_config")
        if isinstance(config_facet, dict):
            for profile in config_facet.get("render_profiles", {}).values():
                if isinstance(profile, dict):
                    _require_edge(edge_rows, "iac_declares_profile", artifact_id, profile.get("id"), "profile containment", errors)


def check_document(document: dict) -> list[str]:
    """Return sorted violations of IaC invariants JSON Schema cannot express."""
    errors: list[str] = []
    application = document.get("application", {})
    if not isinstance(application, dict):
        return ["application must be an object"]

    try:
        nodes = collect_nodes(application)
    except ValueError as error:
        errors.extend(str(error).splitlines())
        # Retain the first node for each ID so independent checks can still run.
        nodes = {}
        for node_id, node in _node_items(application):
            nodes.setdefault(node_id, node)

    edge_rows = list(_edges(application))
    aliases = list(_aliases(application))
    alias_ids = {alias.get("id") for alias in aliases}
    relationship_contract = _relationship_contract()
    for edge_type, edge_name, edge in edge_rows:
        src = edge.get("src")
        dst = edge.get("dst")
        if src not in nodes:
            errors.append(f"dangling edge source: {edge_type}/{edge_name}: {src}")
        else:
            contract = relationship_contract.get(edge_type)
            if contract is None:
                errors.append(f"edge family is absent from graph catalog: {edge_type}")
            elif not (
                _projected_labels(str(src), nodes[src], alias_ids)
                & set(contract.get("from", []))
            ):
                errors.append(f"edge endpoint type violation: {edge_type}/{edge_name}/src: {src}")
        if dst not in nodes:
            errors.append(f"dangling edge destination: {edge_type}/{edge_name}: {dst}")
        else:
            contract = relationship_contract.get(edge_type)
            if contract is not None and not (
                _projected_labels(str(dst), nodes[dst], alias_ids)
                & set(contract.get("to", []))
            ):
                errors.append(f"edge endpoint type violation: {edge_type}/{edge_name}/dst: {dst}")

    alias_edges = [edge for edge_type, _, edge in edge_rows if edge_type == "iac_alias_of"]
    for alias in aliases:
        alias_id = alias.get("id")
        target = alias.get("target")
        if alias_id == target or target not in nodes or target in alias_ids:
            errors.append(f"alias target is not canonical: {alias_id}: {target}")
        matching_edges = sum(
            edge.get("src") == alias_id and edge.get("dst") == target for edge in alias_edges
        )
        if matching_edges != 1:
            errors.append(
                f"alias must have exactly one matching iac_alias_of edge: {alias_id}: found {matching_edges}"
            )

    for node_id, node in nodes.items():
        kind = node.get("kind")
        if kind == "artifact":
            _check_artifact(node, errors)
        elif kind == "package":
            if node.get("id") != node.get("purl"):
                errors.append(f"package id must equal purl: {node_id}")
            if not str(node.get("purl", "")).startswith(SUPPORTED_PURL_PREFIX):
                errors.append(f"unsupported package URL type: {node_id}")
        elif kind == "helm_chart_reference" and "purl" in node:
            if not str(node.get("purl", "")).startswith(SUPPORTED_PURL_PREFIX):
                errors.append(f"unsupported package URL type: {node_id}")
        elif kind == "helm_render_profile":
            layers = node.get("value_layers", {})
            if isinstance(layers, dict):
                ordinals = [
                    layer.get("ordinal")
                    for layer in layers.values()
                    if isinstance(layer, dict)
                ]
                if (
                    len(ordinals) != len(layers)
                    or not all(isinstance(ordinal, int) for ordinal in ordinals)
                    or sorted(ordinals) != list(range(len(layers)))
                ):
                    errors.append(
                        f"profile layer ordinals must be contiguous from zero: {node_id}"
                    )
        elif kind == "kubernetes_resource" and node.get("resource_kind") == "Secret":
            secret_data = node.get("secret_data", {})
            if isinstance(secret_data, dict):
                for datum_name, datum in secret_data.items():
                    if not isinstance(datum, dict) or set(datum) != {"key", "sha256"}:
                        errors.append(
                            f"Secret data must contain only key and sha256: {node_id}: {datum_name}"
                        )

    _check_level(document, application, errors)
    _check_scalar_references(nodes, alias_ids, edge_rows, errors)
    _check_containment(application, edge_rows, document.get("max_level"), errors)

    return sorted(set(errors))


def assert_monotone(lower: dict, higher: dict) -> list[str]:
    """Require the higher analysis level to preserve the lower projection."""
    errors: list[str] = []

    def walk(left: object, right: object, path: tuple[str, ...]) -> None:
        if isinstance(left, dict):
            if not isinstance(right, dict):
                errors.append(f"type changed at {'/'.join(path)}")
                return
            for key, value in left.items():
                if key == "max_level":
                    continue
                if key not in right:
                    errors.append(f"removed {'/'.join(path + (key,))}")
                else:
                    walk(value, right[key], path + (key,))
            return
        if isinstance(left, list):
            if not isinstance(right, list) or left != right[: len(left)]:
                errors.append(f"list changed at {'/'.join(path)}")
            return
        if left != right:
            errors.append(f"value changed at {'/'.join(path)}")

    walk(lower, higher, ())
    return sorted(errors)


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def check_catalog(catalog: dict) -> list[str]:
    """Return sorted semantic violations in the Neo4j graph catalog."""
    errors: list[str] = []
    labels = [
        entry.get("label")
        for entry in catalog.get("node_labels", [])
        if isinstance(entry, dict) and isinstance(entry.get("label"), str)
    ]
    label_set = set(labels)
    for label in _duplicates(labels):
        errors.append(f"duplicate node label: {label}")

    relationships = [
        entry for entry in catalog.get("relationship_types", []) if isinstance(entry, dict)
    ]
    relationship_types = [
        entry.get("type")
        for entry in relationships
        if isinstance(entry.get("type"), str)
    ]
    for relationship_type in _duplicates(relationship_types):
        errors.append(f"duplicate relationship type: {relationship_type}")

    for relationship in relationships:
        relationship_type = relationship.get("type", "<unknown>")
        if relationship.get("properties"):
            errors.append(f"relationship properties must be empty: {relationship_type}")
        if (
            relationship_type not in NEUTRAL_RELATIONSHIP_TYPES
            and not str(relationship_type).startswith("IAC_")
        ):
            errors.append(
                f"relationship type must be IAC_* or neutral allowlisted: {relationship_type}"
            )
        for endpoint in ("from", "to"):
            for label in relationship.get(endpoint, []):
                if label not in label_set:
                    errors.append(
                        f"unknown relationship endpoint label: {relationship_type}/{endpoint}: {label}"
                    )

    for entry_kind, collection_name in (("constraint", "constraints"), ("index", "indexes")):
        for statement in catalog.get(collection_name, []):
            for label in _LABEL_REFERENCE.findall(statement):
                if label not in label_set:
                    errors.append(f"{entry_kind} mentions unknown label: {label}")

    return sorted(errors)
