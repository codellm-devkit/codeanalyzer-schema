#!/usr/bin/env python3
"""Semantic conformance checks for the schema-v2 IaC contract."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re


NEUTRAL_RELATIONSHIP_TYPES = {"DEFINES_CONFIG", "HAS_ARTIFACT"}
_LABEL_REFERENCE = re.compile(r":\s*`?([A-Za-z][A-Za-z0-9_]*)`?")


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
    for edge_type, edge_name, edge in edge_rows:
        src = edge.get("src")
        dst = edge.get("dst")
        if src not in nodes:
            errors.append(f"dangling edge source: {edge_type}/{edge_name}: {src}")
        if dst not in nodes:
            errors.append(f"dangling edge destination: {edge_type}/{edge_name}: {dst}")

    aliases = list(_aliases(application))
    alias_ids = {alias.get("id") for alias in aliases}
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
        elif kind == "package" and node.get("id") != node.get("purl"):
            errors.append(f"package id must equal purl: {node_id}")
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

    return sorted(errors)


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
        if path and path[-1] == "target_id" and left is None and isinstance(right, str):
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
