"""
services/infrastructure_mapper.py
-----------------------------------
Infrastructure Mapping Engine (Step 2 — Nodes & Edges).

Converts the flat resource list produced by
`services.terraform_parser.parse_terraform()` into a graph:

    - nodes: one entry per Terraform resource block.
    - edges: a "references" relationship wherever one resource's
      attributes literally contain another resource's exact `type.name`
      id (e.g. `aws_instance.web_server` referencing
      `aws_security_group.web_sg` via `vpc_security_group_ids`).

Why this approach is deterministic and safe:
    `python-hcl2` normalises *every* reference expression — whether
    written as a bare traversal (`aws_security_group.web_sg.id`) or as
    a string interpolation (`"${aws_security_group.web_sg.id}"`) — into
    the same `"${type.name...}"` string inside `attributes`. So we never
    need to parse HCL expression syntax ourselves: we just search each
    resource's attribute values (recursively, across dicts/lists/strings)
    for the exact `type.name` id of every *other* resource that was
    actually parsed from this file.

    Because we only ever test against ids drawn from the real resource
    list — never against arbitrary identifiers — references to
    variables (`var.x`), data sources (`data.x.y`), modules
    (`module.x`), or resources that simply aren't in this file can never
    produce an edge: there is no matching id for them to be compared
    against. No heuristics, no LLM/AI, no guessing based on resource
    type alone.

This module has no FastAPI/HTTP dependency, so it can be reused by a
CLI, a background job, or the future threat_engine without dragging in
web-framework imports.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Friendly (human-readable) resource type labels
# ---------------------------------------------------------------------------

# Small, easily-extended lookup for common Terraform (mostly AWS) resource
# types. Anything not listed here falls back to `_humanize_resource_type()`,
# which strips the provider prefix and title-cases the rest.
_FRIENDLY_TYPE_NAMES: dict[str, str] = {
    "aws_instance": "EC2 Instance",
    "aws_s3_bucket": "S3 Bucket",
    "aws_security_group": "Security Group",
    "aws_vpc": "VPC",
    "aws_subnet": "Subnet",
    "aws_iam_role": "IAM Role",
    "aws_iam_policy": "IAM Policy",
    "aws_iam_role_policy_attachment": "IAM Role Policy Attachment",
    "aws_db_instance": "RDS Database Instance",
    "aws_lambda_function": "Lambda Function",
    "aws_route_table": "Route Table",
    "aws_internet_gateway": "Internet Gateway",
    "aws_lb": "Load Balancer",
    "aws_elb": "Load Balancer",
    "aws_key_pair": "Key Pair",
    "aws_eip": "Elastic IP",
    "aws_ebs_volume": "EBS Volume",
}

_KNOWN_PROVIDER_PREFIXES = ("aws_", "azurerm_", "google_", "google-beta_")


def _humanize_resource_type(resource_type: str) -> str:
    """
    Best-effort human-readable label for a resource type, e.g.
    "aws_instance" -> "EC2 Instance", or, for anything not in the lookup
    table, "azurerm_virtual_network" -> "Virtual Network".
    """
    if resource_type in _FRIENDLY_TYPE_NAMES:
        return _FRIENDLY_TYPE_NAMES[resource_type]

    stripped = resource_type
    for prefix in _KNOWN_PROVIDER_PREFIXES:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break

    return stripped.replace("_", " ").title() if stripped else resource_type


# ---------------------------------------------------------------------------
# Reference extraction
# ---------------------------------------------------------------------------


def _collect_strings(value: Any) -> Iterable[str]:
    """
    Recursively walk a resource's `attributes` value — which may be a
    dict, a list, or a scalar — and yield every string leaf found. This
    is where a reference like "${aws_security_group.web_sg.id}" lives,
    however deeply it's nested (e.g. inside a list inside a nested block
    dict).
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _collect_strings(v)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _collect_strings(item)
    # numbers, booleans, None: nothing to yield


def _references_id(haystack: str, resource_id: str) -> bool:
    """
    True if `haystack` contains the exact `resource_id` (e.g.
    "aws_security_group.web_sg") as a whole token — not merely as a
    substring of a longer type or name. This stops
    "aws_instance.web_server_2" from being mistaken for a reference to
    "aws_instance.web_server".
    """
    pattern = r"\b" + re.escape(resource_id) + r"\b"
    return re.search(pattern, haystack) is not None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_infrastructure_map(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Convert parsed Terraform resources into an infrastructure map of
    nodes and edges.

    Args:
        resources: The list returned by
            `services.terraform_parser.parse_terraform()`, each item
            shaped like {"type": ..., "name": ..., "attributes": {...}}.

    Returns:
        {"nodes": [...], "edges": [...]}.
        Both are always present (never omitted, never None); both are
        empty lists when `resources` is empty — this never raises.

    Node shape:
        {"id", "resource_type", "name", "label", "attributes"}

    Edge shape:
        {"source", "target", "relationship", "label"}
        `source` is the resource that contains the reference; `target`
        is the resource being referenced.

    Guarantees:
        - No edges to variables, data sources, modules, or resources
          absent from `resources` (see module docstring for why).
        - No self-referencing edges.
        - No duplicate edges, even if a resource mentions another
          resource's id more than once in its attributes.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    if not resources:
        return {"nodes": nodes, "edges": edges}

    # ---- Nodes ----------------------------------------------------------
    # Build every node (and its id) first, so the full set of valid ids is
    # known before we go looking for references — an edge should only
    # ever point at a node that actually exists in this file.
    resource_ids: list[str] = []
    for resource in resources:
        resource_type = resource.get("type", "")
        name = resource.get("name", "")
        resource_id = f"{resource_type}.{name}"
        resource_ids.append(resource_id)

        nodes.append(
            {
                "id": resource_id,
                "resource_type": resource_type,
                "name": name,
                "label": f"{_humanize_resource_type(resource_type)}: {name}",
                "attributes": resource.get("attributes", {}) or {},
            }
        )

    # ---- Edges ------------------------------------------------------------
    seen_edges: set[tuple[str, str]] = set()

    for source_resource, source_id in zip(resources, resource_ids):
        haystack = " ".join(_collect_strings(source_resource.get("attributes", {})))
        if not haystack:
            continue

        for target_resource, target_id in zip(resources, resource_ids):
            if target_id == source_id:
                continue  # never a self-referencing edge

            if (source_id, target_id) in seen_edges:
                continue  # already recorded — avoid duplicates

            if not _references_id(haystack, target_id):
                continue

            seen_edges.add((source_id, target_id))
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "relationship": "references",
                    "label": f"Uses {_humanize_resource_type(target_resource.get('type', ''))}",
                }
            )

    return {"nodes": nodes, "edges": edges}
