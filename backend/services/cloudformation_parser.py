"""
services/cloudformation_parser.py
---------------------------------
AWS CloudFormation Template Parser (Stage 3).

Parses AWS CloudFormation templates formatted in YAML or JSON into the
common `NormalizedInfrastructure` model using `NormalizedResource`.

Key Capabilities:
1. Full support for CloudFormation YAML and JSON templates (.yaml, .yml, .json).
2. Safe YAML parsing supporting custom CloudFormation short-form tags:
   !Ref, !Sub, !GetAtt, !Join, !Select, !If, !ImportValue, !FindInMap,
   !GetAZs, !Base64, !And, !Or, !Not, !Equals, !Condition.
3. Preserves intrinsic functions as structured data without remote AWS calls
   or template execution.
4. Robust structural validation: distinguishes valid CloudFormation templates
   from generic YAML/JSON and Kubernetes manifests.
5. Captures resource types, properties, logical IDs, and dependencies (DependsOn,
   Ref, and Fn::GetAtt relationships).
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

import yaml

from services.infrastructure_schema import (
    IaCFormat,
    NormalizedInfrastructure,
    NormalizedResource,
    ParsingStatus,
    PlatformProvider,
)
from services.parser_registry import (
    BaseIaCParser,
    MalformedIaCError,
    UnsupportedFormatError,
)

# ---------------------------------------------------------------------------
# Constants & Safeguards
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB maximum template size
MAX_RESOURCE_COUNT = 500           # AWS CloudFormation resource limit

PSEUDO_PARAMETERS = {
    "AWS::AccountId",
    "AWS::NotificationARNs",
    "AWS::NoValue",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
}


# ---------------------------------------------------------------------------
# Custom PyYAML SafeLoader with CloudFormation Intrinsic Tag Constructors
# ---------------------------------------------------------------------------


class CfnYamlLoader(yaml.SafeLoader):
    """Safe YAML loader with registered constructors for CloudFormation tags."""


def _make_generic_constructor(tag_name: str):
    def constructor(loader: yaml.Loader, node: yaml.Node) -> Any:
        if isinstance(node, yaml.ScalarNode):
            return {tag_name: loader.construct_scalar(node)}
        elif isinstance(node, yaml.SequenceNode):
            return {tag_name: loader.construct_sequence(node)}
        elif isinstance(node, yaml.MappingNode):
            return {tag_name: loader.construct_mapping(node)}
        return {tag_name: None}
    return constructor


def _getatt_constructor(loader: yaml.Loader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        val = loader.construct_scalar(node)
        return {"Fn::GetAtt": val.split(".", 1) if "." in val else [val]}
    elif isinstance(node, yaml.SequenceNode):
        return {"Fn::GetAtt": loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {"Fn::GetAtt": loader.construct_mapping(node)}
    return {"Fn::GetAtt": []}


def _ref_constructor(loader: yaml.Loader, node: yaml.Node) -> Any:
    return {"Ref": loader.construct_scalar(node)}


def _condition_constructor(loader: yaml.Loader, node: yaml.Node) -> Any:
    return {"Condition": loader.construct_scalar(node)}


# Register CloudFormation YAML short-form tag constructors
CfnYamlLoader.add_constructor("!Ref", _ref_constructor)
CfnYamlLoader.add_constructor("!GetAtt", _getatt_constructor)
CfnYamlLoader.add_constructor("!Condition", _condition_constructor)

for _tag in (
    "Sub",
    "Join",
    "Select",
    "If",
    "ImportValue",
    "FindInMap",
    "GetAZs",
    "Base64",
    "And",
    "Or",
    "Not",
    "Equals",
):
    CfnYamlLoader.add_constructor(f"!{_tag}", _make_generic_constructor(f"Fn::{_tag}"))


# ---------------------------------------------------------------------------
# Relationship & Intrinsic Extraction Helpers
# ---------------------------------------------------------------------------


def _extract_relationships(properties: Any, depends_on: Any) -> list[str]:
    """
    Extract referenced resource logical IDs from DependsOn and intrinsic
    functions (Ref, Fn::GetAtt).
    """
    targets: list[str] = []

    # 1. Explicit DependsOn dependencies
    if isinstance(depends_on, str) and depends_on.strip():
        targets.append(depends_on.strip())
    elif isinstance(depends_on, list):
        for dep in depends_on:
            if isinstance(dep, str) and dep.strip():
                targets.append(dep.strip())

    # 2. Walk properties recursively for Ref and Fn::GetAtt
    def _walk(val: Any) -> None:
        if isinstance(val, dict):
            # Check for Ref
            ref_val = val.get("Ref")
            if isinstance(ref_val, str) and ref_val.strip() and ref_val not in PSEUDO_PARAMETERS:
                targets.append(ref_val.strip())

            # Check for Fn::GetAtt
            getatt_val = val.get("Fn::GetAtt")
            if isinstance(getatt_val, list) and len(getatt_val) > 0:
                first = getatt_val[0]
                if isinstance(first, str) and first.strip() and first not in PSEUDO_PARAMETERS:
                    targets.append(first.strip())
            elif isinstance(getatt_val, str) and "." in getatt_val:
                first = getatt_val.split(".", 1)[0].strip()
                if first and first not in PSEUDO_PARAMETERS:
                    targets.append(first)

            for v in val.values():
                _walk(v)
        elif isinstance(val, list):
            for item in val:
                _walk(item)

    _walk(properties)

    # Return deduplicated list while preserving order
    return list(dict.fromkeys(targets))


def _find_intrinsics_summary(properties: Any) -> list[str]:
    """Find names of intrinsic functions used within properties."""
    found: set[str] = set()

    def _walk(val: Any) -> None:
        if isinstance(val, dict):
            for k in val.keys():
                if k == "Ref" or k.startswith("Fn::"):
                    found.add(k)
            for v in val.values():
                _walk(v)
        elif isinstance(val, list):
            for item in val:
                _walk(item)

    _walk(properties)
    return sorted(found)


# ---------------------------------------------------------------------------
# Format Signature Inspectors
# ---------------------------------------------------------------------------


def _looks_like_kubernetes(content: str) -> bool:
    """Heuristic check for Kubernetes manifests to prevent misidentification."""
    if not content:
        return False
    indicators = ["apiVersion:", "kind:", "metadata:"]
    return sum(1 for ind in indicators if ind in content) >= 2


# ---------------------------------------------------------------------------
# CloudFormation Parser
# ---------------------------------------------------------------------------


class CloudFormationParser(BaseIaCParser):
    """
    Parser implementation for AWS CloudFormation templates in YAML and JSON format.
    """

    @property
    def format_name(self) -> IaCFormat:
        return IaCFormat.CLOUDFORMATION

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".yaml", ".yml", ".json")

    def can_parse(self, filename: str, content: str = "") -> bool:
        """
        Structural validation ensuring the document is a valid CloudFormation
        template and not generic YAML/JSON or Kubernetes manifests.
        """
        if not filename:
            return False

        fn_lower = filename.lower()

        # Never claim Terraform JSON
        if fn_lower.endswith(".tf.json"):
            return False

        # Must have supported extension
        if not (fn_lower.endswith(".yaml") or fn_lower.endswith(".yml") or fn_lower.endswith(".json")):
            return False

        # If no content is provided, cannot claim format definitively
        if not content or not content.strip():
            return False

        # Reject Kubernetes manifests immediately
        if _looks_like_kubernetes(content):
            return False

        try:
            # Parse document structure
            if fn_lower.endswith(".json") or content.strip().startswith("{"):
                data = json.loads(content)
            else:
                data = yaml.load(content, Loader=CfnYamlLoader)

            if not isinstance(data, dict):
                return False

            resources = data.get("Resources")
            if not isinstance(resources, dict) or len(resources) == 0:
                return False

            # Inspect resources: must have logical IDs and plausible CloudFormation Types
            valid_cfn_resources = 0
            for logical_id, decl in resources.items():
                if not isinstance(logical_id, str) or not logical_id.strip():
                    return False
                if isinstance(decl, dict) and "Type" in decl and isinstance(decl["Type"], str):
                    res_type = decl["Type"].strip()
                    # Standard CloudFormation types: 'AWS::Service::Resource', 'Custom::...', or 'X::Y::Z'
                    if "::" in res_type or res_type.startswith("AWS::") or res_type.startswith("Custom::"):
                        valid_cfn_resources += 1

            return valid_cfn_resources > 0
        except Exception:
            return False

    def parse(self, content: str, filename: str = "") -> NormalizedInfrastructure:
        """
        Parse raw CloudFormation template text into NormalizedInfrastructure.

        Raises:
            MalformedIaCError: If content is empty, invalid YAML/JSON, or lacks
                               a valid 'Resources' section.
        """
        if not content or not content.strip():
            raise MalformedIaCError("File is empty.")

        # File size safeguard
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise MalformedIaCError(f"CloudFormation file exceeds maximum supported size (10 MB).")

        fn_lower = filename.lower()
        data: Any = None

        # 1. Parse YAML or JSON safely
        if fn_lower.endswith(".json") or content.strip().startswith("{"):
            try:
                data = json.loads(content)
            except Exception as exc:
                raise MalformedIaCError(f"Invalid CloudFormation JSON syntax: {exc}") from exc
        else:
            try:
                data = yaml.load(content, Loader=CfnYamlLoader)
            except Exception as exc:
                raise MalformedIaCError(f"Invalid CloudFormation YAML syntax: {exc}") from exc

        if not isinstance(data, dict):
            raise MalformedIaCError("CloudFormation template root must be a mapping/object.")

        # 2. Validate Resources section
        if "Resources" not in data:
            raise MalformedIaCError("CloudFormation template is missing required 'Resources' section.")

        resources_dict = data.get("Resources")
        if not isinstance(resources_dict, dict) or len(resources_dict) == 0:
            raise MalformedIaCError("CloudFormation template 'Resources' section must be a non-empty mapping.")

        if len(resources_dict) > MAX_RESOURCE_COUNT:
            raise MalformedIaCError(f"Template exceeds maximum resource limit of {MAX_RESOURCE_COUNT} resources.")

        # 3. Extract and normalize resources
        normalized_resources: list[NormalizedResource] = []
        template_warnings: list[str] = []

        for logical_id, decl in resources_dict.items():
            if not isinstance(decl, dict):
                raise MalformedIaCError(f"Resource '{logical_id}' declaration must be a mapping/object.")

            res_type = decl.get("Type")
            if not res_type or not isinstance(res_type, str):
                raise MalformedIaCError(f"Resource '{logical_id}' is missing a valid 'Type' attribute.")

            res_type = res_type.strip()
            properties = decl.get("Properties")
            if properties is None:
                properties = {}
            elif not isinstance(properties, dict):
                properties = {"_raw_properties": properties}

            depends_on = decl.get("DependsOn")
            relationships = _extract_relationships(properties, depends_on)

            # Record intrinsic function notices
            intrinsics_used = _find_intrinsics_summary(properties)
            res_warnings: list[str] = []
            if intrinsics_used:
                res_warnings.append(
                    f"Preserved unresolved intrinsic functions {intrinsics_used} as structured data."
                )

            # Determine provider
            provider = PlatformProvider.AWS.value
            if not res_type.startswith("AWS::") and not res_type.startswith("Custom::"):
                provider = PlatformProvider.GENERIC.value

            normalized_res = NormalizedResource(
                id=f"{res_type}.{logical_id}",
                name=logical_id,
                type=res_type,
                source_format=IaCFormat.CLOUDFORMATION.value,
                provider=provider,
                attributes=properties,
                relationships=relationships,
                source_file=filename,
                source_location={
                    "format": "cloudformation",
                    "logical_id": logical_id,
                    "file": filename,
                },
                parsing_status=ParsingStatus.VALID.value,
                validation_errors=res_warnings,
                raw_declaration=decl,
            )
            normalized_resources.append(normalized_res)

        return NormalizedInfrastructure(
            source_format=IaCFormat.CLOUDFORMATION.value,
            source_file=filename,
            resources=normalized_resources,
            parsing_status=ParsingStatus.VALID.value,
            validation_errors=template_warnings,
            metadata={
                "format_version": str(data.get("AWSTemplateFormatVersion", "2010-09-09")),
                "description": str(data.get("Description", "")),
                "parameters_count": len(data.get("Parameters", {})) if isinstance(data.get("Parameters"), dict) else 0,
            },
        )
