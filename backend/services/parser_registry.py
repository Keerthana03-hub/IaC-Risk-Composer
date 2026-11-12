"""
services/parser_registry.py
---------------------------
Multi-IaC Parser Registry & Interface (Stage 2).

Provides a scalable, extensible parser registry that inspects uploaded
Infrastructure-as-Code files, identifies their format, and routes them to
the appropriate parser implementation.

Supported Formats (Architecture):
1. Terraform (.tf, .tf.json) -> Integrated via existing python-hcl2 parser
2. AWS CloudFormation (.yaml, .yml, .json) -> Registered in Stage 3
3. Kubernetes YAML manifests -> Registered in Stage 4
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from services.infrastructure_schema import (
    IaCFormat,
    NormalizedInfrastructure,
    NormalizedResource,
    ParsingStatus,
    PlatformProvider,
)
from services.terraform_parser import TerraformParseError, parse_terraform


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IaCParseError(ValueError):
    """Base exception for all IaC parsing failures."""


class UnsupportedFormatError(IaCParseError):
    """Raised when an uploaded file format is not recognized or supported."""


class MalformedIaCError(IaCParseError):
    """Raised when an uploaded file matches a supported format signature but contains invalid syntax."""


# ---------------------------------------------------------------------------
# Common Parser Interface
# ---------------------------------------------------------------------------


class BaseIaCParser(ABC):
    """
    Abstract interface for format-specific IaC parsers.

    Every parser implementation must define its target format, supported
    file extensions, format identification logic, and safe parsing method.
    """

    @property
    @abstractmethod
    def format_name(self) -> IaCFormat:
        """The normalized IaCFormat enum value handled by this parser."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """File extensions handled by this parser (lowercase, e.g. ('.tf', '.tf.json'))."""
        pass

    @abstractmethod
    def can_parse(self, filename: str, content: str = "") -> bool:
        """
        Inspect filename and optional content signature to determine if
        this parser can process the file.
        """
        pass

    @abstractmethod
    def parse(self, content: str, filename: str = "") -> NormalizedInfrastructure:
        """
        Safely parse source text into a NormalizedInfrastructure model.

        Raises:
            IaCParseError or subclasses (MalformedIaCError) on parsing failure.
        """
        pass


# ---------------------------------------------------------------------------
# Terraform Parser Implementation (Stage 2)
# ---------------------------------------------------------------------------


class TerraformParser(BaseIaCParser):
    """
    Parser for Terraform configurations (.tf HCL2 and .tf.json).

    Reuses the existing `services.terraform_parser.parse_terraform` implementation
    for .tf files, and supports .tf.json syntax natively.
    """

    @property
    def format_name(self) -> IaCFormat:
        return IaCFormat.TERRAFORM

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".tf", ".tf.json")

    def can_parse(self, filename: str, content: str = "") -> bool:
        """
        Return True if filename ends with .tf or .tf.json.
        For .tf.json, optionally validates that the JSON has Terraform-like keys.
        """
        fn_lower = filename.lower()
        if fn_lower.endswith(".tf.json"):
            if not content:
                return True
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    # Check for standard Terraform root keys
                    tf_root_keys = {"resource", "provider", "variable", "terraform", "output", "data", "module", "locals"}
                    return any(k in data for k in tf_root_keys) or len(data) == 0
                return False
            except Exception:
                return False

        return fn_lower.endswith(".tf")

    def parse(self, content: str, filename: str = "") -> NormalizedInfrastructure:
        """
        Parse Terraform .tf or .tf.json into a NormalizedInfrastructure model.
        """
        if not content or not content.strip():
            raise MalformedIaCError("File is empty.")

        fn_lower = filename.lower()
        raw_resources: list[dict[str, Any]] = []

        if fn_lower.endswith(".tf.json"):
            # Parse Terraform JSON format
            try:
                parsed_json = json.loads(content)
            except Exception as exc:
                raise MalformedIaCError(f"Invalid Terraform JSON syntax: {exc}") from exc

            if not isinstance(parsed_json, dict):
                raise MalformedIaCError("Terraform .tf.json root must be a JSON object.")

            resource_block = parsed_json.get("resource", [])
            # Terraform JSON resource block can be a list of dicts or a dict of dicts
            if isinstance(resource_block, dict):
                # Shape: {"aws_s3_bucket": {"bucket_name": {...}}}
                for res_type, named in resource_block.items():
                    if isinstance(named, dict):
                        for res_name, attrs in named.items():
                            raw_resources.append({
                                "type": str(res_type),
                                "name": str(res_name),
                                "attributes": attrs if isinstance(attrs, dict) else {},
                            })
            elif isinstance(resource_block, list):
                # Shape: [{"aws_s3_bucket": {"bucket_name": {...}}}]
                for block in resource_block:
                    if isinstance(block, dict):
                        for res_type, named in block.items():
                            if isinstance(named, dict):
                                for res_name, attrs in named.items():
                                    raw_resources.append({
                                        "type": str(res_type),
                                        "name": str(res_name),
                                        "attributes": attrs if isinstance(attrs, dict) else {},
                                    })
        else:
            # Parse HCL2 .tf using existing parser
            try:
                raw_resources = parse_terraform(content)
            except TerraformParseError as exc:
                raise MalformedIaCError(str(exc)) from exc

        # Convert to NormalizedResource models
        normalized_resources = [
            NormalizedResource.from_terraform(r, filename=filename)
            for r in raw_resources
        ]

        return NormalizedInfrastructure(
            source_format=IaCFormat.TERRAFORM.value,
            source_file=filename,
            resources=normalized_resources,
            parsing_status=ParsingStatus.VALID.value,
            validation_errors=[],
            metadata={"parser": "python-hcl2" if not fn_lower.endswith(".tf.json") else "json"},
        )


# ---------------------------------------------------------------------------
# Central Parser Registry
# ---------------------------------------------------------------------------


class ParserRegistry:
    """
    Central registry and router for multi-IaC parsers.

    Maintains registered parser instances, performs format identification
    via file extension and content inspection, and dispatches parsing safely.
    """

    def __init__(self) -> None:
        self._parsers: dict[IaCFormat, BaseIaCParser] = {}

    def register(self, parser: BaseIaCParser) -> None:
        """Register an IaC parser implementation."""
        self._parsers[parser.format_name] = parser

    def unregister(self, format_name: IaCFormat) -> None:
        """Remove a parser implementation by format."""
        self._parsers.pop(format_name, None)

    def _ensure_default_parsers(self) -> None:
        """Ensure standard built-in parsers are registered on the global default registry."""
        if globals().get("default_parser_registry") is self:
            if IaCFormat.CLOUDFORMATION not in self._parsers:
                try:
                    from services.cloudformation_parser import CloudFormationParser
                    self.register(CloudFormationParser())
                except ImportError:
                    pass
            if IaCFormat.KUBERNETES not in self._parsers:
                try:
                    from services.kubernetes_parser import KubernetesParser
                    self.register(KubernetesParser())
                except ImportError:
                    pass

    def get_parser(self, format_name: IaCFormat | str) -> BaseIaCParser | None:
        """Retrieve parser for a specific format enum or string name."""
        self._ensure_default_parsers()
        if isinstance(format_name, str):
            try:
                format_name = IaCFormat(format_name.lower())
            except ValueError:
                return None
        return self._parsers.get(format_name)

    def list_parsers(self) -> list[BaseIaCParser]:
        """List all currently registered parser instances."""
        self._ensure_default_parsers()
        return list(self._parsers.values())

    def list_supported_formats(self) -> list[str]:
        """List human-readable names of currently registered formats."""
        self._ensure_default_parsers()
        return [p.format_name.value for p in self._parsers.values()]

    def identify_format(self, filename: str, content: str = "") -> IaCFormat:
        """
        Identify the IaC format of an uploaded file by checking registered
        parsers against its filename and content signature.

        Raises:
            UnsupportedFormatError: If no registered parser claims the file,
                                    or if arbitrary YAML/JSON lacks valid IaC signatures.
        """
        self._ensure_default_parsers()
        if not filename:
            raise UnsupportedFormatError("No filename provided for format identification.")

        fn_lower = filename.lower()

        # Check registered parsers
        for parser in self._parsers.values():
            if parser.can_parse(filename, content):
                return parser.format_name

        # If file is YAML or JSON but not matched by registered parsers:
        if fn_lower.endswith((".yaml", ".yml")):
            raise UnsupportedFormatError(
                f"File '{filename}' is a generic YAML file and does not match any supported Infrastructure-as-Code format."
            )

        if fn_lower.endswith(".json") and not fn_lower.endswith(".tf.json"):
            raise UnsupportedFormatError(
                f"File '{filename}' is a generic JSON file and does not match any supported Infrastructure-as-Code format."
            )

        ext = Path(filename).suffix or "unknown"
        supported = ", ".join([
            ".tf, .tf.json (Terraform)",
            ".yaml, .yml, .json (CloudFormation)",
            ".yaml, .yml (Kubernetes)",
        ])
        raise UnsupportedFormatError(
            f"Unsupported file format '{ext}' for file '{filename}'. Supported formats: {supported}."
        )

    def get_parser_for_file(self, filename: str, content: str = "") -> BaseIaCParser:
        """
        Resolve the appropriate parser for a given file.

        Raises:
            UnsupportedFormatError: If no registered parser is found.
        """
        fmt = self.identify_format(filename, content)
        parser = self._parsers.get(fmt)
        if not parser:
            raise UnsupportedFormatError(f"No parser implementation registered for format '{fmt.value}'.")
        return parser

    def parse(self, content: str, filename: str = "") -> NormalizedInfrastructure:
        """
        Identify format and parse content into a NormalizedInfrastructure model.
        """
        parser = self.get_parser_for_file(filename, content)
        return parser.parse(content, filename=filename)


# ---------------------------------------------------------------------------
# Format Signature Helpers (Prevents Arbitrary YAML / JSON Misidentification)
# ---------------------------------------------------------------------------


def _looks_like_cloudformation_template(content: str) -> bool:
    """Heuristic check for AWS CloudFormation signatures."""
    if not content:
        return False
    indicators = [
        "AWSTemplateFormatVersion",
        "AWS::",
        "Fn::Sub",
        "Fn::GetAtt",
        "Fn::Join",
    ]
    return any(ind in content for ind in indicators)


def _looks_like_kubernetes_manifest(content: str) -> bool:
    """Heuristic check for Kubernetes manifest signatures."""
    if not content:
        return False
    indicators = [
        "apiVersion:",
        "kind:",
        "metadata:",
        "spec:",
    ]
    return sum(1 for ind in indicators if ind in content) >= 2


# ---------------------------------------------------------------------------
# Global Registry Instance & Convenience Functions
# ---------------------------------------------------------------------------

default_parser_registry = ParserRegistry()
default_parser_registry.register(TerraformParser())

try:
    from services.cloudformation_parser import CloudFormationParser
    default_parser_registry.register(CloudFormationParser())
except ImportError:
    pass

try:
    from services.kubernetes_parser import KubernetesParser
    default_parser_registry.register(KubernetesParser())
except ImportError:
    pass


def parse_iac(content: str, filename: str = "") -> NormalizedInfrastructure:
    """Parse IaC content using the default registered parser for the format."""
    return default_parser_registry.parse(content, filename=filename)


def identify_iac_format(filename: str, content: str = "") -> IaCFormat:
    """Identify the IaC format of a file using the default registry."""
    return default_parser_registry.identify_format(filename, content)
