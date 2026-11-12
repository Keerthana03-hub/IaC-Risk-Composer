"""
services/infrastructure_schema.py
---------------------------------
Common Infrastructure Representation (Stage 1).

Defines the normalized internal schema for infrastructure-as-code resources
across multiple input formats (Terraform, CloudFormation, Kubernetes).

Design Goals:
1. Universal representation: captures resource identity, type, attributes,
   relationships, provenance, and validation status regardless of source format.
2. Backward compatibility: supports dictionary-like access (`r["type"]`, `r["name"]`,
   `r["attributes"]`) and legacy conversion so existing Step 1–6 analysis modules
   continue to function without modification.
3. Extensible: provides type constants and builders for Terraform, CloudFormation,
   and Kubernetes resources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Format and Provider Enumerations
# ---------------------------------------------------------------------------


class IaCFormat(str, Enum):
    """Supported Infrastructure-as-Code source formats."""

    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    UNKNOWN = "unknown"


class PlatformProvider(str, Enum):
    """Target cloud platform or runtime environment."""

    AWS = "aws"
    KUBERNETES = "kubernetes"
    AZURE = "azure"
    GCP = "gcp"
    GENERIC = "generic"


class ParsingStatus(str, Enum):
    """Integrity and validation status of a parsed resource or document."""

    VALID = "valid"
    PARTIAL = "partial"
    WARNING = "warning"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Normalized Resource Model
# ---------------------------------------------------------------------------


@dataclass
class NormalizedResource:
    """
    A single infrastructure resource declaration, normalized across IaC formats.

    Fields:
        id: Unique resource identifier across the template (e.g. 'aws_s3_bucket.vault',
            'AWS::S3::Bucket.SecureVault', 'k8s:Deployment/default/api-gateway').
        name: Logical or declared name of the resource.
        type: Resource type string (e.g. 'aws_s3_bucket', 'AWS::S3::Bucket', 'Deployment').
        source_format: Originating IaC format (terraform, cloudformation, kubernetes).
        provider: Target provider or platform (aws, kubernetes, azure, gcp, generic).
        attributes: Resource properties, arguments, or spec dictionary.
        relationships: Explicit or inferred IDs of other resources referenced by this one.
        source_file: Name of the originating source file.
        source_location: File location metadata (e.g., {"line": 12, "doc_index": 0}).
        parsing_status: Validation state (valid, partial, warning, error).
        validation_errors: Informational, warning, or error messages from the parser.
        raw_declaration: Optional unparsed/verbatim block content for auditing.
    """

    id: str
    name: str
    type: str
    source_format: str = IaCFormat.TERRAFORM.value
    provider: str = PlatformProvider.AWS.value
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: list[str] = field(default_factory=list)
    source_file: str | None = None
    source_location: dict[str, Any] = field(default_factory=dict)
    parsing_status: str = ParsingStatus.VALID.value
    validation_errors: list[str] = field(default_factory=list)
    raw_declaration: dict[str, Any] | None = None

    # -----------------------------------------------------------------------
    # Dictionary Compatibility Protocol (Backward Compatibility with Legacy Code)
    # -----------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        """Allow legacy dict-style access (e.g. resource['type'])."""
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Allow legacy dict-style assignment (e.g. resource['attributes'] = ...)."""
        if hasattr(self, key):
            setattr(self, key, value)
        else:
            raise KeyError(f"NormalizedResource has no field '{key}'")

    def __contains__(self, key: object) -> bool:
        """Support 'key in resource' checks."""
        return isinstance(key, str) and hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        """Dictionary get() helper for legacy code."""
        if hasattr(self, key):
            val = getattr(self, key)
            return default if val is None else val
        return default

    def to_dict(self) -> dict[str, Any]:
        """Convert to standard Python dictionary."""
        return asdict(self)

    def to_legacy_dict(self) -> dict[str, Any]:
        """
        Export as a classic Step 1 resource dictionary:
        {'type': ..., 'name': ..., 'attributes': ...}
        """
        return {
            "type": self.type,
            "name": self.name,
            "attributes": self.attributes,
        }

    # -----------------------------------------------------------------------
    # Factory Methods
    # -----------------------------------------------------------------------

    @classmethod
    def from_terraform(
        cls,
        resource_dict: Mapping[str, Any],
        filename: str | None = None,
    ) -> NormalizedResource:
        """
        Create a NormalizedResource from a legacy Terraform parsed resource dictionary:
        {'type': 'aws_s3_bucket', 'name': 'vault', 'attributes': {...}}
        """
        res_type = str(resource_dict.get("type", ""))
        name = str(resource_dict.get("name", ""))
        attrs = dict(resource_dict.get("attributes", {}) or {})
        res_id = f"{res_type}.{name}" if res_type and name else name or res_type

        # Infer provider from type prefix
        provider = PlatformProvider.AWS.value
        if res_type.startswith("azurerm_"):
            provider = PlatformProvider.AZURE.value
        elif res_type.startswith("google_") or res_type.startswith("google-beta_"):
            provider = PlatformProvider.GCP.value
        elif res_type.startswith("kubernetes_"):
            provider = PlatformProvider.KUBERNETES.value

        return cls(
            id=res_id,
            name=name,
            type=res_type,
            source_format=IaCFormat.TERRAFORM.value,
            provider=provider,
            attributes=attrs,
            source_file=filename,
            source_location={"format": "hcl2"},
            parsing_status=ParsingStatus.VALID.value,
        )


# ---------------------------------------------------------------------------
# Normalized Infrastructure Container
# ---------------------------------------------------------------------------


@dataclass
class NormalizedInfrastructure:
    """
    Complete parsed infrastructure model containing normalized resources and metadata.
    """

    source_format: str
    source_file: str
    resources: list[NormalizedResource] = field(default_factory=list)
    parsing_status: str = ParsingStatus.VALID.value
    validation_errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def resource_count(self) -> int:
        """Total number of declared resources."""
        return len(self.resources)

    @property
    def resource_types(self) -> list[str]:
        """Sorted list of unique resource type identifiers."""
        return sorted({r.type for r in self.resources if r.type})

    def get_resource(self, resource_id: str) -> NormalizedResource | None:
        """Lookup resource by its unique normalized ID."""
        for r in self.resources:
            if r.id == resource_id:
                return r
        return None

    def to_legacy_resources(self) -> list[dict[str, Any]]:
        """
        Convert to list of legacy Step 1 resource dictionaries:
        [{'type': ..., 'name': ..., 'attributes': ...}]
        """
        return [r.to_legacy_dict() for r in self.resources]

    def to_dict(self) -> dict[str, Any]:
        """Export full container as a serializable dictionary."""
        return {
            "source_format": self.source_format,
            "source_file": self.source_file,
            "resource_count": self.resource_count,
            "resource_types": self.resource_types,
            "parsing_status": self.parsing_status,
            "validation_errors": self.validation_errors,
            "metadata": self.metadata,
            "resources": [r.to_dict() for r in self.resources],
        }
