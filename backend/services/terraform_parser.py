"""
services/terraform_parser.py
------------------------------
Reusable Terraform (.tf) parsing service, built on `python-hcl2`.

Step 2 scope: parse HCL2 source and extract `resource "type" "name" {...}`
blocks. No risk scoring, no threat rules, no findings — that is reserved
for a later threat-engine phase that will consume this output.

Kept independent of FastAPI/HTTP concerns on purpose, so it can be reused
by a CLI, a background job, or the future threat_engine without dragging
in web-framework dependencies.
"""

from __future__ import annotations

import io
from typing import Any

import hcl2
from hcl2.utils import SerializationOptions
from lark.exceptions import LarkError


class TerraformParseError(ValueError):
    """Raised when Terraform source cannot be parsed as valid HCL2."""


# python-hcl2 >= 8 changed its defaults: it now wraps string literals in
# extra quotes and adds "__is_block__" markers so parse trees can be
# round-tripped back into HCL. Neither is useful for extracting resources,
# so we opt back into the classic, simpler shape:
#   {"resource": [{"aws_instance": {"web_server": {"ami": "ami-123"}}}]}
_SERIALIZATION_OPTIONS = SerializationOptions(
    strip_string_quotes=True,   # "ami-123" instead of '"ami-123"'
    explicit_blocks=False,      # no "__is_block__" marker keys
    with_comments=False,        # comments aren't needed for parsing
)


def parse_terraform(content: str) -> list[dict[str, Any]]:
    """
    Parse raw Terraform (HCL2) source text and return a flat list of the
    resource blocks it declares.

    Each item has the shape:
        {"type": "aws_instance", "name": "web_server", "attributes": {...}}

    `attributes` is included in addition to the minimal {type, name} shape
    so the same parsed data can be reused by later phases (threat_engine)
    without re-parsing the file.

    Args:
        content: Raw Terraform/HCL2 source text (already decoded to str).

    Raises:
        TerraformParseError: if `content` is empty or is not valid HCL2.
    """
    if not content or not content.strip():
        raise TerraformParseError("File is empty.")

    try:
        parsed = hcl2.load(io.StringIO(content), serialization_options=_SERIALIZATION_OPTIONS)
    except LarkError as exc:
        raise TerraformParseError(f"Invalid Terraform/HCL2 syntax: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - surface any parser failure cleanly
        raise TerraformParseError(f"Failed to parse Terraform file: {exc}") from exc

    resources: list[dict[str, Any]] = []
    for block in parsed.get("resource", []):
        for resource_type, named in block.items():
            for resource_name, attributes in named.items():
                resources.append(
                    {
                        "type": resource_type,
                        "name": resource_name,
                        "attributes": attributes,
                    }
                )
    return resources
