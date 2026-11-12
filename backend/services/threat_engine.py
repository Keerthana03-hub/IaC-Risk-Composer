"""
services/threat_engine.py
--------------------------
Rule-based Threat Detection Engine for IaC Risk Composer (Step 3).

Analyzes parsed Terraform resources and infrastructure map (nodes/edges)
against reusable security threat templates to detect cloud misconfigurations.
"""

from __future__ import annotations

import json
from typing import Any

from services.threat_templates import THREAT_TEMPLATES, ThreatTemplate
from services.rules_cloudformation import analyze_cloudformation_threats
from services.rules_kubernetes import (
    WORKLOAD_KINDS,
    analyze_kubernetes_threats,
    detect_k8s_011_missing_network_policy,
)

# Standard sensitive services with typical ports
SENSITIVE_PORTS: dict[int, str] = {
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

PUBLIC_ACLS = {"public-read", "public-read-write", "website"}
UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}


# ---------------------------------------------------------------------------
# Rule Helpers
# ---------------------------------------------------------------------------


def _normalize_list(value: Any) -> list[Any]:
    """Ensure value is a flat list."""
    if value is None:
        return []
    if isinstance(value, list):
        items: list[Any] = []
        for item in value:
            if isinstance(item, list):
                items.extend(_normalize_list(item))
            else:
                items.append(item)
        return items
    return [value]


def _extract_cidrs(rule: dict[str, Any]) -> list[str]:
    """Extract all CIDR strings from a security group rule dict."""
    cidrs: list[str] = []
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        val = rule.get(key)
        for c in _normalize_list(val):
            if isinstance(c, str) and c.strip():
                cidrs.append(c.strip())
    return cidrs


def _get_unrestricted_cidrs(rule: dict[str, Any]) -> list[str]:
    """Return any unrestricted CIDRs (0.0.0.0/0 or ::/0) found in rule."""
    return [c for c in _extract_cidrs(rule) if c in UNRESTRICTED_CIDRS]


def _covers_port(rule: dict[str, Any], target_port: int) -> bool:
    """Check if rule permits inbound traffic to the specified target port."""
    protocol = str(rule.get("protocol", "")).lower()
    if protocol in ("-1", "all"):
        return True

    from_p = rule.get("from_port")
    to_p = rule.get("to_port")
    if from_p is None or to_p is None:
        return False

    try:
        from_int = int(from_p)
        to_int = int(to_p)
    except (ValueError, TypeError):
        return False

    # In AWS security groups, from_port=0, to_port=0 denotes all ports
    if from_int == 0 and to_int == 0:
        return True

    return from_int <= target_port <= to_int


def _covers_all_ports(rule: dict[str, Any]) -> bool:
    """Check if rule permits inbound traffic across all ports."""
    protocol = str(rule.get("protocol", "")).lower()
    if protocol in ("-1", "all"):
        return True

    from_p = rule.get("from_port")
    to_p = rule.get("to_port")
    if from_p is not None and to_p is not None:
        try:
            from_int = int(from_p)
            to_int = int(to_p)
            if (from_int == 0 and to_int == 0) or (from_int == 0 and to_int >= 65535):
                return True
        except (ValueError, TypeError):
            pass

    return False


def _normalize_ingress_rules(attributes: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract and flatten ingress rules from a security group's attributes."""
    ingress_raw = attributes.get("ingress")
    if not ingress_raw:
        return []

    rules: list[dict[str, Any]] = []
    for item in _normalize_list(ingress_raw):
        if isinstance(item, dict):
            rules.append(item)
    return rules


def _parse_policy_json(policy_val: Any) -> tuple[dict[str, Any] | None, bool]:
    """
    Safely parse IAM policy into a Python dictionary.

    Returns:
        (policy_dict, is_parse_error)
    """
    if isinstance(policy_val, dict):
        return policy_val, False

    if isinstance(policy_val, str):
        cleaned = policy_val.strip()
        # Handle heredoc formatting: <<EOF ... EOF or <<-EOF ... EOF
        if cleaned.startswith("<<"):
            lines = cleaned.splitlines()
            if len(lines) >= 3:
                cleaned = "\n".join(lines[1:-1]).strip()

        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return data, False
            return None, True
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None, True

    return None, False


def _is_wildcard(val: Any) -> bool:
    """Check if value is or contains wildcard '*'."""
    if val == "*":
        return True
    if isinstance(val, (list, tuple, set)):
        return "*" in val
    return False


# ---------------------------------------------------------------------------
# Individual Threat Detection Rules
# ---------------------------------------------------------------------------


def _detect_s3_threats(
    resource: dict[str, Any],
    resource_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    referenced_by: dict[str, list[dict[str, Any]]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate Threat 1 (Public Access) and Threat 5 (Storage Encryption) for S3."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attributes = resource.get("attributes", {}) or {}

    template_s3_pub = THREAT_TEMPLATES["THREAT-001"]
    template_enc = THREAT_TEMPLATES["THREAT-005"]

    # 1. aws_s3_bucket
    if res_type == "aws_s3_bucket":
        acl = attributes.get("acl")

        # Threat 1: Direct public ACL on bucket
        if isinstance(acl, str) and acl.lower() in PUBLIC_ACLS:
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-001-acl",
                    "threat_id": template_s3_pub.threat_id,
                    "title": f"Publicly Accessible S3 Bucket via ACL ({res_name})",
                    "description": template_s3_pub.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Critical" if acl.lower() == "public-read-write" else "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"acl": acl},
                    "impact": template_s3_pub.potential_impact,
                    "recommendation": template_s3_pub.recommended_mitigation,
                }
            )

        # Threat 1: Associated resources via infrastructure map edges
        for edge in referenced_by.get(resource_id, []):
            src_node = nodes_by_id.get(edge.get("source", ""))
            if not src_node:
                continue

            src_type = src_node.get("resource_type", "")
            src_attrs = src_node.get("attributes", {}) or {}

            # Connected aws_s3_bucket_acl
            if src_type == "aws_s3_bucket_acl":
                src_acl = src_attrs.get("acl")
                if isinstance(src_acl, str) and src_acl.lower() in PUBLIC_ACLS:
                    findings.append(
                        {
                            "finding_id": f"{resource_id}-THREAT-001-connected-acl",
                            "threat_id": template_s3_pub.threat_id,
                            "title": f"Publicly Accessible S3 Bucket via Attached ACL ({res_name})",
                            "description": template_s3_pub.description,
                            "affected_resource_id": resource_id,
                            "affected_resource_type": res_type,
                            "affected_resource_name": res_name,
                            "severity": "Critical" if src_acl.lower() == "public-read-write" else "High",
                            "detection_status": "Confirmed",
                            "confidence": "High",
                            "evidence": {
                                "acl_resource": src_node.get("id"),
                                "acl": src_acl,
                            },
                            "impact": template_s3_pub.potential_impact,
                            "recommendation": template_s3_pub.recommended_mitigation,
                        }
                    )

            # Connected aws_s3_bucket_public_access_block with disabled settings
            elif src_type == "aws_s3_bucket_public_access_block":
                disabled_flags = [
                    k
                    for k in (
                        "block_public_acls",
                        "block_public_policy",
                        "ignore_public_acls",
                        "restrict_public_buckets",
                    )
                    if src_attrs.get(k) is False or str(src_attrs.get(k)).lower() == "false"
                ]
                if disabled_flags:
                    findings.append(
                        {
                            "finding_id": f"{resource_id}-THREAT-001-disabled-pab",
                            "threat_id": template_s3_pub.threat_id,
                            "title": f"S3 Bucket Public Access Block Explicitly Disabled ({res_name})",
                            "description": template_s3_pub.description,
                            "affected_resource_id": resource_id,
                            "affected_resource_type": res_type,
                            "affected_resource_name": res_name,
                            "severity": "High",
                            "detection_status": "Confirmed",
                            "confidence": "High",
                            "evidence": {
                                "public_access_block_resource": src_node.get("id"),
                                "disabled_settings": disabled_flags,
                            },
                            "impact": template_s3_pub.potential_impact,
                            "recommendation": template_s3_pub.recommended_mitigation,
                        }
                    )

        # Threat 5: S3 Bucket Encryption
        has_sse = "server_side_encryption_configuration" in attributes
        if not has_sse:
            for edge in referenced_by.get(resource_id, []):
                src_node = nodes_by_id.get(edge.get("source", ""))
                if src_node and src_node.get("resource_type") == "aws_s3_bucket_server_side_encryption_configuration":
                    has_sse = True
                    break

        if not has_sse:
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-005-encryption",
                    "threat_id": template_enc.threat_id,
                    "title": f"S3 Bucket Server-Side Encryption Not Explicitly Configured ({res_name})",
                    "description": template_enc.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Medium",
                    "detection_status": "Needs Review",
                    "confidence": "Medium",
                    "evidence": {"server_side_encryption_configuration": "missing"},
                    "impact": template_enc.potential_impact,
                    "recommendation": template_enc.recommended_mitigation,
                }
            )

    # 2. Standalone aws_s3_bucket_public_access_block
    elif res_type == "aws_s3_bucket_public_access_block":
        disabled_flags = [
            k
            for k in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            )
            if attributes.get(k) is False or str(attributes.get(k)).lower() == "false"
        ]
        if disabled_flags:
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-001-disabled-block",
                    "threat_id": template_s3_pub.threat_id,
                    "title": f"S3 Public Access Block Explicitly Disabled ({res_name})",
                    "description": template_s3_pub.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"disabled_settings": disabled_flags},
                    "impact": template_s3_pub.potential_impact,
                    "recommendation": template_s3_pub.recommended_mitigation,
                }
            )

    # 3. Standalone aws_s3_bucket_acl
    elif res_type == "aws_s3_bucket_acl":
        acl = attributes.get("acl")
        if isinstance(acl, str) and acl.lower() in PUBLIC_ACLS:
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-001-acl",
                    "threat_id": template_s3_pub.threat_id,
                    "title": f"Public S3 Bucket ACL Defined ({res_name})",
                    "description": template_s3_pub.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Critical" if acl.lower() == "public-read-write" else "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"acl": acl},
                    "impact": template_s3_pub.potential_impact,
                    "recommendation": template_s3_pub.recommended_mitigation,
                }
            )


def _detect_security_group_threats(
    resource: dict[str, Any],
    resource_id: str,
    references_to: dict[str, list[dict[str, Any]]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate Threat 2 (Unrestricted SSH) and Threat 3 (Sensitive Ports) for security groups."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attributes = resource.get("attributes", {}) or {}

    template_ssh = THREAT_TEMPLATES["THREAT-002"]
    template_sensitive = THREAT_TEMPLATES["THREAT-003"]

    rules_to_check: list[dict[str, Any]] = []

    if res_type == "aws_security_group":
        rules_to_check = _normalize_ingress_rules(attributes)
    elif res_type == "aws_security_group_rule":
        rule_type = attributes.get("type")
        if str(rule_type).lower() == "ingress":
            rules_to_check = [attributes]

    if not rules_to_check:
        return

    for idx, rule in enumerate(rules_to_check):
        unrestricted_cidrs = _get_unrestricted_cidrs(rule)
        if not unrestricted_cidrs:
            continue

        protocol = rule.get("protocol", "tcp")
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        # Threat 2: SSH access on port 22
        if _covers_port(rule, 22):
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-002-ssh-{idx}",
                    "threat_id": template_ssh.threat_id,
                    "title": f"Unrestricted SSH Access on Port 22 ({res_name})",
                    "description": template_ssh.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "unrestricted_cidrs": unrestricted_cidrs,
                    },
                    "impact": template_ssh.potential_impact,
                    "recommendation": template_ssh.recommended_mitigation,
                }
            )

        # Threat 3: All ports unrestricted
        if _covers_all_ports(rule):
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-003-all-ports-{idx}",
                    "threat_id": template_sensitive.threat_id,
                    "title": f"Unrestricted Inbound Access to All Ports ({res_name})",
                    "description": "Security group rule allows unrestricted inbound access to all ports from 0.0.0.0/0 or ::/0.",
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Critical",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "unrestricted_cidrs": unrestricted_cidrs,
                    },
                    "impact": template_sensitive.potential_impact,
                    "recommendation": template_sensitive.recommended_mitigation,
                }
            )
        else:
            # Threat 3: Sensitive specific ports (RDP, DBs)
            for port, service in SENSITIVE_PORTS.items():
                if _covers_port(rule, port):
                    findings.append(
                        {
                            "finding_id": f"{resource_id}-THREAT-003-port-{port}-{idx}",
                            "threat_id": template_sensitive.threat_id,
                            "title": f"Unrestricted Inbound Access to {service} on Port {port} ({res_name})",
                            "description": f"Security group rule permits unrestricted ingress access to {service} on port {port} from {', '.join(unrestricted_cidrs)}.",
                            "affected_resource_id": resource_id,
                            "affected_resource_type": res_type,
                            "affected_resource_name": res_name,
                            "severity": "High",
                            "detection_status": "Confirmed",
                            "confidence": "High",
                            "evidence": {
                                "service": service,
                                "port": port,
                                "protocol": protocol,
                                "unrestricted_cidrs": unrestricted_cidrs,
                            },
                            "impact": template_sensitive.potential_impact,
                            "recommendation": template_sensitive.recommended_mitigation,
                        }
                    )


def _detect_database_threats(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate Threat 4 (Public DB) and Threat 5 (Storage Encryption) for databases."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attributes = resource.get("attributes", {}) or {}

    template_db_pub = THREAT_TEMPLATES["THREAT-004"]
    template_enc = THREAT_TEMPLATES["THREAT-005"]

    # Threat 4: Publicly accessible database
    publicly_accessible = attributes.get("publicly_accessible")
    if publicly_accessible is True or str(publicly_accessible).lower() == "true":
        findings.append(
            {
                "finding_id": f"{resource_id}-THREAT-004-public-db",
                "threat_id": template_db_pub.threat_id,
                "title": f"Publicly Accessible Database Instance ({res_name})",
                "description": template_db_pub.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"publicly_accessible": True},
                "impact": template_db_pub.potential_impact,
                "recommendation": template_db_pub.recommended_mitigation,
            }
        )

    # Threat 5: Storage encryption (for aws_db_instance)
    if res_type == "aws_db_instance":
        storage_encrypted = attributes.get("storage_encrypted")
        if storage_encrypted is False or str(storage_encrypted).lower() == "false":
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-005-db-unencrypted",
                    "threat_id": template_enc.threat_id,
                    "title": f"Database Storage Encryption Explicitly Disabled ({res_name})",
                    "description": template_enc.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"storage_encrypted": False},
                    "impact": template_enc.potential_impact,
                    "recommendation": template_enc.recommended_mitigation,
                }
            )
        elif storage_encrypted is None:
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-005-db-encryption-missing",
                    "threat_id": template_enc.threat_id,
                    "title": f"Database Storage Encryption Not Explicitly Configured ({res_name})",
                    "description": template_enc.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Medium",
                    "detection_status": "Needs Review",
                    "confidence": "Medium",
                    "evidence": {"storage_encrypted": "missing"},
                    "impact": template_enc.potential_impact,
                    "recommendation": template_enc.recommended_mitigation,
                }
            )


def _detect_ebs_threats(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate Threat 5 (Storage Encryption) for EBS volumes."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attributes = resource.get("attributes", {}) or {}

    template_enc = THREAT_TEMPLATES["THREAT-005"]
    encrypted = attributes.get("encrypted")

    if encrypted is False or str(encrypted).lower() == "false":
        findings.append(
            {
                "finding_id": f"{resource_id}-THREAT-005-ebs-unencrypted",
                "threat_id": template_enc.threat_id,
                "title": f"EBS Volume Storage Encryption Explicitly Disabled ({res_name})",
                "description": template_enc.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"encrypted": False},
                "impact": template_enc.potential_impact,
                "recommendation": template_enc.recommended_mitigation,
            }
        )
    elif encrypted is None:
        findings.append(
            {
                "finding_id": f"{resource_id}-THREAT-005-ebs-encryption-missing",
                "threat_id": template_enc.threat_id,
                "title": f"EBS Volume Storage Encryption Not Explicitly Configured ({res_name})",
                "description": template_enc.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "severity": "Medium",
                "detection_status": "Needs Review",
                "confidence": "Medium",
                "evidence": {"encrypted": "missing"},
                "impact": template_enc.potential_impact,
                "recommendation": template_enc.recommended_mitigation,
            }
        )


def _detect_iam_threats(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate Threat 6 (Overly Permissive IAM Policy) for IAM policies."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attributes = resource.get("attributes", {}) or {}

    template_iam = THREAT_TEMPLATES["THREAT-006"]

    # Extract policy attribute
    policy_val = attributes.get("policy")
    if policy_val is None and res_type == "aws_iam_policy_document":
        policy_val = attributes.get("statement")

    if policy_val is None:
        return

    policy_dict, is_parse_error = _parse_policy_json(policy_val)

    if is_parse_error:
        preview = str(policy_val)[:200]
        findings.append(
            {
                "finding_id": f"{resource_id}-THREAT-006-parse-review",
                "threat_id": template_iam.threat_id,
                "title": f"IAM Policy Requires Review – Non-standard or Dynamic Policy ({res_name})",
                "description": (
                    "IAM policy content could not be parsed as static JSON (may use string "
                    "interpolation or complex functions). Manual security review recommended."
                ),
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "severity": "Medium",
                "detection_status": "Needs Review",
                "confidence": "Low",
                "evidence": {"raw_policy_preview": preview},
                "impact": template_iam.potential_impact,
                "recommendation": template_iam.recommended_mitigation,
            }
        )
        return

    if not policy_dict:
        return

    statements = policy_dict.get("Statement") or policy_dict.get("statement")
    if not statements:
        return

    for idx, stmt in enumerate(_normalize_list(statements)):
        if not isinstance(stmt, dict):
            continue

        effect = str(stmt.get("Effect", "")).lower()
        if effect != "allow":
            continue

        action = stmt.get("Action")
        resource_target = stmt.get("Resource")

        # Overly permissive administrative policy: Action = * and Resource = *
        if _is_wildcard(action) and _is_wildcard(resource_target):
            findings.append(
                {
                    "finding_id": f"{resource_id}-THREAT-006-wildcard-{idx}",
                    "threat_id": template_iam.threat_id,
                    "title": f"IAM Policy Grants Full Administrative Access (*:*) ({res_name})",
                    "description": template_iam.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "severity": "Critical",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {
                        "statement": stmt,
                    },
                    "impact": template_iam.potential_impact,
                    "recommendation": template_iam.recommended_mitigation,
                }
            )


# ---------------------------------------------------------------------------
# Main Public Engine Function
# ---------------------------------------------------------------------------


def analyze_threats(
    resources: list[dict[str, Any]],
    infrastructure_map: dict[str, Any] | None = None,
    source_format: str | None = None,
    normalized_infrastructure: Any = None,
) -> list[dict[str, Any]]:
    """
    Analyze parsed IaC resources (Terraform, CloudFormation, Kubernetes) and
    infrastructure map using standardized security threat templates.

    Args:
        resources: Flat list of parsed resources shaped like
                   {"type": ..., "name": ..., "attributes": {...}} or NormalizedResource instances.
        infrastructure_map: Infrastructure graph shaped like {"nodes": [...], "edges": [...]}.
        source_format: Optional source format ('terraform', 'cloudformation', 'kubernetes').
        normalized_infrastructure: Optional NormalizedInfrastructure container.

    Returns:
        List of structured, format-grounded threat finding dictionaries.
    """
    if not resources:
        return []

    infra_map = infrastructure_map or {}
    nodes = infra_map.get("nodes", [])
    edges = infra_map.get("edges", [])

    nodes_by_id: dict[str, dict[str, Any]] = {
        node["id"]: node for node in nodes if isinstance(node, dict) and "id" in node
    }

    referenced_by: dict[str, list[dict[str, Any]]] = {}
    references_to: dict[str, list[dict[str, Any]]] = {}

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = edge.get("source")
        tgt = edge.get("target")
        if src and tgt:
            references_to.setdefault(src, []).append(edge)
            referenced_by.setdefault(tgt, []).append(edge)

    findings: list[dict[str, Any]] = []
    has_k8s_resources = False

    for resource in resources:
        res_type = resource.get("type", "")
        res_name = resource.get("name", "")
        attrs = resource.get("attributes", {}) or {}

        # Determine source format for this resource
        res_fmt = source_format or getattr(resource, "source_format", None)
        if not res_fmt:
            if res_type.startswith("AWS::") or res_type.startswith("Custom::"):
                res_fmt = "cloudformation"
            elif (
                res_type in WORKLOAD_KINDS
                or res_type in (
                    "Service", "Ingress", "ConfigMap", "Secret", "ServiceAccount",
                    "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
                    "NetworkPolicy", "PersistentVolume", "PersistentVolumeClaim", "Namespace",
                )
                or "security_metadata" in attrs
                or "_metadata" in attrs
            ):
                res_fmt = "kubernetes"
            else:
                res_fmt = "terraform"

        # Determine stable resource ID
        if res_fmt == "kubernetes":
            meta = attrs.get("_metadata", {}) or {}
            ns = meta.get("namespace")
            if ns and res_type not in ("ClusterRole", "ClusterRoleBinding", "PersistentVolume", "Namespace"):
                resource_id = f"{res_type}.{ns}.{res_name}"
            else:
                resource_id = resource.get("id") or f"{res_type}.{res_name}"
        else:
            resource_id = resource.get("id") or f"{res_type}.{res_name}"

        # ── CloudFormation Threat Evaluation ──────────────────────────────
        if res_fmt == "cloudformation" or res_type.startswith("AWS::"):
            analyze_cloudformation_threats(
                resource,
                resource_id,
                nodes_by_id,
                referenced_by,
                findings,
            )

        # ── Kubernetes Threat Evaluation ──────────────────────────────────
        elif res_fmt == "kubernetes" or res_type in WORKLOAD_KINDS or res_type in (
            "Service", "Ingress", "Role", "ClusterRole", "ServiceAccount", "NetworkPolicy",
        ):
            has_k8s_resources = True
            analyze_kubernetes_threats(
                resource,
                resource_id,
                findings,
            )

        # ── Terraform Threat Evaluation ───────────────────────────────────
        else:
            # 1. S3 Threat Evaluation (Threat 1, Threat 5)
            if res_type in (
                "aws_s3_bucket",
                "aws_s3_bucket_public_access_block",
                "aws_s3_bucket_acl",
                "aws_s3_bucket_policy",
            ):
                _detect_s3_threats(
                    resource,
                    resource_id,
                    nodes_by_id,
                    referenced_by,
                    findings,
                )

            # 2. Security Group Threat Evaluation (Threat 2, Threat 3)
            elif res_type in ("aws_security_group", "aws_security_group_rule"):
                _detect_security_group_threats(
                    resource,
                    resource_id,
                    references_to,
                    findings,
                )

            # 3. Database Threat Evaluation (Threat 4, Threat 5)
            elif res_type in ("aws_db_instance", "aws_rds_cluster", "aws_redshift_cluster"):
                _detect_database_threats(
                    resource,
                    resource_id,
                    findings,
                )

            # 4. EBS Volume Threat Evaluation (Threat 5)
            elif res_type == "aws_ebs_volume":
                _detect_ebs_threats(
                    resource,
                    resource_id,
                    findings,
                )

            # 5. IAM Policy Threat Evaluation (Threat 6)
            elif res_type in (
                "aws_iam_policy",
                "aws_iam_role_policy",
                "aws_iam_policy_document",
            ):
                _detect_iam_threats(
                    resource,
                    resource_id,
                    findings,
                )

    # Cross-resource rule for Kubernetes manifests: Missing NetworkPolicy
    if has_k8s_resources or source_format == "kubernetes":
        detect_k8s_011_missing_network_policy(resources, findings)

    # Standardize finding fields across all IaC formats
    for f in findings:
        if "resource_id" not in f:
            f["resource_id"] = f.get("affected_resource_id", "")
        if "resource_type" not in f:
            f["resource_type"] = f.get("affected_resource_type", "")
        if "source_format" not in f:
            f["source_format"] = source_format or "terraform"
        if "remediation" not in f:
            f["remediation"] = f.get("recommendation", "")
        if "references" not in f:
            f["references"] = []

    return findings
