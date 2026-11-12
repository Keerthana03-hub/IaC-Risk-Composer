"""
services/rules_cloudformation.py
---------------------------------
CloudFormation Security Threat Detection Rules (Stage 5).

Implements security inspection rules for AWS CloudFormation templates:
- CFN-001: Public S3 Bucket Exposure (ACL, BucketPolicy, PublicAccessBlock)
- CFN-002: Missing S3 Server-Side Encryption
- CFN-003: Overly Permissive IAM Policy (Action: *, Resource: *)
- CFN-004: Publicly Accessible EC2 Security Group (0.0.0.0/0, ::/0, SSH 22, RDP 3389)
- CFN-005: Unencrypted EBS Storage Volume
- CFN-006: Insecure Lambda Configuration (Tracing, Public Function URL)
"""

from __future__ import annotations

import json
from typing import Any

from services.threat_templates import THREAT_TEMPLATES

UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_ACLS = {"publicread", "publicreadwrite", "authenticatedread"}
SENSITIVE_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def _is_wildcard(val: Any) -> bool:
    """Check if value is or contains wildcard '*'."""
    if val == "*":
        return True
    if isinstance(val, (list, tuple, set)):
        return "*" in val
    return False


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


# ---------------------------------------------------------------------------
# CFN-001: Public S3 Bucket Exposure
# ---------------------------------------------------------------------------


def detect_cfn_001_s3_public_access(
    resource: dict[str, Any],
    resource_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    referenced_by: dict[str, list[dict[str, Any]]],
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-001 for AWS::S3::Bucket and AWS::S3::BucketPolicy."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-001"]

    if res_type == "AWS::S3::Bucket":
        # Check AccessControl property
        acl = attrs.get("AccessControl")
        if isinstance(acl, str):
            acl_clean = acl.replace("-", "").replace("_", "").lower()
            if acl_clean in PUBLIC_ACLS:
                is_crit = "write" in acl_clean
                findings.append({
                    "finding_id": f"{resource_id}-CFN-001-acl",
                    "threat_id": template.threat_id,
                    "title": f"CloudFormation S3 Bucket Public ACL Configured ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "cloudformation",
                    "severity": "Critical" if is_crit else "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"AccessControl": acl},
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-accesscontrol"
                    ],
                })

        # Check PublicAccessBlockConfiguration
        pab = attrs.get("PublicAccessBlockConfiguration")
        if isinstance(pab, dict):
            disabled_flags = [
                k for k in (
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                )
                if pab.get(k) is False or str(pab.get(k)).lower() == "false"
            ]
            if disabled_flags:
                findings.append({
                    "finding_id": f"{resource_id}-CFN-001-pab-disabled",
                    "threat_id": template.threat_id,
                    "title": f"CloudFormation S3 Bucket Public Access Block Explicitly Disabled ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "cloudformation",
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"disabled_settings": disabled_flags},
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html"
                    ],
                })

    elif res_type == "AWS::S3::BucketPolicy":
        policy_doc = attrs.get("PolicyDocument")
        if isinstance(policy_doc, dict):
            statements = _normalize_list(policy_doc.get("Statement"))
            for idx, stmt in enumerate(statements):
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get("Effect", "")).lower() != "allow":
                    continue

                principal = stmt.get("Principal")
                is_public_principal = False
                if principal == "*":
                    is_public_principal = True
                elif isinstance(principal, dict) and principal.get("AWS") == "*":
                    is_public_principal = True

                if is_public_principal:
                    findings.append({
                        "finding_id": f"{resource_id}-CFN-001-policy-{idx}",
                        "threat_id": template.threat_id,
                        "title": f"CloudFormation S3 Bucket Policy Grants Public Anonymous Access ({res_name})",
                        "description": template.description,
                        "affected_resource_id": resource_id,
                        "affected_resource_type": res_type,
                        "affected_resource_name": res_name,
                        "resource_id": resource_id,
                        "resource_type": res_type,
                        "source_format": "cloudformation",
                        "severity": "Critical",
                        "detection_status": "Confirmed",
                        "confidence": "High",
                        "evidence": {"statement": stmt},
                        "impact": template.potential_impact,
                        "recommendation": template.recommended_mitigation,
                        "remediation": template.recommended_mitigation,
                        "references": [
                            "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html"
                        ],
                    })


# ---------------------------------------------------------------------------
# CFN-002: Missing S3 Server-Side Encryption
# ---------------------------------------------------------------------------


def detect_cfn_002_s3_encryption(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-002 for AWS::S3::Bucket."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-002"]

    if res_type != "AWS::S3::Bucket":
        return

    bucket_enc = attrs.get("BucketEncryption")
    has_encryption = False

    if isinstance(bucket_enc, dict):
        rules = bucket_enc.get("ServerSideEncryptionConfiguration")
        if isinstance(rules, list) and len(rules) > 0:
            for r in rules:
                if isinstance(r, dict) and "ServerSideEncryptionByDefault" in r:
                    has_encryption = True
                    break

    if not has_encryption:
        findings.append({
            "finding_id": f"{resource_id}-CFN-002-encryption",
            "threat_id": template.threat_id,
            "title": f"CloudFormation S3 Bucket Server-Side Encryption Not Explicitly Configured ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "cloudformation",
            "severity": "Medium",
            "detection_status": "Needs Review",
            "confidence": "Medium",
            "evidence": {"BucketEncryption": "missing"},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-bucketencryption.html"
            ],
        })


# ---------------------------------------------------------------------------
# CFN-003: Overly Permissive IAM Policy
# ---------------------------------------------------------------------------


def detect_cfn_003_iam_wildcards(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-003 for AWS::IAM::Policy, AWS::IAM::Role, AWS::IAM::ManagedPolicy."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-003"]

    policy_docs: list[dict[str, Any]] = []

    # PolicyDocument on Policy or ManagedPolicy
    if isinstance(attrs.get("PolicyDocument"), dict):
        policy_docs.append(attrs["PolicyDocument"])

    # Policies list on Role or User or Group
    policies_list = attrs.get("Policies")
    if isinstance(policies_list, list):
        for pol in policies_list:
            if isinstance(pol, dict) and isinstance(pol.get("PolicyDocument"), dict):
                policy_docs.append(pol["PolicyDocument"])

    for p_idx, doc in enumerate(policy_docs):
        statements = _normalize_list(doc.get("Statement"))
        for s_idx, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).lower() != "allow":
                continue

            action = stmt.get("Action")
            resource_target = stmt.get("Resource")

            if _is_wildcard(action) and _is_wildcard(resource_target):
                findings.append({
                    "finding_id": f"{resource_id}-CFN-003-wildcard-{p_idx}-{s_idx}",
                    "threat_id": template.threat_id,
                    "title": f"CloudFormation IAM Policy Grants Full Administrative Access (*:*) ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "cloudformation",
                    "severity": "Critical",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"statement": stmt},
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                    ],
                })
            elif _is_wildcard(action):
                findings.append({
                    "finding_id": f"{resource_id}-CFN-003-broad-action-{p_idx}-{s_idx}",
                    "threat_id": template.threat_id,
                    "title": f"CloudFormation IAM Policy Grants Wildcard Action on Resources ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "cloudformation",
                    "severity": "High",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"statement": stmt},
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                    ],
                })


# ---------------------------------------------------------------------------
# CFN-004: Publicly Accessible EC2 Security Group
# ---------------------------------------------------------------------------


def detect_cfn_004_security_group_ingress(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-004 for AWS::EC2::SecurityGroup and AWS::EC2::SecurityGroupIngress."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-004"]

    rules_to_check: list[dict[str, Any]] = []

    if res_type == "AWS::EC2::SecurityGroup":
        ingress_list = attrs.get("SecurityGroupIngress")
        if isinstance(ingress_list, list):
            rules_to_check.extend([r for r in ingress_list if isinstance(r, dict)])
    elif res_type == "AWS::EC2::SecurityGroupIngress":
        rules_to_check.append(attrs)

    for idx, rule in enumerate(rules_to_check):
        unrestricted: list[str] = []
        cidr_ip = rule.get("CidrIp")
        cidr_ipv6 = rule.get("CidrIpv6")

        if isinstance(cidr_ip, str) and cidr_ip.strip() in UNRESTRICTED_CIDRS:
            unrestricted.append(cidr_ip.strip())
        if isinstance(cidr_ipv6, str) and cidr_ipv6.strip() in UNRESTRICTED_CIDRS:
            unrestricted.append(cidr_ipv6.strip())

        if not unrestricted:
            continue

        ip_protocol = str(rule.get("IpProtocol", "tcp")).lower()
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        is_all_ports = ip_protocol in ("-1", "all") or (
            from_port == 0 and (to_port == 0 or to_port == 65535 or to_port is None)
        )

        is_admin_port = False
        port_label = "all ports" if is_all_ports else ""

        if not is_all_ports and from_port is not None and to_port is not None:
            try:
                fp = int(from_port)
                tp = int(to_port)
                for p, s in SENSITIVE_ADMIN_PORTS.items():
                    if fp <= p <= tp:
                        is_admin_port = True
                        port_label = f"{s} (port {p})"
                        break
                if not port_label:
                    port_label = f"port {fp}" if fp == tp else f"ports {fp}-{tp}"
            except (ValueError, TypeError):
                port_label = "unknown ports"

        is_critical = is_admin_port or is_all_ports
        severity = "Critical" if is_critical else "High"
        title = (
            f"CloudFormation Security Group Ingress Exposes Administrative {port_label} to Internet ({res_name})"
            if is_admin_port
            else f"CloudFormation Security Group Allows Unrestricted Ingress to {port_label} ({res_name})"
        )

        findings.append({
            "finding_id": f"{resource_id}-CFN-004-ingress-{idx}",
            "threat_id": template.threat_id,
            "title": title,
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "cloudformation",
            "severity": severity,
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {
                "unrestricted_cidrs": unrestricted,
                "protocol": ip_protocol,
                "from_port": from_port,
                "to_port": to_port,
            },
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
            ],
        })


# ---------------------------------------------------------------------------
# CFN-005: Unencrypted EBS Storage Volume
# ---------------------------------------------------------------------------


def detect_cfn_005_ebs_encryption(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-005 for AWS::EC2::Volume."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-005"]

    if res_type != "AWS::EC2::Volume":
        return

    encrypted = attrs.get("Encrypted")

    if encrypted is False or str(encrypted).lower() == "false":
        findings.append({
            "finding_id": f"{resource_id}-CFN-005-ebs-unencrypted",
            "threat_id": template.threat_id,
            "title": f"CloudFormation EBS Volume Encryption Explicitly Disabled ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "cloudformation",
            "severity": "High",
            "detection_status": "Confirmed",
            "confidence": "High",
            "evidence": {"Encrypted": False},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
            ],
        })
    elif encrypted is None:
        findings.append({
            "finding_id": f"{resource_id}-CFN-005-ebs-missing",
            "threat_id": template.threat_id,
            "title": f"CloudFormation EBS Volume Encryption Not Explicitly Configured ({res_name})",
            "description": template.description,
            "affected_resource_id": resource_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "resource_id": resource_id,
            "resource_type": res_type,
            "source_format": "cloudformation",
            "severity": "Medium",
            "detection_status": "Needs Review",
            "confidence": "Medium",
            "evidence": {"Encrypted": "missing"},
            "impact": template.potential_impact,
            "recommendation": template.recommended_mitigation,
            "remediation": template.recommended_mitigation,
            "references": [
                "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html"
            ],
        })


# ---------------------------------------------------------------------------
# CFN-006: Insecure Lambda Configuration
# ---------------------------------------------------------------------------


def detect_cfn_006_lambda_config(
    resource: dict[str, Any],
    resource_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Evaluate CFN-006 for AWS::Lambda::Function and AWS::Lambda::Url."""
    res_type = resource.get("type", "")
    res_name = resource.get("name", "")
    attrs = resource.get("attributes", {}) or {}
    template = THREAT_TEMPLATES["CFN-006"]

    if res_type == "AWS::Lambda::Function":
        tracing_cfg = attrs.get("TracingConfig")
        if isinstance(tracing_cfg, dict):
            mode = str(tracing_cfg.get("Mode", "")).lower()
            if mode == "passthrough":
                findings.append({
                    "finding_id": f"{resource_id}-CFN-006-tracing-passthrough",
                    "threat_id": template.threat_id,
                    "title": f"CloudFormation Lambda Active Tracing Not Enabled (PassThrough Mode) ({res_name})",
                    "description": template.description,
                    "affected_resource_id": resource_id,
                    "affected_resource_type": res_type,
                    "affected_resource_name": res_name,
                    "resource_id": resource_id,
                    "resource_type": res_type,
                    "source_format": "cloudformation",
                    "severity": "Medium",
                    "detection_status": "Confirmed",
                    "confidence": "High",
                    "evidence": {"TracingConfig": {"Mode": "PassThrough"}},
                    "impact": template.potential_impact,
                    "recommendation": template.recommended_mitigation,
                    "remediation": template.recommended_mitigation,
                    "references": [
                        "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-tracingconfig.html"
                    ],
                })
        elif tracing_cfg is None:
            findings.append({
                "finding_id": f"{resource_id}-CFN-006-tracing-missing",
                "threat_id": template.threat_id,
                "title": f"CloudFormation Lambda Tracing Configuration Omitted ({res_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "cloudformation",
                "severity": "Medium",
                "detection_status": "Needs Review",
                "confidence": "Low",
                "evidence": {"TracingConfig": "missing"},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-tracingconfig.html"
                ],
            })

    elif res_type == "AWS::Lambda::Url":
        auth_type = str(attrs.get("AuthType", "")).upper()
        if auth_type == "NONE":
            findings.append({
                "finding_id": f"{resource_id}-CFN-006-public-url-none",
                "threat_id": template.threat_id,
                "title": f"CloudFormation Lambda Function URL Configured Without Authentication (NONE) ({res_name})",
                "description": template.description,
                "affected_resource_id": resource_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "resource_id": resource_id,
                "resource_type": res_type,
                "source_format": "cloudformation",
                "severity": "High",
                "detection_status": "Confirmed",
                "confidence": "High",
                "evidence": {"AuthType": "NONE"},
                "impact": template.potential_impact,
                "recommendation": template.recommended_mitigation,
                "remediation": template.recommended_mitigation,
                "references": [
                    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-url.html"
                ],
            })


# ---------------------------------------------------------------------------
# Master CloudFormation Threat Evaluation Entry Point
# ---------------------------------------------------------------------------


def analyze_cloudformation_threats(
    resource: dict[str, Any],
    resource_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    referenced_by: dict[str, list[dict[str, Any]]],
    findings: list[dict[str, Any]],
) -> None:
    """Dispatch CloudFormation resource to appropriate rule evaluations."""
    res_type = resource.get("type", "")

    # 1. S3 Threat Evaluation (CFN-001, CFN-002)
    if res_type in ("AWS::S3::Bucket", "AWS::S3::BucketPolicy"):
        detect_cfn_001_s3_public_access(resource, resource_id, nodes_by_id, referenced_by, findings)
        if res_type == "AWS::S3::Bucket":
            detect_cfn_002_s3_encryption(resource, resource_id, findings)

    # 2. IAM Threat Evaluation (CFN-003)
    elif res_type in ("AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy", "AWS::IAM::Group"):
        detect_cfn_003_iam_wildcards(resource, resource_id, findings)

    # 3. Security Group Threat Evaluation (CFN-004)
    elif res_type in ("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"):
        detect_cfn_004_security_group_ingress(resource, resource_id, findings)

    # 4. EBS Threat Evaluation (CFN-005)
    elif res_type == "AWS::EC2::Volume":
        detect_cfn_005_ebs_encryption(resource, resource_id, findings)

    # 5. Lambda Threat Evaluation (CFN-006)
    elif res_type in ("AWS::Lambda::Function", "AWS::Lambda::Url"):
        detect_cfn_006_lambda_config(resource, resource_id, findings)
