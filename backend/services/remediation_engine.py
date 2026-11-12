"""
services/remediation_engine.py
-------------------------------
Security Recommendations and Safe Terraform Fix Generation (Step 6).

Generates actionable remediation recommendations and safe, deterministic
Terraform code suggestions for detected threat findings.

Safety Principles:
------------------
1. Never modifies or overwrites user Terraform files.
2. Never invents resource names, KMS ARNs, account IDs, or provider configurations.
3. Suggests code only for explicitly supported patterns (e.g., S3 server-side
   encryption via aws_s3_bucket_server_side_encryption_configuration).
4. Unsupported or ambiguous findings default safely to manual guidance without code.
5. Needs Review / Provisional findings remain explicitly non-final.
6. Modular provider design enables future AI/LLM integration (e.g. IBM watsonx.ai)
   while currently executing deterministic rule-based logic.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any


# ---------------------------------------------------------------------------
# Identifier Sanitization Helpers
# ---------------------------------------------------------------------------


def _sanitize_identifier(name: str) -> str:
    """
    Sanitize an untrusted resource name into a valid Terraform identifier.

    Terraform identifiers contain letters, digits, underscores, and dashes,
    and must not start with a digit.
    """
    if not name:
        return "s3_bucket"
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", str(name).strip())
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"res_{cleaned}"
    return cleaned


def _resolve_unique_label(base_name: str, existing_names: set[str]) -> str:
    """Ensure the remediation resource label is unique to avoid syntax collisions."""
    candidate = f"{base_name}_sse"
    if candidate not in existing_names:
        existing_names.add(candidate)
        return candidate

    counter = 2
    while f"{candidate}_{counter}" in existing_names:
        counter += 1
    chosen = f"{candidate}_{counter}"
    existing_names.add(chosen)
    return chosen


# ---------------------------------------------------------------------------
# Abstract Remediation Provider Interface
# ---------------------------------------------------------------------------


class BaseRemediationProvider(ABC):
    """
    Abstract interface for remediation generators.

    Allows plugging in deterministic rule-based generators today, or an
    authorized LLM provider (e.g., IBM watsonx.ai) in the future.
    """

    @abstractmethod
    def generate(
        self,
        finding: dict[str, Any],
        resources: list[dict[str, Any]],
        existing_labels: set[str],
    ) -> dict[str, Any]:
        """Generate a remediation recommendation for a single finding."""
        pass


# ---------------------------------------------------------------------------
# Deterministic Rule-Based Remediation Provider
# ---------------------------------------------------------------------------


class RuleBasedRemediationProvider(BaseRemediationProvider):
    """
    Deterministic remediation engine.

    Generates safe code patches only when complete, unambiguous resource
    context exists. Never invents ARNs, KMS keys, or unsupported attributes.
    """

    def generate(
        self,
        finding: dict[str, Any],
        resources: list[dict[str, Any]],
        existing_labels: set[str],
    ) -> dict[str, Any]:
        finding_id = str(finding.get("finding_id", ""))
        threat_id = str(finding.get("threat_id", ""))
        res_type = str(finding.get("affected_resource_type", ""))
        res_name = str(finding.get("affected_resource_name", ""))
        res_id = str(finding.get("affected_resource_id", ""))
        detection_status = str(finding.get("detection_status", "")).strip()
        risk_assessment = finding.get("risk_assessment") or {}
        assessment_status = str(risk_assessment.get("assessment_status", "")).strip()

        is_provisional = (
            detection_status == "Needs Review" or assessment_status == "Provisional"
        )

        remediation_id = f"rem-{finding_id}" if finding_id else "rem-unknown"
        remediation_status = "Needs Review" if is_provisional else "Suggested"

        # ── S3 Missing Encryption (THREAT-005 on aws_s3_bucket) ────────────
        if threat_id == "THREAT-005" and res_type == "aws_s3_bucket":
            return self._remediate_s3_encryption(
                finding=finding,
                finding_id=finding_id,
                remediation_id=remediation_id,
                res_id=res_id,
                res_type=res_type,
                res_name=res_name,
                resources=resources,
                existing_labels=existing_labels,
                is_provisional=is_provisional,
                remediation_status=remediation_status,
            )

        # ── Unsupported or Manual-Only Threat Types ────────────────────────
        return self._remediate_unsupported(
            finding=finding,
            finding_id=finding_id,
            remediation_id=remediation_id,
            res_id=res_id,
            res_type=res_type,
            res_name=res_name,
            is_provisional=is_provisional,
            remediation_status=remediation_status,
        )

    # ── S3 Server-Side Encryption Patch Generator ──────────────────────────

    def _remediate_s3_encryption(
        self,
        finding: dict[str, Any],
        finding_id: str,
        remediation_id: str,
        res_id: str,
        res_type: str,
        res_name: str,
        resources: list[dict[str, Any]],
        existing_labels: set[str],
        is_provisional: bool,
        remediation_status: str,
    ) -> dict[str, Any]:
        title = f"Enable Default Server-Side Encryption for {res_id}"

        # 1. Validate that the bucket resource is actually present in parsed input
        bucket_found = False
        has_existing_sse = False

        for r in resources:
            if not isinstance(r, dict):
                continue
            r_type = r.get("type", "")
            r_name = r.get("name", "")
            r_attrs = r.get("attributes", {}) or {}

            if r_type == "aws_s3_bucket" and r_name == res_name:
                bucket_found = True
                if "server_side_encryption_configuration" in r_attrs:
                    has_existing_sse = True

            # Check if separate SSE resource already exists for this bucket
            if r_type == "aws_s3_bucket_server_side_encryption_configuration":
                bucket_ref = str(r_attrs.get("bucket", ""))
                if res_name in bucket_ref:
                    has_existing_sse = True

        # Safety Check A: Resource name is empty or bucket not found
        if not res_name or not bucket_found:
            return {
                "remediation_id": remediation_id,
                "finding_id": finding_id,
                "affected_resource_id": res_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "title": title,
                "explanation": (
                    "Sufficient resource context could not be safely verified in the parsed "
                    "Terraform configuration. Automatic code patch generation was omitted to prevent invalid syntax."
                ),
                "recommended_actions": [
                    "Locate the target S3 bucket in your Terraform configuration.",
                    "Declare an 'aws_s3_bucket_server_side_encryption_configuration' resource referencing the bucket.",
                ],
                "suggested_code": None,
                "patch_type": "manual",
                "assumptions": [
                    "Target bucket definition could not be resolved in the uploaded Terraform file."
                ],
                "validation_steps": [
                    "Verify the S3 bucket declaration in your Terraform codebase.",
                    "Consult AWS documentation for declaring server-side encryption configuration.",
                ],
                "remediation_status": remediation_status,
                "generated_by": "rule_based",
            }

        # Safety Check B: Equivalent encryption configuration already exists
        if has_existing_sse:
            return {
                "remediation_id": remediation_id,
                "finding_id": finding_id,
                "affected_resource_id": res_id,
                "affected_resource_type": res_type,
                "affected_resource_name": res_name,
                "title": title,
                "explanation": (
                    "An equivalent server-side encryption configuration already appears to be declared "
                    f"in the Terraform file for {res_id}. No duplicate resource was generated."
                ),
                "recommended_actions": [
                    "Review the existing encryption configuration block to ensure it covers all required bucket objects.",
                ],
                "suggested_code": None,
                "patch_type": "manual",
                "assumptions": [
                    "Existing configuration handles server-side encryption."
                ],
                "validation_steps": [
                    "Run 'terraform plan' to confirm that encryption settings are applied.",
                ],
                "remediation_status": "Needs Review",
                "generated_by": "rule_based",
            }

        # Safe Patch Generation: Derive deterministic sanitized identifier
        sanitized_name = _sanitize_identifier(res_name)
        remediation_label = _resolve_unique_label(sanitized_name, existing_labels)

        # Minimal safe example using standard AWS-managed AES256 (SSE-S3)
        # Note: Never invents a customer KMS ARN.
        suggested_code = (
            f'resource "aws_s3_bucket_server_side_encryption_configuration" "{remediation_label}" {{\n'
            f'  bucket = aws_s3_bucket.{res_name}.id\n\n'
            f'  rule {{\n'
            f'    apply_server_side_encryption_by_default {{\n'
            f'      sse_algorithm = "AES256"\n'
            f'    }}\n'
            f'  }}\n'
            f'}}'
        )

        explanation = (
            "Suggested safe Terraform addition: declares a dedicated server-side encryption "
            f"configuration for aws_s3_bucket.{res_name} using AWS-managed AES256 (SSE-S3). "
            "This suggestion requires review and does not modify your original file. "
            "If your organization enforces KMS-managed encryption, replace AES256 with aws:kms "
            "and specify your designated KMS key ID."
        )

        return {
            "remediation_id": remediation_id,
            "finding_id": finding_id,
            "affected_resource_id": res_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "title": title,
            "explanation": explanation,
            "recommended_actions": [
                f"Add the suggested 'aws_s3_bucket_server_side_encryption_configuration.{remediation_label}' resource to your Terraform project.",
                "If customer-managed KMS keys are mandated by your security baseline, update 'sse_algorithm' to 'aws:kms' and add 'kms_master_key_id'.",
            ],
            "suggested_code": suggested_code,
            "patch_type": "addition",
            "assumptions": [
                "Assumes AWS-managed AES256 (SSE-S3) satisfies at-rest data encryption requirements.",
                "Assumes customer-managed KMS keys are not mandatory for this workload.",
                "Suggestion does not confirm a runtime vulnerability; runtime account defaults may already encrypt S3 objects.",
            ],
            "validation_steps": [
                "Review the suggested resource against project architectural standards.",
                "Run `terraform plan` to verify that the planned addition does not replace or disrupt existing infrastructure.",
                "After deployment, verify encryption status using: `aws s3api get-bucket-encryption --bucket <bucket-name>`.",
            ],
            "remediation_status": remediation_status,
            "generated_by": "rule_based",
        }

    # ── Unsupported Threat Types (Manual Guidance Only) ────────────────────

    def _remediate_unsupported(
        self,
        finding: dict[str, Any],
        finding_id: str,
        remediation_id: str,
        res_id: str,
        res_type: str,
        res_name: str,
        is_provisional: bool,
        remediation_status: str,
    ) -> dict[str, Any]:
        threat_id = finding.get("threat_id", "")
        finding_title = finding.get("title", "Security Threat")
        raw_recommendation = str(finding.get("recommendation", "")).strip()

        suggested_code: str | None = None
        patch_type: str = "manual"

        # Provide tailored manual actions based strictly on existing threat context
        if threat_id == "THREAT-001":
            recommended_actions = [
                "Remove public ACL settings (e.g. change 'public-read' to 'private').",
                "Declare an 'aws_s3_bucket_public_access_block' resource with all block public access flags set to true.",
                "Verify bucket policies do not allow anonymous Principal ('*') actions.",
            ]
            assumptions = ["Assumes the bucket does not host a public website requiring anonymous internet access."]
            validation_steps = [
                "Inspect the bucket ACL and attached policies in your Terraform configuration.",
                "Run `terraform plan` to verify the modified ACL settings.",
            ]
        elif threat_id == "THREAT-002":
            recommended_actions = [
                "Restrict security group ingress 'cidr_blocks' on port 22 from 0.0.0.0/0 to authorized corporate CIDR blocks.",
                "Evaluate migrating to AWS Systems Manager Session Manager to eliminate inbound SSH ports entirely.",
            ]
            assumptions = ["Assumes administrative shell access can be restricted to known CIDR ranges or IAM-based session management."]
            validation_steps = [
                "Confirm the authorized IP addresses of administrative personnel.",
                "Run `terraform plan` to preview the updated ingress security group rule.",
            ]
        elif threat_id == "THREAT-003":
            recommended_actions = [
                "Remove unrestricted CIDR ranges (0.0.0.0/0, ::/0) from sensitive administrative and database ingress rules.",
                "Scope ingress to private VPC subnet CIDRs or internal client security groups.",
            ]
            assumptions = ["Assumes sensitive services are intended exclusively for internal application communication."]
            validation_steps = [
                "Identify internal application security groups that require connectivity to this port.",
                "Run `terraform plan` to verify ingress restriction.",
            ]
        elif threat_id == "THREAT-004":
            recommended_actions = [
                "Set 'publicly_accessible = false' on the database resource block.",
                "Ensure the database subnet group associates only with private subnets that do not route to an Internet Gateway.",
            ]
            assumptions = ["Assumes client applications connect to the database from within the VPC or via private networking."]
            validation_steps = [
                "Review the database subnet group routing in your VPC configuration.",
                "Run `terraform plan` to ensure that modifying 'publicly_accessible' does not cause unintended resource recreation.",
            ]
        elif threat_id == "THREAT-006":
            recommended_actions = [
                "Restrict IAM policy Action statements from '*' to discrete, required API permissions.",
                "Restrict Resource statements from '*' to specific resource ARNs following least-privilege principles.",
            ]
            assumptions = ["Assumes workload permissions can be enumerated from application requirements or CloudTrail audit logs."]
            validation_steps = [
                "Review AWS IAM Access Analyzer findings for excessive administrative access.",
                "Run `terraform plan` to verify the revised IAM policy document.",
            ]
        # ── CloudFormation Specific Remediations ──────────────────────────────
        elif threat_id == "CFN-001":
            recommended_actions = [
                "Remove public AccessControl values (avoid PublicRead, PublicReadWrite).",
                "Configure PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets set to true.",
            ]
            assumptions = ["Assumes bucket is intended for internal or authenticated access."]
            suggested_code = (
                "PublicAccessBlockConfiguration:\n"
                "  BlockPublicAcls: true\n"
                "  BlockPublicPolicy: true\n"
                "  IgnorePublicAcls: true\n"
                "  RestrictPublicBuckets: true"
            )
            patch_type = "addition"
            validation_steps = ["Validate CloudFormation template: aws cloudformation validate-template ..."]
        elif threat_id == "CFN-002":
            recommended_actions = [
                "Add BucketEncryption to AWS::S3::Bucket Properties with ServerSideEncryptionConfiguration.",
                "Configure ServerSideEncryptionByDefault with SSEAlgorithm: AES256 or aws:kms.",
            ]
            assumptions = ["Assumes AWS-managed AES256 encryption satisfies data protection requirements."]
            suggested_code = (
                "BucketEncryption:\n"
                "  ServerSideEncryptionConfiguration:\n"
                "    - ServerSideEncryptionByDefault:\n"
                "        SSEAlgorithm: AES256"
            )
            patch_type = "addition"
            validation_steps = ["Validate CloudFormation template and preview changes via change set."]
        elif threat_id == "CFN-003":
            recommended_actions = [
                "Scope IAM policy Action statements from '*' to discrete API operations.",
                "Replace wildcard Resource ('*') with specific target resource ARNs.",
            ]
            assumptions = ["Assumes least-privilege IAM permissions can be scoped to specific resource ARNs."]
            validation_steps = ["Review IAM policy document with AWS IAM Access Analyzer."]
        elif threat_id == "CFN-004":
            recommended_actions = [
                "Restrict SecurityGroupIngress CidrIp from 0.0.0.0/0 to authorized corporate CIDR blocks.",
                "Use AWS Systems Manager Session Manager instead of open inbound SSH port 22.",
            ]
            assumptions = ["Assumes administrative shell access can be restricted to authorized corporate CIDRs."]
            suggested_code = "CidrIp: 10.0.0.0/16"
            patch_type = "modification"
            validation_steps = ["Verify SecurityGroupIngress CIDR ranges in the CloudFormation template."]
        elif threat_id == "CFN-005":
            recommended_actions = [
                "Set Encrypted: true on the AWS::EC2::Volume resource.",
                "Optionally configure KmsKeyId for centralized encryption key management.",
            ]
            assumptions = ["Assumes EBS encryption is supported in the target AWS region."]
            suggested_code = "Encrypted: true"
            patch_type = "modification"
            validation_steps = ["Review AWS::EC2::Volume properties in CloudFormation template."]
        elif threat_id == "CFN-006":
            recommended_actions = [
                "Configure AuthType: AWS_IAM on AWS::Lambda::Url to require IAM authentication.",
                "Enable active AWS X-Ray tracing by setting TracingConfig.Mode: Active.",
            ]
            assumptions = ["Assumes callers possess IAM credentials or use signed requests."]
            suggested_code = "AuthType: AWS_IAM"
            patch_type = "modification"
            validation_steps = ["Inspect AWS::Lambda::Url and AWS::Lambda::Function properties."]

        # ── Kubernetes Specific Remediations ──────────────────────────────────
        elif threat_id == "K8S-001":
            recommended_actions = [
                "Set securityContext.privileged: false on all workload containers.",
                "Add only the specific Linux capabilities needed rather than granting full node privilege.",
            ]
            assumptions = ["Assumes container does not require raw host device access."]
            suggested_code = "securityContext:\n  privileged: false"
            patch_type = "modification"
            validation_steps = ["Run `kubectl apply --dry-run=client -f <file>` to verify syntax."]
        elif threat_id == "K8S-002":
            recommended_actions = [
                "Configure securityContext.runAsNonRoot: true in the pod or container spec.",
                "Specify a designated non-root UID using runAsUser (e.g. 10001).",
            ]
            assumptions = ["Assumes container image supports running under non-root UID."]
            suggested_code = "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001"
            patch_type = "modification"
            validation_steps = ["Verify workload starts successfully with non-root UID."]
        elif threat_id == "K8S-003":
            recommended_actions = [
                "Set securityContext.allowPrivilegeEscalation: false in container definitions.",
            ]
            assumptions = ["Assumes container binaries do not require setuid/setgid execution."]
            suggested_code = "securityContext:\n  allowPrivilegeEscalation: false"
            patch_type = "modification"
            validation_steps = ["Verify pod securityContext in YAML manifest."]
        elif threat_id == "K8S-004":
            recommended_actions = [
                "Remove dangerous capabilities from capabilities.add.",
                "Drop all capabilities by default (capabilities.drop: ['ALL']) and selectively add unprivileged ones.",
            ]
            assumptions = ["Assumes workload functions without elevated kernel capabilities."]
            suggested_code = "securityContext:\n  capabilities:\n    drop:\n      - ALL"
            patch_type = "modification"
            validation_steps = ["Test container functionality without elevated Linux capabilities."]
        elif threat_id == "K8S-005":
            recommended_actions = [
                "Set hostNetwork: false, hostPID: false, and hostIPC: false in pod specifications.",
            ]
            assumptions = ["Assumes pod is an application workload and not a node monitoring daemon."]
            suggested_code = "hostNetwork: false\nhostPID: false\nhostIPC: false"
            patch_type = "modification"
            validation_steps = ["Verify host network isolation in pod spec."]
        elif threat_id == "K8S-006":
            recommended_actions = [
                "Configure securityContext.readOnlyRootFilesystem: true on the container.",
                "Mount ephemeral emptyDir volumes for writable scratch directories.",
            ]
            assumptions = ["Assumes writable application state is stored on dedicated volumes."]
            suggested_code = "securityContext:\n  readOnlyRootFilesystem: true"
            patch_type = "modification"
            validation_steps = ["Verify container has read-only rootfs configured."]
        elif threat_id == "K8S-007":
            recommended_actions = [
                "Change Service type to ClusterIP for internal services.",
                "Expose web workloads via an Ingress controller with TLS.",
            ]
            assumptions = ["Assumes service is consumed within the cluster or through Ingress."]
            suggested_code = "type: ClusterIP"
            patch_type = "modification"
            validation_steps = ["Review Service spec in YAML manifest."]
        elif threat_id == "K8S-008":
            recommended_actions = [
                "Add a tls block to the Ingress spec specifying hosts and secretName.",
            ]
            assumptions = ["Assumes a valid TLS secret or cert-manager issuer is available."]
            suggested_code = "tls:\n  - hosts:\n      - example.com\n    secretName: example-tls-secret"
            patch_type = "addition"
            validation_steps = ["Verify Ingress TLS configuration and secret references."]
        elif threat_id == "K8S-009":
            recommended_actions = [
                "Replace wildcard '*' in verbs, resources, and apiGroups with specific permissions.",
            ]
            assumptions = ["Assumes specific API operations can be enumerated."]
            validation_steps = ["Audit RBAC rules against least-privilege requirements."]
        elif threat_id == "K8S-010":
            recommended_actions = [
                "Set automountServiceAccountToken: false on the Pod spec or ServiceAccount.",
            ]
            assumptions = ["Assumes workload does not query the Kubernetes API server."]
            suggested_code = "automountServiceAccountToken: false"
            patch_type = "modification"
            validation_steps = ["Verify API token is not mounted at runtime."]
        elif threat_id == "K8S-011":
            recommended_actions = [
                "Define a default-deny NetworkPolicy in the namespace to isolate workload traffic.",
            ]
            assumptions = ["Assumes cluster network plugin supports NetworkPolicy."]
            validation_steps = ["Inspect NetworkPolicy resources in the namespace."]
        elif threat_id == "K8S-012":
            recommended_actions = [
                "Replace 'latest' or untagged container images with specific semantic version tags.",
                "Pin critical container images to immutable SHA256 digests.",
            ]
            assumptions = ["Assumes versioned image tags are available in the container registry."]
            validation_steps = ["Verify image tag in container spec."]
        else:
            recommended_actions = [raw_recommendation] if raw_recommendation else [
                "Review the resource configuration against cloud security baseline standards."
            ]
            assumptions = ["Assumes standard cloud provider security baseline applies."]
            validation_steps = [
                "Review the IaC configuration and execute planning tools to inspect changes."
            ]

        if suggested_code:
            explanation = (
                f"Suggested safe remediation patch for {finding_title}. "
                "Review the proposed configuration snippet against architectural standards. "
                "User files are never modified automatically."
            )
        else:
            explanation = (
                f"Manual remediation guidance for {finding_title}. "
                "Automated code patch generation is not supported for this threat pattern "
                "to prevent generating unsafe or speculative infrastructure configurations. "
                "Follow the recommended actions manually."
            )

        return {
            "remediation_id": remediation_id,
            "finding_id": finding_id,
            "affected_resource_id": res_id,
            "affected_resource_type": res_type,
            "affected_resource_name": res_name,
            "title": f"Remediation Guidance: {finding_title}",
            "explanation": explanation,
            "recommended_actions": recommended_actions,
            "suggested_code": suggested_code,
            "patch_type": patch_type,
            "assumptions": assumptions,
            "validation_steps": validation_steps,
            "remediation_status": remediation_status,
            "generated_by": "rule_based",
        }


# ---------------------------------------------------------------------------
# Provider Factory & Public Pipeline API
# ---------------------------------------------------------------------------

_CURRENT_PROVIDER: BaseRemediationProvider = RuleBasedRemediationProvider()


def get_remediation_provider() -> BaseRemediationProvider:
    """
    Return the active remediation provider.

    Currently returns RuleBasedRemediationProvider.
    Future extension: can return WatsonxRemediationProvider when configured.
    """
    return _CURRENT_PROVIDER


def generate_remediation(
    finding: dict[str, Any],
    resources: list[dict[str, Any]],
    existing_labels: set[str],
) -> dict[str, Any]:
    """
    Generate a remediation recommendation for a single finding.

    Args:
        finding: Dictionary representation of a threat finding.
        resources: Full list of parsed Terraform resources.
        existing_labels: Set of resource labels already in use to prevent collisions.

    Returns:
        Structured remediation recommendation dictionary matching the API schema.
    """
    if not isinstance(finding, dict):
        return {
            "remediation_id": "rem-invalid",
            "finding_id": "",
            "affected_resource_id": "",
            "affected_resource_type": "",
            "affected_resource_name": "",
            "title": "Invalid Finding",
            "explanation": "Cannot generate remediation for malformed finding object.",
            "recommended_actions": [],
            "suggested_code": None,
            "patch_type": "manual",
            "assumptions": [],
            "validation_steps": [],
            "remediation_status": "Needs Review",
            "generated_by": "rule_based",
        }

    provider = get_remediation_provider()
    return provider.generate(finding, resources, existing_labels)


def generate_remediations(
    threat_findings: list[dict[str, Any]],
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate remediation recommendations and safe code patches for all findings.

    Args:
        threat_findings: List of finding dictionaries from Steps 3 and 4.
        resources: List of parsed Terraform resource blocks from Step 1.

    Returns:
        List of structured remediation recommendation dictionaries, one per finding.
        Returns [] if threat_findings is empty or None.
    """
    if not threat_findings:
        return []

    safe_resources = resources if isinstance(resources, list) else []

    # Collect existing resource labels from input to avoid naming collisions
    existing_labels: set[str] = {
        r.get("name", "")
        for r in safe_resources
        if isinstance(r, dict) and r.get("name")
    }

    remediations: list[dict[str, Any]] = []
    for item in threat_findings:
        if isinstance(item, dict):
            remediations.append(
                generate_remediation(item, safe_resources, existing_labels)
            )

    return remediations
