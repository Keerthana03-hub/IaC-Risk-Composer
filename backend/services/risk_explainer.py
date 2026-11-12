"""
services/risk_explainer.py
---------------------------
AI-Powered Risk Explanation Engine for IaC Risk Composer (Step 5).

Generates clear, evidence-grounded, plain-language explanations of existing
threat findings and risk assessments. Explains what was detected, why it matters,
what evidence supports it, what remains uncertain, and what actions/verification
steps the developer should take.

Design Note (Step 5 Architecture):
----------------------------------
This service currently uses a deterministic, rule-based explanation engine
(`RuleBasedExplanationProvider`) that grounds every sentence strictly in the
actual finding fields without fabricating evidence, risk scores, or cloud states.

Future LLM Integration Point (e.g. IBM watsonx.ai):
---------------------------------------------------
The architecture implements `BaseExplanationProvider` to allow seamless future
integration of an authorized LLM provider (such as IBM watsonx.ai Granite or
Llama models) by implementing a `WatsonxExplanationProvider` class conforming to
`BaseExplanationProvider.explain()` without breaking the existing API contract.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any


# ---------------------------------------------------------------------------
# Abstract Explanation Provider Interface
# ---------------------------------------------------------------------------


class BaseExplanationProvider(ABC):
    """
    Abstract interface for explanation generators.

    Allows plugging in deterministic rule-based explainers today, or an
    authorized LLM provider (e.g., IBM watsonx.ai) in the future.
    """

    @abstractmethod
    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Generate a structured explanation dictionary for a single finding."""
        pass


# ---------------------------------------------------------------------------
# Deterministic Rule-Based Explanation Provider
# ---------------------------------------------------------------------------


class RuleBasedExplanationProvider(BaseExplanationProvider):
    """
    Deterministic, evidence-grounded explanation engine.

    All generated explanations are derived strictly from the finding's
    existing attributes (title, description, severity, evidence, recommendation,
    detection_status, risk_assessment) without external hallucinations or
    unsupported assumptions.
    """

    def explain(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Generate a structured explanation for a single finding."""
        finding_id = str(finding.get("finding_id", ""))
        detection_status = str(finding.get("detection_status", "")).strip()
        risk_assessment = finding.get("risk_assessment") or {}
        assessment_status = str(risk_assessment.get("assessment_status", "")).strip()

        is_provisional = (
            detection_status == "Needs Review" or assessment_status == "Provisional"
        )

        summary = self._generate_summary(finding, is_provisional)
        why_it_matters = self._generate_why_it_matters(finding, is_provisional)
        evidence_explanation = self._generate_evidence_explanation(finding)
        uncertainty = self._generate_uncertainty(is_provisional)
        recommended_actions = self._generate_recommended_actions(finding)
        verification_steps = self._generate_verification_steps(finding)

        explanation_status = "Needs Review" if is_provisional else "Generated"
        explanation_method = "rule_based"

        return {
            "finding_id": finding_id,
            "summary": summary,
            "why_it_matters": why_it_matters,
            "evidence_explanation": evidence_explanation,
            "uncertainty": uncertainty,
            "recommended_actions": recommended_actions,
            "verification_steps": verification_steps,
            "explanation_status": explanation_status,
            "explanation_method": explanation_method,
        }

    # ── Summary ────────────────────────────────────────────────────────────

    def _generate_summary(
        self, finding: dict[str, Any], is_provisional: bool
    ) -> str:
        res_id = finding.get("affected_resource_id") or "Resource"
        title = finding.get("title") or "Potential Security Misconfiguration"

        if is_provisional:
            return (
                f"Configuration review required for {res_id}: {title}. "
                "The configuration does not confirm an immediate vulnerability, "
                "but requires verification against environment baselines."
            )
        return f"Confirmed security misconfiguration detected on {res_id}: {title}."

    # ── Why It Matters ─────────────────────────────────────────────────────

    def _generate_why_it_matters(
        self, finding: dict[str, Any], is_provisional: bool
    ) -> str:
        impact = str(finding.get("impact", "")).strip()
        description = str(finding.get("description", "")).strip()
        risk_assessment = finding.get("risk_assessment") or {}
        level = risk_assessment.get("risk_level")
        score = risk_assessment.get("inherent_risk_score")

        if is_provisional:
            return (
                "Unconfigured or missing security parameters leave resources reliant on "
                "implicit cloud provider defaults or organizational baselines. If those "
                f"defaults change or are permissive, data exposure or unauthorized access may occur. {impact}"
            ).strip()

        score_info = f"Assessed as {level} Inherent Risk (score: {score}/25). " if level and score else ""
        return f"{score_info}{impact} {description}".strip()

    # ── Evidence Explanation ───────────────────────────────────────────────

    def _generate_evidence_explanation(self, finding: dict[str, Any]) -> str:
        evidence = finding.get("evidence")
        if not evidence or not isinstance(evidence, dict):
            return "No specific attribute evidence was attached to this finding."

        # Case 1: Missing or unconfigured attributes
        missing_attrs = [
            k for k, v in evidence.items() if v == "missing" or v is None
        ]
        if missing_attrs:
            return (
                f"The Terraform resource definition omits the configuration for: {', '.join(missing_attrs)}. "
                "This indicates an unconfigured property in IaC code, not an explicitly disabled setting. "
                "Cloud account defaults or out-of-band policies may govern runtime behavior."
            )

        # Case 2: Explicitly disabled security controls
        disabled_keys = [
            k for k, v in evidence.items()
            if (v is False or str(v).lower() == "false")
        ]
        if disabled_keys or "disabled_settings" in evidence:
            details = evidence.get("disabled_settings") or disabled_keys
            return (
                f"The configuration explicitly sets security controls to disabled: {details}. "
                "This creates a confirmed gap in protection according to the security template."
            )

        # Case 3: Publicly accessible flag
        if evidence.get("publicly_accessible") is True:
            return (
                "The database resource explicitly specifies 'publicly_accessible = true', "
                "which instructs AWS to provision a public IP address reachable from the Internet."
            )

        # Case 4: Unrestricted network ingress (0.0.0.0/0 or ::/0)
        if "unrestricted_cidrs" in evidence:
            cidrs = evidence.get("unrestricted_cidrs", [])
            protocol = evidence.get("protocol", "tcp")
            from_port = evidence.get("from_port")
            to_port = evidence.get("to_port")
            port_str = (
                "all ports"
                if from_port == 0 and (to_port == 0 or to_port == 65535 or str(protocol) in ("-1", "all"))
                else f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
            )
            return (
                f"The ingress rule explicitly permits unrestricted traffic from {', '.join(cidrs)} "
                f"to {port_str} (protocol: {protocol})."
            )

        # Case 5: Public ACL
        if "acl" in evidence:
            return (
                f"The resource specifies the Access Control List (ACL) as '{evidence.get('acl')}', "
                "which explicitly grants public access."
            )

        # Case 6: IAM Policy Statement
        if "statement" in evidence:
            stmt = evidence.get("statement", {})
            action = stmt.get("Action", "*")
            resource = stmt.get("Resource", "*")
            return (
                f"The IAM policy statement grants Effect='Allow' with broad permissions: "
                f"Action='{action}' across Resource='{resource}'."
            )

        return f"Identified configuration evidence: {json.dumps(evidence, default=str)}."

    # ── Uncertainty ────────────────────────────────────────────────────────

    def _generate_uncertainty(self, is_provisional: bool) -> str:
        if is_provisional:
            return (
                "High uncertainty: The Terraform configuration lacks explicit attribute declaration. "
                "It is unknown whether account-level controls (such as AWS Organization SCPs, S3 account-level "
                "Block Public Access, or EBS default encryption) enforce protection in the target account. "
                "Manual review of runtime environment settings is required before confirming a risk."
            )
        return (
            "Low uncertainty: Finding is confirmed directly from explicit Terraform attribute definitions. "
            "However, perimeter defenses outside this file (such as AWS Network Firewall, VPC route tables, "
            "or security group associations) were not evaluated and may restrict practical exploitability."
        )

    # ── Recommended Actions ────────────────────────────────────────────────

    def _generate_recommended_actions(self, finding: dict[str, Any]) -> list[str]:
        threat_id = finding.get("threat_id", "")
        recommendation = finding.get("recommendation", "")

        # Threat-specific practical actions
        if threat_id == "THREAT-001":
            return [
                "Remove any public ACL definitions (set acl = 'private').",
                "Add an 'aws_s3_bucket_public_access_block' resource with all block flags set to true.",
                "Ensure bucket policies only allow access to authenticated IAM roles or specific VPC endpoints.",
            ]
        if threat_id == "THREAT-002":
            return [
                "Restrict security group ingress cidr_blocks from 0.0.0.0/0 to authorized corporate CIDR ranges.",
                "Consider deploying AWS Systems Manager Session Manager to enable secure shell access without open inbound ports.",
            ]
        if threat_id == "THREAT-003":
            return [
                "Remove unrestricted CIDRs (0.0.0.0/0, ::/0) from sensitive service and database ingress rules.",
                "Place database and cache services in private subnets accessible only by internal application security groups.",
            ]
        if threat_id == "THREAT-004":
            return [
                "Set 'publicly_accessible = false' on the database resource.",
                "Verify database subnets do not route directly to an Internet Gateway.",
            ]
        if threat_id == "THREAT-005":
            return [
                "Explicitly enable storage encryption in the Terraform resource (e.g. storage_encrypted = true or encrypted = true).",
                "Specify a customer-managed AWS KMS key ARN for centralized encryption management and auditability.",
            ]
        if threat_id == "THREAT-006":
            return [
                "Restrict IAM policy Action statements from '*' to specific required API calls.",
                "Restrict Resource statements from '*' to specific resource ARNs, following least-privilege principles.",
            ]

        # ── CloudFormation Specific Recommendations ──────────────────────────
        if threat_id == "CFN-001":
            return [
                "Remove public AccessControl property (avoid PublicRead, PublicReadWrite).",
                "Add PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets set to true.",
                "Ensure bucket policy statements only allow access to authenticated principals.",
            ]
        if threat_id == "CFN-002":
            return [
                "Add BucketEncryption to AWS::S3::Bucket Properties with ServerSideEncryptionConfiguration.",
                "Configure ServerSideEncryptionByDefault with SSEAlgorithm: AES256 or aws:kms.",
            ]
        if threat_id == "CFN-003":
            return [
                "Scope IAM policy Action statements from '*' to discrete API operations.",
                "Replace wildcard Resource ('*') with specific target resource ARNs.",
            ]
        if threat_id == "CFN-004":
            return [
                "Restrict SecurityGroupIngress CidrIp from 0.0.0.0/0 to authorized corporate CIDR blocks.",
                "Use AWS Systems Manager Session Manager instead of public SSH port 22 access.",
            ]
        if threat_id == "CFN-005":
            return [
                "Set Encrypted: true on the AWS::EC2::Volume resource.",
                "Optionally configure KmsKeyId for centralized encryption key management.",
            ]
        if threat_id == "CFN-006":
            return [
                "Configure AuthType: AWS_IAM on AWS::Lambda::Url to require signature authentication.",
                "Enable active AWS X-Ray tracing by setting TracingConfig.Mode: Active.",
            ]

        # ── Kubernetes Specific Recommendations ──────────────────────────────
        if threat_id == "K8S-001":
            return [
                "Set securityContext.privileged: false on all workload containers.",
                "Add only the specific Linux capabilities needed rather than granting full node privilege.",
            ]
        if threat_id == "K8S-002":
            return [
                "Configure securityContext.runAsNonRoot: true in the pod or container spec.",
                "Specify a designated non-root UID using runAsUser (e.g. 10001).",
            ]
        if threat_id == "K8S-003":
            return [
                "Set securityContext.allowPrivilegeEscalation: false in container definitions.",
                "Enforce the Restricted Pod Security Standard across the namespace.",
            ]
        if threat_id == "K8S-004":
            return [
                "Remove dangerous capabilities (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, NET_ADMIN, DAC_OVERRIDE) from capabilities.add.",
                "Drop all capabilities by default (capabilities.drop: ['ALL']) and selectively add unprivileged ones.",
            ]
        if threat_id == "K8S-005":
            return [
                "Set hostNetwork: false, hostPID: false, and hostIPC: false in pod specifications.",
                "Isolate container networking and IPC within standard Kubernetes namespace boundaries.",
            ]
        if threat_id == "K8S-006":
            return [
                "Configure securityContext.readOnlyRootFilesystem: true on the container.",
                "Mount ephemeral emptyDir volumes for writable temporary directories (e.g. /tmp).",
            ]
        if threat_id == "K8S-007":
            return [
                "Use type: ClusterIP for internal services.",
                "Expose web workloads via an Ingress controller with TLS and ingress source filtering.",
            ]
        if threat_id == "K8S-008":
            return [
                "Add a tls block to the Ingress spec specifying hosts and a secretName containing TLS certificates.",
                "Deploy cert-manager to automatically provision and rotate Let's Encrypt TLS certificates.",
            ]
        if threat_id == "K8S-009":
            return [
                "Replace wildcard '*' in verbs, resources, and apiGroups with the minimum required permissions.",
                "Audit RBAC bindings to ensure least-privilege access for each ServiceAccount.",
            ]
        if threat_id == "K8S-010":
            return [
                "Set automountServiceAccountToken: false on the Pod spec or ServiceAccount.",
                "Enable token automounting only for pods that directly interact with the Kubernetes API server.",
            ]
        if threat_id == "K8S-011":
            return [
                "Create a default-deny NetworkPolicy in the namespace to isolate workload traffic.",
                "Define explicit NetworkPolicy ingress and egress rules for required application communication.",
            ]
        if threat_id == "K8S-012":
            return [
                "Replace 'latest' or untagged container images with specific semantic version tags (e.g. v1.2.3).",
                "Pin critical production container images to immutable SHA256 digests (@sha256:...).",
            ]

        if recommendation:
            return [recommendation]
        return ["Review the resource configuration and align with cloud security architecture standards."]

    # ── Verification Steps ─────────────────────────────────────────────────

    def _generate_verification_steps(self, finding: dict[str, Any]) -> list[str]:
        res_type = finding.get("affected_resource_type", "")

        if res_type in ("aws_security_group", "aws_security_group_rule"):
            return [
                "Inspect the Terraform file to locate ingress blocks defining cidr_blocks = ['0.0.0.0/0'].",
                "Run `aws ec2 describe-security-groups --group-ids <id>` to inspect effective inbound rules in the AWS account.",
                "Check whether any live EC2 instances or load balancers are currently associated with this security group.",
            ]
        if "s3" in res_type:
            return [
                "Inspect the bucket block in Terraform for 'acl' attributes or attached 'aws_s3_bucket_acl' resources.",
                "Run `aws s3api get-public-access-block --bucket <bucket-name>` to verify account and bucket block settings.",
                "Run `aws s3api get-bucket-encryption --bucket <bucket-name>` to check runtime default encryption status.",
            ]
        if "db" in res_type or "rds" in res_type or "redshift" in res_type:
            return [
                "Verify the 'publicly_accessible' attribute in the Terraform database resource block.",
                "Run `aws rds describe-db-instances --db-instance-identifier <id>` to inspect public accessibility in runtime.",
                "Check whether the DB subnet group routes to an Internet Gateway or a private NAT Gateway.",
            ]
        if "ebs" in res_type:
            return [
                "Inspect the Terraform 'aws_ebs_volume' block for 'encrypted = true'.",
                "Run `aws ec2 get-ebs-encryption-by-default` to verify whether the AWS account enforces encryption automatically.",
            ]
        if "iam" in res_type:
            return [
                "Inspect the IAM policy JSON or document statement for wildcard ('*') Action and Resource fields.",
                "Use AWS IAM Access Analyzer or `aws iam get-policy-version` to review active permissions and policy validity.",
            ]

        return [
            "Inspect the resource block definition and its attribute values in the Terraform source file.",
            "Verify the deployed resource's configuration in the cloud provider console or via CLI.",
        ]


# ---------------------------------------------------------------------------
# Provider Factory & Public Pipeline API
# ---------------------------------------------------------------------------

_CURRENT_PROVIDER: BaseExplanationProvider = RuleBasedExplanationProvider()


def get_explanation_provider() -> BaseExplanationProvider:
    """
    Return the active explanation provider.

    Currently returns RuleBasedExplanationProvider.
    Future extension: can return WatsonxExplanationProvider when configured.
    """
    return _CURRENT_PROVIDER


def explain_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Generate an evidence-grounded, structured explanation for a single finding.

    Args:
        finding: Dictionary representation of a threat finding (with Step 4 risk assessment).

    Returns:
        Structured explanation dictionary matching the RiskExplanation schema.
    """
    if not isinstance(finding, dict):
        return {
            "finding_id": "",
            "summary": "Invalid finding format.",
            "why_it_matters": "",
            "evidence_explanation": "No evidence available.",
            "uncertainty": "High uncertainty: Malformed finding object.",
            "recommended_actions": [],
            "verification_steps": [],
            "explanation_status": "Needs Review",
            "explanation_method": "rule_based",
        }

    provider = get_explanation_provider()
    return provider.explain(finding)


def explain_findings(threat_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Generate structured explanations for all findings in the analysis.

    Args:
        threat_findings: List of finding dictionaries from Steps 3 and 4.

    Returns:
        List of structured explanation dictionaries, one per finding.
        Returns [] if threat_findings is empty or None.
    """
    if not threat_findings:
        return []

    explanations: list[dict[str, Any]] = []
    for item in threat_findings:
        if isinstance(item, dict):
            explanations.append(explain_finding(item))

    return explanations
