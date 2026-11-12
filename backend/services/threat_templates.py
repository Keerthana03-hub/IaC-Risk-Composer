"""
services/threat_templates.py
------------------------------
Reusable security threat templates for IaC Risk Composer (Step 3).

Defines standardized, reusable threat templates for detecting cloud security
misconfigurations in Terraform resources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ThreatTemplate:
    """
    Reusable definition of a security threat rule.

    Attributes:
        threat_id: Unique identifier for the threat (e.g. 'THREAT-001').
        threat_name: Short human-readable title.
        description: Detailed explanation of the misconfiguration.
        applicable_resource_types: Terraform resource types this rule inspects.
        rule_identifier: Internal rule/detection logic identifier.
        default_severity: Default severity level ('Critical', 'High', 'Medium', 'Low').
        potential_impact: Security impact if this vulnerability is exploited.
        recommended_mitigation: Actionable remediation guidance.
    """

    threat_id: str
    threat_name: str
    description: str
    applicable_resource_types: tuple[str, ...]
    rule_identifier: str
    default_severity: str
    potential_impact: str
    recommended_mitigation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert template to a dictionary."""
        data = asdict(self)
        data["applicable_resource_types"] = list(self.applicable_resource_types)
        return data


# ---------------------------------------------------------------------------
# Initial Reusable Threat Templates (Threats 1 through 6)
# ---------------------------------------------------------------------------

THREAT_TEMPLATES: dict[str, ThreatTemplate] = {
    # Threat 1: Publicly Accessible S3 Bucket
    "THREAT-001": ThreatTemplate(
        threat_id="THREAT-001",
        threat_name="Publicly Accessible S3 Bucket",
        description=(
            "Detects S3 bucket configurations that explicitly permit public access via "
            "public ACLs (e.g. public-read, public-read-write, website), permissive bucket "
            "policies, or explicitly disabled S3 Block Public Access configurations."
        ),
        applicable_resource_types=(
            "aws_s3_bucket",
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_acl",
            "aws_s3_bucket_policy",
        ),
        rule_identifier="RULE-S3-PUBLIC-ACCESS",
        default_severity="High",
        potential_impact=(
            "Unauthorized external actors can read, download, or overwrite sensitive "
            "objects stored in the bucket, leading to data breaches or tampering."
        ),
        recommended_mitigation=(
            "Remove public ACLs, ensure S3 Block Public Access settings are enabled, "
            "and restrict bucket policies to explicit IAM roles or VPC endpoints."
        ),
    ),

    # Threat 2: Unrestricted SSH Access
    "THREAT-002": ThreatTemplate(
        threat_id="THREAT-002",
        threat_name="Unrestricted SSH Access",
        description=(
            "Detects security group ingress rules that permit inbound SSH access (TCP port 22) "
            "from unrestricted IPv4 CIDR 0.0.0.0/0 or unrestricted IPv6 CIDR ::/0."
        ),
        applicable_resource_types=(
            "aws_security_group",
            "aws_security_group_rule",
        ),
        rule_identifier="RULE-SG-UNRESTRICTED-SSH",
        default_severity="High",
        potential_impact=(
            "Attackers may be able to attempt remote access to exposed systems via "
            "brute-force password attacks, stolen keys, or SSH vulnerabilities."
        ),
        recommended_mitigation=(
            "Restrict SSH access to trusted IP ranges or use a secure management solution "
            "such as AWS Systems Manager Session Manager."
        ),
    ),

    # Threat 3: Unrestricted Sensitive Port Access
    "THREAT-003": ThreatTemplate(
        threat_id="THREAT-003",
        threat_name="Unrestricted Sensitive Port Access",
        description=(
            "Detects security group ingress rules allowing unrestricted inbound access (0.0.0.0/0 or ::/0) "
            "to sensitive administrative or database services (RDP: 3389, MySQL: 3306, PostgreSQL: 5432, "
            "Redis: 6379, MongoDB: 27017) or unrestricted access to all ports."
        ),
        applicable_resource_types=(
            "aws_security_group",
            "aws_security_group_rule",
        ),
        rule_identifier="RULE-SG-SENSITIVE-PORTS",
        default_severity="High",
        potential_impact=(
            "Database services or administrative protocols exposed to the public Internet "
            "are vulnerable to brute-force attacks, data leakage, and unauthorized access."
        ),
        recommended_mitigation=(
            "Restrict inbound ingress to trusted IP ranges or private application subnets, "
            "and avoid opening sensitive database or management ports to 0.0.0.0/0."
        ),
    ),

    # Threat 4: Publicly Accessible Database
    "THREAT-004": ThreatTemplate(
        threat_id="THREAT-004",
        threat_name="Publicly Accessible Database",
        description=(
            "Detects database instances configured with publicly_accessible = true, "
            "assigning them public IP addresses reachable from the Internet."
        ),
        applicable_resource_types=(
            "aws_db_instance",
            "aws_rds_cluster",
            "aws_redshift_cluster",
        ),
        rule_identifier="RULE-DB-PUBLIC-ACCESS",
        default_severity="High",
        potential_impact=(
            "Publicly accessible databases are exposed to internet-wide port scans, "
            "credential brute-forcing, zero-day database exploits, and potential mass exfiltration."
        ),
        recommended_mitigation=(
            "Set publicly_accessible = false and deploy database instances inside private VPC subnets "
            "accessed via internal security groups or VPN."
        ),
    ),

    # Threat 5: Missing Storage Encryption
    "THREAT-005": ThreatTemplate(
        threat_id="THREAT-005",
        threat_name="Missing Storage Encryption",
        description=(
            "Detects storage resources (EBS volumes, RDS instances, S3 buckets) with encryption "
            "explicitly disabled or missing required encryption configuration."
        ),
        applicable_resource_types=(
            "aws_s3_bucket",
            "aws_ebs_volume",
            "aws_db_instance",
        ),
        rule_identifier="RULE-STORAGE-ENCRYPTION",
        default_severity="Medium",
        potential_impact=(
            "Unencrypted data at rest is vulnerable to unauthorized access or regulatory compliance "
            "violations if physical or logical storage media are improperly accessed or leaked."
        ),
        recommended_mitigation=(
            "Enable at-rest encryption (e.g., encrypted = true or storage_encrypted = true) "
            "using AWS KMS keys or cloud-managed encryption keys."
        ),
    ),

    # Threat 6: Overly Permissive IAM Policy
    "THREAT-006": ThreatTemplate(
        threat_id="THREAT-006",
        threat_name="Overly Permissive IAM Policy",
        description=(
            "Detects IAM policies that grant administrative access with wildcard Action (*) "
            "across all resources (*), violating the principle of least privilege."
        ),
        applicable_resource_types=(
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_iam_policy_document",
        ),
        rule_identifier="RULE-IAM-WILDCARD-PERMISSIONS",
        default_severity="Critical",
        potential_impact=(
            "Grants full administrative control across all cloud services and resources, "
            "allowing unauthorized privilege escalation, resource manipulation, and data exfiltration."
        ),
        recommended_mitigation=(
            "Scope IAM policy permissions according to the principle of least privilege, "
            "specifying discrete actions and specific resource ARNs."
        ),
    ),

    # ── CloudFormation Threat Templates (CFN-001 to CFN-006) ─────────────
    "CFN-001": ThreatTemplate(
        threat_id="CFN-001",
        threat_name="Public S3 Bucket Exposure",
        description=(
            "Detects CloudFormation S3 bucket configurations that explicitly permit public access "
            "via public ACLs (PublicRead, PublicReadWrite), permissive bucket policies, or disabled "
            "Block Public Access settings."
        ),
        applicable_resource_types=("AWS::S3::Bucket", "AWS::S3::BucketPolicy"),
        rule_identifier="RULE-CFN-S3-PUBLIC-ACCESS",
        default_severity="High",
        potential_impact=(
            "Unauthorized external actors can read or write objects in the S3 bucket, "
            "leading to sensitive data leaks, data corruption, or compliance violations."
        ),
        recommended_mitigation=(
            "Configure PublicAccessBlockConfiguration with all block settings enabled, "
            "avoid public AccessControl values, and restrict bucket policies to specific IAM principals."
        ),
    ),
    "CFN-002": ThreatTemplate(
        threat_id="CFN-002",
        threat_name="Missing S3 Server-Side Encryption",
        description=(
            "Detects CloudFormation S3 bucket resources that omit server-side encryption configuration "
            "or do not explicitly define BucketEncryption properties."
        ),
        applicable_resource_types=("AWS::S3::Bucket",),
        rule_identifier="RULE-CFN-S3-ENCRYPTION",
        default_severity="Medium",
        potential_impact=(
            "Stored bucket data may be vulnerable to unauthorized access at rest if account or "
            "organization-level encryption defaults are not enforced."
        ),
        recommended_mitigation=(
            "Specify BucketEncryption with ServerSideEncryptionConfiguration using AES256 or aws:kms."
        ),
    ),
    "CFN-003": ThreatTemplate(
        threat_id="CFN-003",
        threat_name="Overly Permissive IAM Policy",
        description=(
            "Detects CloudFormation IAM policies and roles granting wildcard Action (*) across "
            "all resources (*), violating the principle of least privilege."
        ),
        applicable_resource_types=(
            "AWS::IAM::Policy",
            "AWS::IAM::Role",
            "AWS::IAM::ManagedPolicy",
        ),
        rule_identifier="RULE-CFN-IAM-WILDCARD",
        default_severity="Critical",
        potential_impact=(
            "Grants administrative control across cloud services, enabling unauthorized resource access, "
            "privilege escalation, and potential compromise of the entire AWS account."
        ),
        recommended_mitigation=(
            "Restrict IAM policy Action and Resource statements to only the specific API calls "
            "and ARNs necessary for workload functionality."
        ),
    ),
    "CFN-004": ThreatTemplate(
        threat_id="CFN-004",
        threat_name="Publicly Accessible EC2 Security Group",
        description=(
            "Detects CloudFormation security group ingress rules permitting unrestricted inbound "
            "traffic (0.0.0.0/0 or ::/0), especially for sensitive management ports such as SSH (22) and RDP (3389)."
        ),
        applicable_resource_types=(
            "AWS::EC2::SecurityGroup",
            "AWS::EC2::SecurityGroupIngress",
        ),
        rule_identifier="RULE-CFN-SG-PUBLIC-INGRESS",
        default_severity="High",
        potential_impact=(
            "Exposes host instances or services to external port scanning, brute-force attacks, "
            "and potential remote command execution from the public Internet."
        ),
        recommended_mitigation=(
            "Restrict ingress CIDR ranges to authorized corporate IPs or use AWS Systems Manager Session Manager."
        ),
    ),
    "CFN-005": ThreatTemplate(
        threat_id="CFN-005",
        threat_name="Unencrypted EBS Storage Volume",
        description=(
            "Detects CloudFormation EBS volumes where encryption is explicitly set to false or omitted."
        ),
        applicable_resource_types=("AWS::EC2::Volume",),
        rule_identifier="RULE-CFN-EBS-ENCRYPTION",
        default_severity="High",
        potential_impact=(
            "Unencrypted block storage volumes can result in data exposure if snapshots, physical media, "
            "or volume backups are accessed improperly."
        ),
        recommended_mitigation=(
            "Set Encrypted: true on the AWS::EC2::Volume resource and optionally specify a KmsKeyId."
        ),
    ),
    "CFN-006": ThreatTemplate(
        threat_id="CFN-006",
        threat_name="Insecure Lambda Configuration",
        description=(
            "Detects CloudFormation Lambda functions with insecure public function URLs (AuthType: NONE), "
            "disabled active tracing, or overly permissive execution roles."
        ),
        applicable_resource_types=("AWS::Lambda::Function", "AWS::Lambda::Url"),
        rule_identifier="RULE-CFN-LAMBDA-CONFIG",
        default_severity="High",
        potential_impact=(
            "Unauthenticated function URLs allow arbitrary internet callers to trigger serverless code execution, "
            "and disabled tracing limits incident response visibility."
        ),
        recommended_mitigation=(
            "Configure AuthType: AWS_IAM for Lambda URLs and enable active tracing with TracingConfig.Mode: Active."
        ),
    ),

    # ── Kubernetes Threat Templates (K8S-001 to K8S-012) ─────────────────
    "K8S-001": ThreatTemplate(
        threat_id="K8S-001",
        threat_name="Privileged Container Execution",
        description=(
            "Detects Kubernetes workload containers configured with privileged: true, granting container "
            "processes root-equivalent capabilities on the host node."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-PRIVILEGED-CONTAINER",
        default_severity="Critical",
        potential_impact=(
            "A compromised privileged container allows attackers to escape container isolation, "
            "access host kernel devices, and gain complete control over the underlying Kubernetes node."
        ),
        recommended_mitigation=(
            "Set securityContext.privileged: false on all containers and use discrete Linux capabilities if needed."
        ),
    ),
    "K8S-002": ThreatTemplate(
        threat_id="K8S-002",
        threat_name="Container Running as Root",
        description=(
            "Detects Kubernetes containers running as the root user via explicit runAsUser: 0 "
            "or runAsNonRoot: false."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-ROOT-USER",
        default_severity="High",
        potential_impact=(
            "Running processes as root increases the blast radius of container vulnerabilities, "
            "facilitating privilege escalation and host filesystem tampering upon compromise."
        ),
        recommended_mitigation=(
            "Configure securityContext.runAsNonRoot: true and specify a non-zero runAsUser (e.g. runAsUser: 10001)."
        ),
    ),
    "K8S-003": ThreatTemplate(
        threat_id="K8S-003",
        threat_name="Privilege Escalation Allowed",
        description=(
            "Detects containers where allowPrivilegeEscalation is set to true, permitting child processes "
            "to gain more privileges than their parent via setuid/setgid binaries."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-ALLOW-PRIVILEGE-ESCALATION",
        default_severity="High",
        potential_impact=(
            "Attackers can leverage setuid executables inside the container to escalate from an unprivileged "
            "user account to root within the container runtime."
        ),
        recommended_mitigation=(
            "Explicitly configure securityContext.allowPrivilegeEscalation: false in container definitions."
        ),
    ),
    "K8S-004": ThreatTemplate(
        threat_id="K8S-004",
        threat_name="Dangerous Linux Capabilities Added",
        description=(
            "Detects containers configured with dangerous Linux capabilities such as SYS_ADMIN, "
            "SYS_MODULE, SYS_PTRACE, NET_ADMIN, or DAC_OVERRIDE."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-DANGEROUS-CAPABILITIES",
        default_severity="High",
        potential_impact=(
            "Dangerous capabilities allow containers to manipulate host kernel modules, inspect processes, "
            "reconfigure network interfaces, or bypass filesystem permissions, enabling container escape."
        ),
        recommended_mitigation=(
            "Drop unnecessary capabilities using capabilities.drop: ['ALL'] and add only the minimal required capabilities."
        ),
    ),
    "K8S-005": ThreatTemplate(
        threat_id="K8S-005",
        threat_name="Host Namespace Exposure",
        description=(
            "Detects workloads sharing host namespaces (hostNetwork: true, hostPID: true, or hostIPC: true), "
            "breaking isolation boundaries between pods and the host."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-HOST-NAMESPACES",
        default_severity="High",
        potential_impact=(
            "Sharing host namespaces allows containers to sniff host network traffic, inspect processes on the node, "
            "or communicate via host shared memory, compromising node security."
        ),
        recommended_mitigation=(
            "Ensure hostNetwork, hostPID, and hostIPC are set to false unless running authorized node infrastructure agents."
        ),
    ),
    "K8S-006": ThreatTemplate(
        threat_id="K8S-006",
        threat_name="Writable Root Filesystem",
        description=(
            "Detects containers where readOnlyRootFilesystem is explicitly configured as false."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-WRITABLE-ROOTFS",
        default_severity="Medium",
        potential_impact=(
            "A writable root filesystem enables attackers to download exploit tools, install malicious software, "
            "or overwrite binaries after gaining initial container access."
        ),
        recommended_mitigation=(
            "Set securityContext.readOnlyRootFilesystem: true and use ephemeral emptyDir volumes for scratch data."
        ),
    ),
    "K8S-007": ThreatTemplate(
        threat_id="K8S-007",
        threat_name="Unrestricted Service Exposure",
        description=(
            "Detects Kubernetes Services configured with type LoadBalancer or NodePort, which may expose "
            "internal workloads to external networks."
        ),
        applicable_resource_types=("Service",),
        rule_identifier="RULE-K8S-SERVICE-EXPOSURE",
        default_severity="Medium",
        potential_impact=(
            "Workloads exposed via NodePort or LoadBalancer can be reached from external networks, "
            "increasing attack surface if not protected by firewalls or ingress controls."
        ),
        recommended_mitigation=(
            "Use ClusterIP for internal services and expose external traffic through an Ingress controller with TLS."
        ),
    ),
    "K8S-008": ThreatTemplate(
        threat_id="K8S-008",
        threat_name="Ingress Configured Without TLS",
        description=(
            "Detects Kubernetes Ingress resources that route traffic to services without configuring TLS encryption."
        ),
        applicable_resource_types=("Ingress",),
        rule_identifier="RULE-K8S-INGRESS-NO-TLS",
        default_severity="Medium",
        potential_impact=(
            "Unencrypted HTTP ingress traffic allows eavesdropping and man-in-the-middle attacks on sensitive "
            "application data in transit."
        ),
        recommended_mitigation=(
            "Configure the tls block in the Ingress spec referencing a valid TLS secret or cert-manager issuer."
        ),
    ),
    "K8S-009": ThreatTemplate(
        threat_id="K8S-009",
        threat_name="Excessive RBAC Wildcard Permissions",
        description=(
            "Detects Kubernetes Role or ClusterRole definitions that grant wildcard permissions (* in verbs, "
            "resources, or apiGroups)."
        ),
        applicable_resource_types=("Role", "ClusterRole"),
        rule_identifier="RULE-K8S-RBAC-WILDCARD",
        default_severity="High",
        potential_impact=(
            "Wildcard RBAC rights violate least privilege and can allow unauthorized cluster administration, "
            "secret exfiltration, or rogue pod deployment."
        ),
        recommended_mitigation=(
            "Replace wildcard permissions with specific verbs and resources needed by the service account."
        ),
    ),
    "K8S-010": ThreatTemplate(
        threat_id="K8S-010",
        threat_name="ServiceAccount Token Automount Enabled",
        description=(
            "Detects workloads or ServiceAccounts explicitly configuring automountServiceAccountToken: true."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ServiceAccount",
        ),
        rule_identifier="RULE-K8S-AUTOMOUNT-SA-TOKEN",
        default_severity="Medium",
        potential_impact=(
            "Mounting service account API tokens into containers that do not communicate with the Kubernetes API "
            "creates an unnecessary credential theft target if the container is compromised."
        ),
        recommended_mitigation=(
            "Set automountServiceAccountToken: false on pods and service accounts that do not require API server access."
        ),
    ),
    "K8S-011": ThreatTemplate(
        threat_id="K8S-011",
        threat_name="Missing NetworkPolicy for Namespace Workloads",
        description=(
            "Identifies namespaces containing workload resources without an accompanying NetworkPolicy "
            "defined in the manifest."
        ),
        applicable_resource_types=("Namespace", "Pod", "Deployment", "StatefulSet", "DaemonSet"),
        rule_identifier="RULE-K8S-MISSING-NETPOL",
        default_severity="Medium",
        potential_impact=(
            "Without NetworkPolicies, all pods in a namespace can communicate unrestricted with any other pod "
            "across the cluster, facilitating lateral movement."
        ),
        recommended_mitigation=(
            "Define a default-deny NetworkPolicy and create explicit ingress/egress allow rules for application traffic."
        ),
    ),
    "K8S-012": ThreatTemplate(
        threat_id="K8S-012",
        threat_name="Untrusted Container Image Tag Configuration",
        description=(
            "Detects container images configured using the 'latest' tag or omitting an explicit version tag, "
            "presenting an image-pinning and reproducibility risk."
        ),
        applicable_resource_types=(
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob",
        ),
        rule_identifier="RULE-K8S-IMAGE-TAG",
        default_severity="Medium",
        potential_impact=(
            "Using floating tags like 'latest' introduces deployment non-determinism and risks pulling unexpected "
            "or breaking upstream image changes."
        ),
        recommended_mitigation=(
            "Pin container images to specific semantic version tags (e.g., v1.2.3) or immutable SHA256 image digests."
        ),
    ),
}


def get_threat_template(threat_id: str) -> ThreatTemplate | None:
    """Retrieve a threat template by its threat ID."""
    return THREAT_TEMPLATES.get(threat_id)


def list_threat_templates() -> list[ThreatTemplate]:
    """Return all registered threat templates."""
    return list(THREAT_TEMPLATES.values())
