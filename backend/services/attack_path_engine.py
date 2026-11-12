"""
services/attack_path_engine.py
------------------------------
Relationship-Aware Attack Path Analysis Engine (Stage 6).

Identifies how an attacker could potentially move through infrastructure resources,
from an externally exposed entry point to sensitive target resources.

Capabilities:
1. Directed Infrastructure Graph: builds a directed graph of resources and connections.
2. Multi-IaC Support: resolves relationships for Terraform, AWS CloudFormation, and Kubernetes.
3. Component Classification: External Entry Points, Workloads, Privileges, and Sensitive Resources.
4. Directed Path Discovery: DFS traversal with loop/cycle prevention, path length limits, and deduplication.
5. Evidence-Grounded Risk Scoring: conservative severity, confidence, and provisional status handling.
6. Plain-Language Explanations: clear narratives, step-by-step evidence, and explicit limitations.

Safety:
- Static IaC analysis only; never executes code or connects to cloud accounts.
- Grounded: never creates graph edges for unresolved or imaginary resources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from typing import Any, Iterable

from services.infrastructure_schema import IaCFormat, NormalizedInfrastructure, NormalizedResource

# ---------------------------------------------------------------------------
# Classification & Category Constants
# ---------------------------------------------------------------------------

CATEGORY_ENTRY_POINT = "entry_point"
CATEGORY_WORKLOAD = "workload"
CATEGORY_PRIVILEGE = "privilege"
CATEGORY_SENSITIVE = "sensitive"
CATEGORY_STANDARD = "standard"

# Workload Resource Types
WORKLOAD_TYPES_TF = {"aws_instance", "aws_lambda_function", "aws_ecs_task_definition"}
WORKLOAD_TYPES_CFN = {
    "AWS::EC2::Instance",
    "AWS::Lambda::Function",
    "AWS::ECS::TaskDefinition",
    "AWS::ECS::Service",
}
WORKLOAD_KINDS_K8S = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}

# Privilege & Identity Types
PRIVILEGE_TYPES_TF = {
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_instance_profile",
    "aws_iam_role_policy_attachment",
}
PRIVILEGE_TYPES_CFN = {
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::InstanceProfile",
}
PRIVILEGE_KINDS_K8S = {
    "ServiceAccount",
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
}

# Sensitive Data / Storage Types
SENSITIVE_TYPES_TF = {"aws_s3_bucket", "aws_db_instance", "aws_ebs_volume"}
SENSITIVE_TYPES_CFN = {"AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::EC2::Volume"}
SENSITIVE_KINDS_K8S = {"Secret", "PersistentVolume", "PersistentVolumeClaim"}

# Kubernetes Cluster-Scoped Resource Kinds
CLUSTER_SCOPED_KINDS = {
    "ClusterRole",
    "ClusterRoleBinding",
    "PersistentVolume",
    "Namespace",
    "CustomResourceDefinition",
    "Node",
    "StorageClass",
}

# Max Graph Traversal Limits
MAX_TRAVERSAL_DEPTH = 8
MAX_DISCOVERED_PATHS = 25


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class GraphEdge:
    """A directed edge representing relationship or data/traffic flow."""

    source: str
    target: str
    relationship: str
    details: str
    is_confirmed: bool = True


@dataclass
class GraphNode:
    """A node in the directed infrastructure attack graph."""

    id: str
    name: str
    resource_type: str
    source_format: str
    categories: set[str] = field(default_factory=set)
    attributes: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    unresolved_references: list[str] = field(default_factory=list)

    @property
    def is_entry_point(self) -> bool:
        return CATEGORY_ENTRY_POINT in self.categories

    @property
    def is_workload(self) -> bool:
        return CATEGORY_WORKLOAD in self.categories

    @property
    def is_privilege(self) -> bool:
        return CATEGORY_PRIVILEGE in self.categories

    @property
    def is_sensitive(self) -> bool:
        return CATEGORY_SENSITIVE in self.categories


@dataclass
class AttackPathHop:
    """A single step along an attack path."""

    step: int
    source: str
    target: str
    relationship: str
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPath:
    """A complete discovered attack path from entry point to target."""

    path_id: str
    source_format: str
    entry_point: str
    target_resource: str
    resource_path: list[str]
    severity: str
    confidence: str
    assessment_status: str
    description: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_format": self.source_format,
            "entry_point": self.entry_point,
            "target_resource": self.target_resource,
            "resource_path": self.resource_path,
            "severity": self.severity,
            "confidence": self.confidence,
            "assessment_status": self.assessment_status,
            "description": self.description,
            "evidence": self.evidence,
            "related_findings": self.related_findings,
            "limitations": self.limitations,
        }


# ---------------------------------------------------------------------------
# Directed Infrastructure Attack Graph
# ---------------------------------------------------------------------------


class DirectedAttackGraph:
    """Directed graph representing resources and actionable security relationships."""

    def __init__(self, source_format: str) -> None:
        self.source_format = source_format
        self.nodes: dict[str, GraphNode] = {}
        self.adjacency: dict[str, list[GraphEdge]] = {}
        self.seen_edges: set[tuple[str, str, str]] = set()

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        details: str,
        is_confirmed: bool = True,
    ) -> bool:
        """Add a directed edge if both nodes exist and edge is not duplicate."""
        if source_id == target_id:
            return False  # Avoid self-referencing loops

        edge_key = (source_id, target_id, relationship)
        if edge_key in self.seen_edges:
            return False

        if source_id not in self.nodes or target_id not in self.nodes:
            # Cannot link to an undeclared resource
            return False

        edge = GraphEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            details=details,
            is_confirmed=is_confirmed,
        )
        self.adjacency.setdefault(source_id, []).append(edge)
        self.seen_edges.add(edge_key)
        return True


# ---------------------------------------------------------------------------
# Helper: String Collection and Identification
# ---------------------------------------------------------------------------


def _collect_string_leaves(data: Any) -> list[str]:
    """Recursively collect all string values in an arbitrary dictionary/list."""
    leaves: list[str] = []
    if isinstance(data, str):
        leaves.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            leaves.extend(_collect_string_leaves(v))
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            leaves.extend(_collect_string_leaves(item))
    return leaves


def _matches_terraform_reference(token: str, target_type: str, target_name: str) -> bool:
    """
    Check if a reference token exactly matches a target Terraform resource.
    Handles:
    - aws_security_group.web
    - ${aws_security_group.web.id}
    - aws_security_group.web.id
    - aws_security_group.web.arn
    - web (exact name match only)
    Never matches if target_name is merely a prefix or substring of token.
    """
    if not token or not isinstance(token, str):
        return False
    cleaned = token.strip()
    if cleaned.startswith("${") and cleaned.endswith("}"):
        cleaned = cleaned[2:-1].strip()

    target_addr = f"{target_type}.{target_name}"
    if cleaned == target_addr:
        return True
    if cleaned.startswith(f"{target_addr}."):
        return True
    if cleaned == target_name:
        return True
    return False


def _matches_cloudformation_reference(token: str, target_name: str) -> bool:
    """
    Check if a token exactly references a CloudFormation logical ID.
    Handles:
    - Exact logical ID: "AppBucket"
    - Attribute ref: "AppBucket.Arn"
    - Fn::Sub expression: "${AppBucket}", "${AppBucket.Arn}"
    Never matches if target_name is merely a substring (e.g. "App" in "AppBucket").
    """
    if not token or not isinstance(token, str):
        return False
    cleaned = token.strip()
    if cleaned == target_name:
        return True
    if cleaned.startswith(f"{target_name}."):
        return True
    sub_pattern = rf"\$\{{\s*{re.escape(target_name)}(?:\.[^}}]+)?\s*\}}"
    if re.search(sub_pattern, cleaned):
        return True
    return False


def _extract_policy_statements(data: Any) -> list[dict[str, Any]]:
    """Recursively extract IAM policy statement dictionaries from arbitrary structures."""
    statements: list[dict[str, Any]] = []
    if not data:
        return statements

    if isinstance(data, str):
        cleaned = data.strip()
        parsed_json = False
        if cleaned.startswith("{") or cleaned.startswith("["):
            try:
                parsed = json.loads(cleaned)
                statements.extend(_extract_policy_statements(parsed))
                parsed_json = True
            except Exception:
                pass

        if not parsed_json and "jsonencode(" in cleaned:
            start_idx = cleaned.find("jsonencode(") + len("jsonencode(")
            end_idx = cleaned.rfind(")")
            inner = cleaned[start_idx:end_idx].strip()
            # Convert HCL map/list syntax to JSON
            json_candidate = re.sub(r'([a-zA-Z0-9_":]+)\s*=', r'"\1":', inner)
            json_candidate = re.sub(r'""([^"]+)""', r'"\1"', json_candidate)
            json_candidate = re.sub(r',\s*([}\]])', r'\1', json_candidate)
            try:
                parsed = json.loads(json_candidate)
                statements.extend(_extract_policy_statements(parsed))
                parsed_json = True
            except Exception:
                pass

        if not parsed_json and ("Statement" in cleaned or "Action" in cleaned or "jsonencode" in cleaned):
            # Split into individual statement blocks delimited by { ... }
            blocks = re.findall(r'\{([^{}]+)\}', cleaned)
            if not blocks:
                blocks = [cleaned]
            for block in blocks:
                act_m = re.findall(r'Action\s*[:=]\s*(?:\[(.*?)\]|["\']([^"\']+)["\'])', block, re.IGNORECASE)
                actions: list[str] = []
                for m in act_m:
                    if m[0]:
                        actions.extend([a.strip(' \t\n\r"\'') for a in m[0].split(",") if a.strip(' \t\n\r"\'')])
                    elif m[1]:
                        actions.append(m[1].strip())

                res_m = re.findall(r'Resource\s*[:=]\s*(?:\[(.*?)\]|["\']([^"\']+)["\'])', block, re.IGNORECASE)
                resources: list[str] = []
                for m in res_m:
                    if m[0]:
                        resources.extend([r.strip(' \t\n\r"\'') for r in m[0].split(",") if r.strip(' \t\n\r"\'')])
                    elif m[1]:
                        resources.append(m[1].strip())

                eff_m = re.search(r'Effect\s*[:=]\s*["\']?(\w+)["\']?', block, re.IGNORECASE)
                effect = eff_m.group(1) if eff_m else "Allow"

                cond_m = re.search(r'Condition\s*[:=]\s*\{([^{}]+)\}', block, re.IGNORECASE)
                cond = {"raw": cond_m.group(1)} if cond_m else None

                if actions or resources:
                    stmt_dict: dict[str, Any] = {
                        "Effect": effect,
                        "Action": actions,
                        "Resource": resources,
                    }
                    if cond:
                        stmt_dict["Condition"] = cond
                    statements.append(stmt_dict)
    elif isinstance(data, dict):
        stmt_data = data.get("Statement") or data.get("statement")
        if stmt_data:
            if isinstance(stmt_data, dict):
                statements.append(stmt_data)
            elif isinstance(stmt_data, list):
                for s in stmt_data:
                    if isinstance(s, dict):
                        statements.append(s)
        if "PolicyDocument" in data:
            statements.extend(_extract_policy_statements(data["PolicyDocument"]))
        if "Policies" in data:
            statements.extend(_extract_policy_statements(data["Policies"]))
        for k in ("policy", "assume_role_policy", "inline_policy"):
            if k in data and data[k] != data:
                statements.extend(_extract_policy_statements(data[k]))
    elif isinstance(data, list):
        for item in data:
            statements.extend(_extract_policy_statements(item))

    return statements


def _action_matches_target(action_str: str, target_type: str) -> tuple[bool, str]:
    """
    Check if an IAM action matches operations for target resource.
    Returns: (matches: bool, action_level: "object" | "bucket" | "all" | "none")
    """
    act = action_str.strip().lower()
    if act == "*":
        return True, "all"

    if target_type in ("aws_s3_bucket", "AWS::S3::Bucket"):
        if act in ("s3:*", "s3:get*", "s3:put*", "s3:object*"):
            return True, "all"
        if act in ("s3:getobject", "s3:getobjectversion", "s3:putobject", "s3:deleteobject", "s3:getobjecttagging"):
            return True, "object"
        if act in ("s3:listbucket", "s3:listbucketversions"):
            return True, "bucket"
        # Pure metadata operations (e.g. location, acl) do not grant object data access
        return False, "none"

    elif target_type in ("aws_db_instance", "AWS::RDS::DBInstance"):
        if act in ("*", "rds:*", "rds-db:*", "rds-db:connect") or act.startswith("rds-db:") or act.startswith("rds:connect"):
            return True, "all"
        if act.startswith("rds:describe"):
            return False, "none"
        if act.startswith("rds:"):
            return True, "all"
        return False, "none"

    elif target_type in ("aws_ebs_volume", "AWS::EC2::Volume"):
        # EC2 Describe actions do NOT grant volume data access
        if act.startswith("ec2:describe"):
            return False, "none"
        # AttachVolume or ModifyVolume alone do NOT grant confirmed data exfiltration
        if act in ("ec2:attachvolume", "ec2:modifyvolume"):
            return False, "none"
        if act in ("*", "ec2:*"):
            return True, "all"
        return False, "none"

    return False, "none"


def _resource_matches_target(
    res_str: str,
    action_level: str,
    target_type: str,
    target_name: str,
    target_attrs: dict[str, Any],
) -> bool:
    """Check whether a Resource string in an IAM statement matches the target resource."""
    if not isinstance(res_str, str):
        return False
    res_cleaned = res_str.strip()
    if res_cleaned == "*":
        return True

    # Terraform address match
    if _matches_terraform_reference(res_cleaned, target_type, target_name):
        return True

    # CloudFormation reference match
    if _matches_cloudformation_reference(res_cleaned, target_name):
        return True

    # S3 ARN matching
    if target_type in ("aws_s3_bucket", "AWS::S3::Bucket"):
        bucket_name = (
            target_attrs.get("bucket")
            or target_attrs.get("BucketName")
            or target_name
        )
        if isinstance(bucket_name, str) and bucket_name:
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            object_arn_prefix = f"arn:aws:s3:::{bucket_name}/"
            exact_object_arn = f"arn:aws:s3:::{bucket_name}/*"

            is_object_arn = (
                res_cleaned == exact_object_arn
                or res_cleaned.startswith(object_arn_prefix)
                or (res_cleaned.endswith("/*") and bucket_name in res_cleaned)
            )
            is_bucket_arn = res_cleaned == bucket_arn

            if is_object_arn:
                # Object ARN matches object-level data actions and wildcard actions
                return action_level in ("object", "all")

            if is_bucket_arn:
                # Bucket ARN matches bucket-level actions and wildcard actions
                # Object-level actions (e.g. s3:GetObject) require an object ARN, not bucket ARN
                if action_level == "object":
                    return False
                return action_level in ("bucket", "all")

            # Check if interpolated: e.g. "${aws_s3_bucket.data.arn}/*"
            if res_cleaned.endswith("/*"):
                base_ref = res_cleaned[:-2]
                if _matches_terraform_reference(base_ref, target_type, target_name):
                    return action_level in ("object", "all")

    # RDS ARN matching
    if target_type in ("aws_db_instance", "AWS::RDS::DBInstance"):
        db_id = (
            target_attrs.get("identifier")
            or target_attrs.get("DBInstanceIdentifier")
            or target_name
        )
        if isinstance(db_id, str) and db_id:
            if res_cleaned.endswith(f":db:{db_id}") or res_cleaned.endswith(f":{db_id}"):
                return True

    # EBS Volume ARN matching
    if target_type in ("aws_ebs_volume", "AWS::EC2::Volume"):
        vol_id = (
            target_attrs.get("id")
            or target_attrs.get("VolumeId")
            or target_name
        )
        if isinstance(vol_id, str) and vol_id:
            if res_cleaned.endswith(f":volume/{vol_id}") or res_cleaned.endswith(f":{vol_id}"):
                return True

    return False


def _evaluate_statement_condition(condition: Any) -> str:
    """
    Evaluate condition block on an IAM statement.
    Returns:
    - "unconditional": no condition present
    - "static_allow": static condition allowing standard access (e.g. Bool aws:SecureTransport=false in Deny)
    - "unsupported": condition involves dynamic context keys that cannot be statically resolved
    """
    if not condition or not isinstance(condition, dict):
        return "unconditional"

    bool_cond = condition.get("Bool") or condition.get("bool")
    if isinstance(bool_cond, dict):
        sec_trans = bool_cond.get("aws:SecureTransport")
        if sec_trans is False or str(sec_trans).lower() == "false":
            return "static_allow"

    return "unsupported"


def _policy_grants_access_to_resource(
    statements: list[dict[str, Any]],
    target_type: str,
    target_name: str,
    target_attrs: dict[str, Any],
) -> tuple[bool, bool]:
    """
    Evaluate a set of IAM policy statements for a target resource using AWS IAM semantics:
    1. Check explicit Deny statements first.
       - Unconditional matching Deny -> returns (False, False) immediately.
       - Matching Deny with static allow condition (e.g. SecureTransport=false) -> does not block.
       - Matching Deny with unsupported dynamic condition -> does not block universally, but flags provisional.
    2. Check explicit Allow statements.
       - Matching Allow -> returns (True, is_provisional).
    3. Default -> returns (False, False).
    """
    has_matching_allow = False
    is_provisional = False

    # Pass 1: Explicit Deny
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = str(stmt.get("Effect", "")).strip().lower()
        if effect != "deny":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(resources, list):
            continue

        for act in actions:
            act_matches, act_level = _action_matches_target(str(act), target_type)
            if not act_matches:
                continue

            for res in resources:
                if _resource_matches_target(str(res), act_level, target_type, target_name, target_attrs):
                    cond_type = _evaluate_statement_condition(stmt.get("Condition") or stmt.get("condition"))
                    if cond_type == "unconditional":
                        return False, False
                    elif cond_type == "static_allow":
                        pass
                    elif cond_type == "unsupported":
                        is_provisional = True

    # Pass 2: Explicit Allow
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = str(stmt.get("Effect", "Allow")).strip().lower()
        if effect != "allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(resources, list):
            continue

        for act in actions:
            act_matches, act_level = _action_matches_target(str(act), target_type)
            if not act_matches:
                continue

            for res in resources:
                if _resource_matches_target(str(res), act_level, target_type, target_name, target_attrs):
                    cond_type = _evaluate_statement_condition(stmt.get("Condition") or stmt.get("condition"))
                    if cond_type == "unsupported":
                        is_provisional = True
                    has_matching_allow = True
                    break
            if has_matching_allow:
                break

    return has_matching_allow, is_provisional


def _policy_statement_grants_access(
    stmt: dict[str, Any],
    target_type: str,
    target_name: str,
    target_attrs: dict[str, Any],
) -> bool:
    """Evaluate a single statement (delegates to _policy_grants_access_to_resource)."""
    grants, _ = _policy_grants_access_to_resource([stmt], target_type, target_name, target_attrs)
    return grants


def _rule_grants_secret_read(rule: dict[str, Any], secret_name: str | None = None) -> bool:
    """Check if an RBAC rule authorizes reading/exfiltrating secrets."""
    if not isinstance(rule, dict):
        return False
    resources = rule.get("resources", [])
    if isinstance(resources, str):
        resources = [resources]
    verbs = rule.get("verbs", [])
    if isinstance(verbs, str):
        verbs = [verbs]
    api_groups = rule.get("apiGroups", [])
    if isinstance(api_groups, str):
        api_groups = [api_groups]
    resource_names = rule.get("resourceNames", [])
    if isinstance(resource_names, str):
        resource_names = [resource_names]

    # Validate resources
    norm_resources = [str(r).strip().lower() for r in resources if isinstance(r, str)]
    has_secret_res = "*" in norm_resources or "secrets" in norm_resources or "secrets/*" in norm_resources
    if not has_secret_res:
        return False

    # Validate API groups: core group is "" or "*"
    norm_api_groups = [str(ag).strip().lower() for ag in api_groups if isinstance(ag, str)]
    if api_groups and not any(ag in ("", "*") for ag in norm_api_groups):
        return False

    # Normalize verbs
    norm_verbs = {str(v).strip().lower() for v in verbs if isinstance(v, str)}
    read_verbs = {"get", "list", "watch", "*"}
    has_read_verb = bool(norm_verbs & read_verbs)
    if not has_read_verb:
        return False

    # Validate resourceNames restrictions
    if resource_names:
        norm_res_names = {str(rn).strip() for rn in resource_names if isinstance(rn, str)}
        if secret_name:
            if secret_name not in norm_res_names and "*" not in norm_res_names:
                return False
            # When resourceNames is restricted, direct secret retrieval requires 'get' or '*'
            # In Kubernetes RBAC, list/watch by collection does not support resourceNames without
            # client metadata.name field-selectors which cannot be established statically from IaC.
            if "get" not in norm_verbs and "*" not in norm_verbs:
                return False

    return True


def _get_k8s_namespace(nr: NormalizedResource | GraphNode) -> str:
    """Extract namespace for Kubernetes resource, returning empty string for cluster-scoped resources."""
    res_type = getattr(nr, "resource_type", "") or getattr(nr, "type", "")
    if res_type in CLUSTER_SCOPED_KINDS:
        return ""
    ns = getattr(nr, "namespace", "") or ""
    if not ns and isinstance(getattr(nr, "attributes", None), dict):
        metadata = nr.attributes.get("metadata", {})
        if isinstance(metadata, dict):
            ns = metadata.get("namespace", "")
    if not ns and hasattr(nr, "id") and "." in nr.id:
        parts = nr.id.split(".")
        if len(parts) >= 3 and parts[0] not in CLUSTER_SCOPED_KINDS:
            return parts[1]
    return ns or "default"


# ---------------------------------------------------------------------------
# Component Classifier
# ---------------------------------------------------------------------------


def classify_resource(
    res_id: str,
    res_type: str,
    attributes: dict[str, Any],
    source_format: str,
    findings: list[dict[str, Any]],
) -> set[str]:
    """
    Classify a resource into one or more categories based on its type,
    attributes, and detected security findings.
    """
    categories: set[str] = set()
    finding_threat_ids = {f.get("threat_id") for f in findings}

    # -----------------------------------------------------------------------
    # Terraform Classification
    # -----------------------------------------------------------------------
    if source_format == IaCFormat.TERRAFORM.value:
        # 1. Entry Points
        if res_type == "aws_security_group":
            ingress_rules = attributes.get("ingress", [])
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]
            is_public_ingress = False
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    cidrs = rule.get("cidr_blocks", [])
                    if isinstance(cidrs, str):
                        cidrs = [cidrs]
                    if any("0.0.0.0/0" in c or "::/0" in c for c in cidrs if isinstance(c, str)):
                        is_public_ingress = True
                        break
            if is_public_ingress or "THREAT-001" in finding_threat_ids or "THREAT-002" in finding_threat_ids:
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type in ("aws_lb", "aws_elb"):
            internal = attributes.get("internal", False)
            if internal is False or str(internal).lower() == "false":
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "aws_internet_gateway":
            categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "aws_s3_bucket":
            acl = str(attributes.get("acl", "")).lower()
            if (
                acl in ("public-read", "public-read-write")
                or "THREAT-001" in finding_threat_ids
                or "THREAT-002" in finding_threat_ids
            ):
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "aws_db_instance":
            pub = attributes.get("publicly_accessible", False)
            if pub is True or str(pub).lower() == "true" or "THREAT-004" in finding_threat_ids:
                categories.add(CATEGORY_ENTRY_POINT)

        # 2. Workloads
        if res_type in WORKLOAD_TYPES_TF:
            categories.add(CATEGORY_WORKLOAD)

        # 3. Privileges
        if res_type in PRIVILEGE_TYPES_TF:
            categories.add(CATEGORY_PRIVILEGE)

        # 4. Sensitive Resources
        if res_type in SENSITIVE_TYPES_TF:
            categories.add(CATEGORY_SENSITIVE)

    # -----------------------------------------------------------------------
    # CloudFormation Classification
    # -----------------------------------------------------------------------
    elif source_format == IaCFormat.CLOUDFORMATION.value:
        # 1. Entry Points
        if res_type == "AWS::EC2::SecurityGroup":
            ingress_rules = attributes.get("SecurityGroupIngress", [])
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]
            is_public_ingress = False
            for rule in ingress_rules:
                if isinstance(rule, dict):
                    cidr = rule.get("CidrIp") or rule.get("CidrIpv6") or ""
                    if "0.0.0.0/0" in cidr or "::/0" in cidr:
                        is_public_ingress = True
                        break
            if is_public_ingress or "CFN-004" in finding_threat_ids:
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            lb_type = str(attributes.get("Type", "application")).strip().lower()
            if lb_type == "gateway":
                # Gateway Load Balancers are transparent in-VPC appliances; Scheme is invalid and not an internet entry point
                pass
            else:
                # ALB and NLB default to internet-facing in CloudFormation if Scheme is omitted
                scheme = str(attributes.get("Scheme", "internet-facing")).strip().lower()
                if scheme == "internet-facing":
                    categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "AWS::ElasticLoadBalancing::LoadBalancer":
            # Classic Load Balancers in CloudFormation default to internet-facing if Scheme is omitted
            scheme = str(attributes.get("Scheme", "internet-facing")).strip().lower()
            if scheme == "internet-facing":
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "AWS::EC2::InternetGateway":
            categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "AWS::S3::Bucket":
            acl = str(attributes.get("AccessControl", "")).lower()
            if (
                acl in ("publicread", "publicreadwrite", "authenticatedread")
                or "CFN-001" in finding_threat_ids
            ):
                categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "AWS::RDS::DBInstance":
            pub = attributes.get("PubliclyAccessible", False)
            if pub is True or str(pub).lower() == "true":
                categories.add(CATEGORY_ENTRY_POINT)

        # 2. Workloads
        if res_type in WORKLOAD_TYPES_CFN:
            categories.add(CATEGORY_WORKLOAD)

        # 3. Privileges
        if res_type in PRIVILEGE_TYPES_CFN:
            categories.add(CATEGORY_PRIVILEGE)

        # 4. Sensitive Resources
        if res_type in SENSITIVE_TYPES_CFN:
            categories.add(CATEGORY_SENSITIVE)

    # -----------------------------------------------------------------------
    # Kubernetes Classification
    # -----------------------------------------------------------------------
    elif source_format == IaCFormat.KUBERNETES.value:
        # 1. Entry Points
        if res_type == "Ingress":
            categories.add(CATEGORY_ENTRY_POINT)

        elif res_type == "Service":
            svc_type = (
                attributes.get("security_metadata", {}).get("type")
                or attributes.get("type")
                or "ClusterIP"
            )
            if svc_type in ("LoadBalancer", "NodePort") or "K8S-007" in finding_threat_ids:
                categories.add(CATEGORY_ENTRY_POINT)

        # 2. Workloads
        if res_type in WORKLOAD_KINDS_K8S:
            categories.add(CATEGORY_WORKLOAD)

        # 3. Privileges
        if res_type in PRIVILEGE_KINDS_K8S:
            categories.add(CATEGORY_PRIVILEGE)

        # 4. Sensitive Resources
        if res_type in SENSITIVE_KINDS_K8S:
            categories.add(CATEGORY_SENSITIVE)

    if not categories:
        categories.add(CATEGORY_STANDARD)

    return categories


# ---------------------------------------------------------------------------
# Graph Builder Across IaC Formats
# ---------------------------------------------------------------------------


def build_directed_attack_graph(
    resources: list[dict[str, Any]],
    threat_findings: list[dict[str, Any]],
    source_format: str,
    normalized_infrastructure: NormalizedInfrastructure | None = None,
) -> DirectedAttackGraph:
    """
    Construct a directed attack graph with classified nodes and resolved relationship edges.
    """
    graph = DirectedAttackGraph(source_format=source_format)

    # Map findings by affected resource ID
    findings_by_resource: dict[str, list[dict[str, Any]]] = {}
    for f in threat_findings:
        target_id = f.get("affected_resource_id") or f.get("resource_id")
        if target_id:
            findings_by_resource.setdefault(target_id, []).append(f)

    # 1. Create all GraphNodes
    norm_res_map: dict[str, NormalizedResource] = {}
    if normalized_infrastructure:
        for nr in normalized_infrastructure.resources:
            norm_res_map[nr.id] = nr

    for r in resources:
        res_type = str(r.get("type", ""))
        name = str(r.get("name", ""))
        attrs = dict(r.get("attributes", {}) or {})

        # Compute stable resource ID consistent with normalized models
        if normalized_infrastructure:
            # Match normalized resource
            matching_nr = None
            for nr in normalized_infrastructure.resources:
                if nr.type == res_type and nr.name == name:
                    matching_nr = nr
                    break
            res_id = matching_nr.id if matching_nr else f"{res_type}.{name}"
        else:
            res_id = f"{res_type}.{name}"

        node_findings = findings_by_resource.get(res_id, [])
        cats = classify_resource(res_id, res_type, attrs, source_format, node_findings)

        node = GraphNode(
            id=res_id,
            name=name,
            resource_type=res_type,
            source_format=source_format,
            categories=cats,
            attributes=attrs,
            findings=node_findings,
        )
        graph.add_node(node)

    # 2. Resolve Relationships and Add Edges
    if source_format == IaCFormat.TERRAFORM.value:
        _resolve_terraform_edges(graph, resources)
    elif source_format == IaCFormat.CLOUDFORMATION.value:
        _resolve_cloudformation_edges(graph, normalized_infrastructure)
    elif source_format == IaCFormat.KUBERNETES.value:
        _resolve_kubernetes_edges(graph, normalized_infrastructure)

    return graph


# ---------------------------------------------------------------------------
# Format-Specific Relationship Resolvers
# ---------------------------------------------------------------------------


def _resolve_terraform_edges(
    graph: DirectedAttackGraph,
    resources: list[dict[str, Any]],
) -> None:
    """Build directed relationships for Terraform resources."""
    res_ids_by_type: dict[str, list[str]] = {}
    for r in resources:
        t = str(r.get("type", ""))
        n = str(r.get("name", ""))
        res_ids_by_type.setdefault(t, []).append(f"{t}.{n}")

    for r in resources:
        source_type = str(r.get("type", ""))
        source_name = str(r.get("name", ""))
        source_id = f"{source_type}.{source_name}"
        attrs = r.get("attributes", {}) or {}

        # A. EC2 Instance -> Security Groups (Inverted: SG exposes Instance)
        if source_type == "aws_instance":
            sg_refs: list[str] = []
            for sg_field in ("vpc_security_group_ids", "security_groups"):
                val = attrs.get(sg_field)
                if val:
                    sg_refs.extend(_collect_string_leaves(val))

            for ref in sg_refs:
                matched_sg = False
                for sg_id in res_ids_by_type.get("aws_security_group", []):
                    sg_name = sg_id.split(".", 1)[1]
                    if _matches_terraform_reference(ref, "aws_security_group", sg_name):
                        graph.add_edge(
                            source_id=sg_id,
                            target_id=source_id,
                            relationship="exposes",
                            details="Security group controls inbound network traffic reaching this EC2 instance.",
                        )
                        matched_sg = True
                if not matched_sg and ref.strip():
                    graph.nodes[source_id].unresolved_references.append(ref.strip())

            # Instance -> IAM Instance Profile -> IAM Role
            profile_val = attrs.get("iam_instance_profile")
            if profile_val:
                prof_tokens = _collect_string_leaves(profile_val)
                matched_role = False
                for prof_token in prof_tokens:
                    # 1. Direct role reference
                    for role_id in res_ids_by_type.get("aws_iam_role", []):
                        role_name = role_id.split(".", 1)[1]
                        if _matches_terraform_reference(prof_token, "aws_iam_role", role_name):
                            graph.add_edge(
                                source_id=source_id,
                                target_id=role_id,
                                relationship="assumes_role",
                                details="EC2 instance executes with privileges granted by IAM role.",
                            )
                            matched_role = True

                    # 2. Instance profile reference
                    for prof_id in res_ids_by_type.get("aws_iam_instance_profile", []):
                        prof_name = prof_id.split(".", 1)[1]
                        if _matches_terraform_reference(prof_token, "aws_iam_instance_profile", prof_name):
                            prof_node = graph.nodes.get(prof_id)
                            if prof_node:
                                prof_role_val = prof_node.attributes.get("role", "")
                                prof_role_tokens = _collect_string_leaves(prof_role_val)
                                for r_token in prof_role_tokens:
                                    for role_id in res_ids_by_type.get("aws_iam_role", []):
                                        role_name = role_id.split(".", 1)[1]
                                        if _matches_terraform_reference(r_token, "aws_iam_role", role_name):
                                            graph.add_edge(
                                                source_id=source_id,
                                                target_id=role_id,
                                                relationship="assumes_role",
                                                details="EC2 instance assumes IAM role via IAM instance profile.",
                                            )
                                            matched_role = True
                    if not matched_role and prof_token.strip():
                        graph.nodes[source_id].unresolved_references.append(prof_token.strip())

            # Instance -> Attached Storage via direct volume reference
            vol_refs: list[str] = []
            for vol_field in ("ebs_block_device", "volume_id"):
                val = attrs.get(vol_field)
                if val:
                    vol_refs.extend(_collect_string_leaves(val))
            for v_ref in vol_refs:
                for vol_id in res_ids_by_type.get("aws_ebs_volume", []):
                    vol_name = vol_id.split(".", 1)[1]
                    if _matches_terraform_reference(v_ref, "aws_ebs_volume", vol_name):
                        graph.add_edge(
                            source_id=source_id,
                            target_id=vol_id,
                            relationship="attaches_storage",
                            details="EC2 instance has EBS storage volume attached.",
                        )

        # B. Volume Attachment: aws_volume_attachment
        elif source_type == "aws_volume_attachment":
            inst_tokens = _collect_string_leaves(attrs.get("instance_id"))
            vol_tokens = _collect_string_leaves(attrs.get("volume_id"))
            matched_inst_id = None
            matched_vol_id = None
            for it in inst_tokens:
                for inst_id in res_ids_by_type.get("aws_instance", []):
                    inst_name = inst_id.split(".", 1)[1]
                    if _matches_terraform_reference(it, "aws_instance", inst_name):
                        matched_inst_id = inst_id
                        break
            for vt in vol_tokens:
                for vol_id in res_ids_by_type.get("aws_ebs_volume", []):
                    vol_name = vol_id.split(".", 1)[1]
                    if _matches_terraform_reference(vt, "aws_ebs_volume", vol_name):
                        matched_vol_id = vol_id
                        break
            if matched_inst_id and matched_vol_id:
                graph.add_edge(
                    source_id=matched_inst_id,
                    target_id=matched_vol_id,
                    relationship="attaches_storage",
                    details="EC2 instance has EBS storage volume attached via aws_volume_attachment.",
                )

        # C. IAM Role Policy Attachment: aws_iam_role_policy_attachment
        elif source_type == "aws_iam_role_policy_attachment":
            role_tokens = _collect_string_leaves(attrs.get("role"))
            policy_tokens = _collect_string_leaves(attrs.get("policy_arn"))
            matched_role_id = None
            matched_policy_id = None

            for rt in role_tokens:
                for r_id in res_ids_by_type.get("aws_iam_role", []):
                    r_name = r_id.split(".", 1)[1]
                    if _matches_terraform_reference(rt, "aws_iam_role", r_name):
                        matched_role_id = r_id
                        break
            if not matched_role_id and role_tokens:
                graph.nodes[source_id].unresolved_references.extend(role_tokens)

            for pt in policy_tokens:
                for p_id in res_ids_by_type.get("aws_iam_policy", []):
                    p_name = p_id.split(".", 1)[1]
                    p_node = graph.nodes.get(p_id)
                    p_node_name = p_node.attributes.get("name", p_name) if p_node else p_name
                    if (
                        _matches_terraform_reference(pt, "aws_iam_policy", p_name)
                        or pt == p_name
                        or pt == p_node_name
                        or pt.endswith(f"/{p_name}")
                        or pt.endswith(f":policy/{p_name}")
                    ):
                        matched_policy_id = p_id
                        break
            if not matched_policy_id and policy_tokens:
                graph.nodes[source_id].unresolved_references.extend(policy_tokens)

            if matched_role_id and matched_policy_id:
                graph.add_edge(
                    source_id=matched_role_id,
                    target_id=source_id,
                    relationship="attaches_policy",
                    details="IAM role attaches IAM policy via aws_iam_role_policy_attachment.",
                )
                graph.add_edge(
                    source_id=source_id,
                    target_id=matched_policy_id,
                    relationship="applies_policy",
                    details="Policy attachment binds permissions of IAM policy to role.",
                )

        # D. IAM Policy -> Sensitive Targets
        elif source_type == "aws_iam_policy":
            has_wildcard_admin = any(
                f.get("threat_id") == "THREAT-006" for f in graph.nodes[source_id].findings
            )
            statements = _extract_policy_statements(attrs)

            # S3 Buckets
            for bucket_id in res_ids_by_type.get("aws_s3_bucket", []):
                b_name = bucket_id.split(".", 1)[1]
                b_node = graph.nodes.get(bucket_id)
                b_attrs = b_node.attributes if b_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_s3_bucket", b_name, b_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=bucket_id,
                        relationship="grants_access",
                        details=(
                            "IAM policy grants administrative wildcard access to S3 bucket."
                            if has_wildcard_admin
                            else "IAM policy permits operations on S3 bucket."
                        ),
                        is_confirmed=not is_prov,
                    )

            # RDS Databases
            for db_id in res_ids_by_type.get("aws_db_instance", []):
                db_name = db_id.split(".", 1)[1]
                db_node = graph.nodes.get(db_id)
                db_attrs = db_node.attributes if db_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_db_instance", db_name, db_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=db_id,
                        relationship="grants_access",
                        details=(
                            "IAM policy grants administrative wildcard access to database."
                            if has_wildcard_admin
                            else "IAM policy permits access to RDS database."
                        ),
                        is_confirmed=not is_prov,
                    )

            # EBS Volumes
            for vol_id in res_ids_by_type.get("aws_ebs_volume", []):
                vol_name = vol_id.split(".", 1)[1]
                v_node = graph.nodes.get(vol_id)
                v_attrs = v_node.attributes if v_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_ebs_volume", vol_name, v_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=vol_id,
                        relationship="grants_access",
                        details=(
                            "IAM policy grants administrative wildcard access to EBS volume."
                            if has_wildcard_admin
                            else "IAM policy permits operations on EBS volume."
                        ),
                        is_confirmed=not is_prov,
                    )

        # E. IAM Role -> Sensitive Targets (inline policies or wildcard admin on role itself)
        elif source_type == "aws_iam_role":
            has_wildcard_admin = any(
                f.get("threat_id") == "THREAT-006" for f in graph.nodes[source_id].findings
            )
            statements = _extract_policy_statements(attrs)

            # S3 Buckets
            for bucket_id in res_ids_by_type.get("aws_s3_bucket", []):
                bucket_name = bucket_id.split(".", 1)[1]
                b_node = graph.nodes.get(bucket_id)
                b_attrs = b_node.attributes if b_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_s3_bucket", bucket_name, b_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=bucket_id,
                        relationship="grants_access",
                        details=(
                            "IAM role grants administrative wildcard access to S3 bucket."
                            if has_wildcard_admin
                            else "IAM role policy permits operations on S3 bucket."
                        ),
                        is_confirmed=not is_prov,
                    )

            # RDS Databases
            for db_id in res_ids_by_type.get("aws_db_instance", []):
                db_name = db_id.split(".", 1)[1]
                db_node = graph.nodes.get(db_id)
                db_attrs = db_node.attributes if db_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_db_instance", db_name, db_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=db_id,
                        relationship="grants_access",
                        details=(
                            "IAM role grants administrative wildcard access to database."
                            if has_wildcard_admin
                            else "IAM role grants access to RDS database."
                        ),
                        is_confirmed=not is_prov,
                    )

            # EBS Volumes
            for vol_id in res_ids_by_type.get("aws_ebs_volume", []):
                vol_name = vol_id.split(".", 1)[1]
                v_node = graph.nodes.get(vol_id)
                v_attrs = v_node.attributes if v_node else {}
                grants, is_prov = _policy_grants_access_to_resource(statements, "aws_ebs_volume", vol_name, v_attrs)
                if has_wildcard_admin or grants:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=vol_id,
                        relationship="grants_access",
                        details=(
                            "IAM role grants administrative wildcard access to EBS volume."
                            if has_wildcard_admin
                            else "IAM role permits operations on EBS volume."
                        ),
                        is_confirmed=not is_prov,
                    )

        # F. Load Balancers -> Workloads
        elif source_type in ("aws_lb", "aws_elb"):
            inst_refs = _collect_string_leaves(attrs.get("instances", []))
            for inst_ref in inst_refs:
                for inst_id in res_ids_by_type.get("aws_instance", []):
                    inst_name = inst_id.split(".", 1)[1]
                    if _matches_terraform_reference(inst_ref, "aws_instance", inst_name):
                        graph.add_edge(
                            source_id=source_id,
                            target_id=inst_id,
                            relationship="routes_to",
                            details="Load balancer distributes external traffic to EC2 instance.",
                        )


def _resolve_cloudformation_edges(
    graph: DirectedAttackGraph,
    normalized_infrastructure: NormalizedInfrastructure | None,
) -> None:
    """Build directed relationships for CloudFormation resources."""
    if not normalized_infrastructure:
        return

    res_by_logical_id: dict[str, NormalizedResource] = {}
    for nr in normalized_infrastructure.resources:
        res_by_logical_id[nr.name] = nr

    for nr in normalized_infrastructure.resources:
        source_id = nr.id
        source_type = nr.type
        logical_id = nr.name
        attrs = nr.attributes

        # 1. EC2 Instance -> Security Groups (Invert: SG exposes Instance)
        if source_type == "AWS::EC2::Instance":
            sg_refs = []
            sg_val = attrs.get("SecurityGroupIds") or attrs.get("SecurityGroups")
            if sg_val:
                sg_refs.extend(_collect_string_leaves(sg_val))

            for ref in sg_refs:
                target_nr = res_by_logical_id.get(ref)
                if target_nr and target_nr.type == "AWS::EC2::SecurityGroup":
                    graph.add_edge(
                        source_id=target_nr.id,
                        target_id=source_id,
                        relationship="exposes",
                        details="Security group governs inbound traffic to EC2 instance.",
                    )
                else:
                    graph.nodes[source_id].unresolved_references.append(ref)

            # Instance -> IAM Role (via IamInstanceProfile)
            profile_val = attrs.get("IamInstanceProfile")
            if profile_val:
                prof_refs = _collect_string_leaves(profile_val)
                matched = False
                for ref in prof_refs:
                    target_nr = res_by_logical_id.get(ref)
                    if target_nr:
                        if target_nr.type == "AWS::IAM::Role":
                            graph.add_edge(
                                source_id=source_id,
                                target_id=target_nr.id,
                                relationship="assumes_role",
                                details="EC2 instance executes with privileges of IAM role.",
                            )
                            matched = True
                        elif target_nr.type == "AWS::IAM::InstanceProfile":
                            # Look for role in profile
                            roles = _collect_string_leaves(target_nr.attributes.get("Roles", []))
                            for r_ref in roles:
                                role_nr = res_by_logical_id.get(r_ref)
                                if role_nr and role_nr.type == "AWS::IAM::Role":
                                    graph.add_edge(
                                        source_id=source_id,
                                        target_id=role_nr.id,
                                        relationship="assumes_role",
                                        details="EC2 instance assumes IAM role via InstanceProfile.",
                                    )
                                    matched = True
                if not matched:
                    graph.nodes[source_id].unresolved_references.extend(prof_refs)

        # 2. Lambda Function -> IAM Role
        elif source_type == "AWS::Lambda::Function":
            role_val = attrs.get("Role")
            if role_val:
                refs = _collect_string_leaves(role_val)
                matched = False
                for ref in refs:
                    target_nr = res_by_logical_id.get(ref)
                    if target_nr and target_nr.type == "AWS::IAM::Role":
                        graph.add_edge(
                            source_id=source_id,
                            target_id=target_nr.id,
                            relationship="assumes_role",
                            details="Lambda function assumes IAM execution role.",
                        )
                        matched = True
                if not matched:
                    graph.nodes[source_id].unresolved_references.extend(refs)

        # 3. IAM Role -> Sensitive Targets (S3 Buckets, DBs) via inline policies or wildcard admin
        elif source_type == "AWS::IAM::Role":
            has_wildcard_admin = any(
                f.get("threat_id") == "CFN-003" for f in graph.nodes[source_id].findings
            )
            statements = _extract_policy_statements(attrs)

            for other_nr in normalized_infrastructure.resources:
                if other_nr.type in ("AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::EC2::Volume"):
                    grants, is_prov = _policy_grants_access_to_resource(
                        statements, other_nr.type, other_nr.name, other_nr.attributes
                    )
                    if grants or has_wildcard_admin:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=other_nr.id,
                            relationship="grants_access",
                            details=(
                                f"IAM role has wildcard administrative permissions over {other_nr.name}."
                                if has_wildcard_admin
                                else f"IAM role policy permits access to {other_nr.name}."
                            ),
                            is_confirmed=not is_prov,
                        )

        # 4. Standalone IAM Policy: AWS::IAM::Policy
        elif source_type == "AWS::IAM::Policy":
            role_tokens = _collect_string_leaves(attrs.get("Roles", []))
            matched_roles: list[NormalizedResource] = []
            for rt in role_tokens:
                matched = False
                for r_nr in normalized_infrastructure.resources:
                    if r_nr.type == "AWS::IAM::Role":
                        if _matches_cloudformation_reference(rt, r_nr.name):
                            matched_roles.append(r_nr)
                            matched = True
                            break
                if not matched and rt.strip():
                    graph.nodes[source_id].unresolved_references.append(f"Role:{rt.strip()}")

            for role_nr in matched_roles:
                graph.add_edge(
                    source_id=role_nr.id,
                    target_id=source_id,
                    relationship="attaches_policy",
                    details=f"IAM role '{role_nr.name}' attaches standalone IAM policy '{nr.name}'.",
                )

            # Evaluate PolicyDocument statements against represented sensitive targets
            statements = _extract_policy_statements(attrs.get("PolicyDocument") or attrs)
            for other_nr in normalized_infrastructure.resources:
                if other_nr.type in ("AWS::S3::Bucket", "AWS::RDS::DBInstance", "AWS::EC2::Volume"):
                    grants, is_prov = _policy_grants_access_to_resource(
                        statements, other_nr.type, other_nr.name, other_nr.attributes
                    )
                    if grants:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=other_nr.id,
                            relationship="grants_access",
                            details=f"Standalone IAM policy '{nr.name}' permits access to {other_nr.name}.",
                            is_confirmed=not is_prov,
                        )

        # 5. Volume Attachment: AWS::EC2::VolumeAttachment
        elif source_type == "AWS::EC2::VolumeAttachment":
            inst_refs = _collect_string_leaves(attrs.get("InstanceId"))
            vol_refs = _collect_string_leaves(attrs.get("VolumeId"))

            matched_inst: NormalizedResource | None = None
            matched_vol: NormalizedResource | None = None

            for inst_ref in inst_refs:
                inst_nr = res_by_logical_id.get(inst_ref)
                if inst_nr and inst_nr.type == "AWS::EC2::Instance":
                    matched_inst = inst_nr
                    break
                elif inst_ref.strip():
                    graph.nodes[source_id].unresolved_references.append(f"InstanceId:{inst_ref.strip()}")

            for vol_ref in vol_refs:
                vol_nr = res_by_logical_id.get(vol_ref)
                if vol_nr and vol_nr.type == "AWS::EC2::Volume":
                    matched_vol = vol_nr
                    break
                elif vol_ref.strip():
                    graph.nodes[source_id].unresolved_references.append(f"VolumeId:{vol_ref.strip()}")

            # If both instance and volume exist in template, connect via VolumeAttachment intermediate node
            if matched_inst and matched_vol:
                graph.add_edge(
                    source_id=matched_inst.id,
                    target_id=source_id,
                    relationship="attaches_storage",
                    details=f"EC2 instance attaches storage via VolumeAttachment '{nr.name}'.",
                )
                graph.add_edge(
                    source_id=source_id,
                    target_id=matched_vol.id,
                    relationship="mounts_volume",
                    details=f"VolumeAttachment '{nr.name}' mounts EBS volume to instance.",
                )


def _resolve_kubernetes_edges(
    graph: DirectedAttackGraph,
    normalized_infrastructure: NormalizedInfrastructure | None,
) -> None:
    """Build directed relationships for Kubernetes resources with namespace isolation."""
    if not normalized_infrastructure:
        return

    # Index resources by (kind, namespace, name). For cluster-scoped kinds, namespace is "".
    by_kind_ns_name: dict[tuple[str, str, str], NormalizedResource] = {}
    for nr in normalized_infrastructure.resources:
        ns = _get_k8s_namespace(nr)
        by_kind_ns_name[(nr.type, ns, nr.name)] = nr

    # Identify cluster-wide roles bound by ClusterRoleBinding, and namespaces bound by RoleBinding
    cluster_wide_roles: set[str] = set()
    cluster_role_namespaces: dict[str, set[str]] = {}

    for nr in normalized_infrastructure.resources:
        attrs = nr.attributes or {}
        sec_meta = attrs.get("security_metadata", {}) or {}
        role_ref = attrs.get("roleRef", {}) or sec_meta.get("roleRef", {})
        role_kind = role_ref.get("kind", "Role")
        role_name = role_ref.get("name")

        if nr.type == "ClusterRoleBinding" and role_kind == "ClusterRole" and role_name:
            crole = by_kind_ns_name.get(("ClusterRole", "", role_name))
            if crole:
                cluster_wide_roles.add(crole.id)

        elif nr.type == "RoleBinding" and role_kind == "ClusterRole" and role_name:
            rb_ns = _get_k8s_namespace(nr)
            crole = by_kind_ns_name.get(("ClusterRole", "", role_name))
            if crole:
                cluster_role_namespaces.setdefault(crole.id, set()).add(rb_ns)

    for nr in normalized_infrastructure.resources:
        source_id = nr.id
        kind = nr.type
        name = nr.name
        ns = _get_k8s_namespace(nr)
        attrs = nr.attributes or {}
        sec_meta = attrs.get("security_metadata", {}) or {}

        # 1. Ingress -> Service (Must be in same namespace)
        if kind == "Ingress":
            for rel in nr.relationships:
                if rel.startswith("Service."):
                    svc_name = rel.split(".", 1)[1]
                    target_nr = by_kind_ns_name.get(("Service", ns, svc_name))
                    if target_nr:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=target_nr.id,
                            relationship="routes_to",
                            details="Ingress routes external HTTP/HTTPS traffic to backend Service.",
                        )
                    else:
                        graph.nodes[source_id].unresolved_references.append(f"Service.{svc_name}")

        # 2. Service -> Workloads (matched via selector within namespace by parser)
        elif kind == "Service":
            for rel_id in nr.relationships:
                if rel_id in graph.nodes:
                    graph.add_edge(
                        source_id=source_id,
                        target_id=rel_id,
                        relationship="routes_to",
                        details="Service routes traffic to matched workload pods.",
                    )

        # 3. Workload (Pod, Deployment, etc.) -> ServiceAccount & Storage (Secrets)
        elif kind in WORKLOAD_KINDS_K8S:
            for rel in nr.relationships:
                if rel.startswith("ServiceAccount."):
                    sa_name = rel.split(".", 1)[1]
                    sa_nr = by_kind_ns_name.get(("ServiceAccount", ns, sa_name))
                    if sa_nr:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=sa_nr.id,
                            relationship="assumes_identity",
                            details="Workload executes using ServiceAccount credentials and RBAC identity.",
                        )
                    else:
                        graph.nodes[source_id].unresolved_references.append(f"ServiceAccount.{sa_name}")

                elif rel.startswith("Secret."):
                    secret_name = rel.split(".", 1)[1]
                    secret_nr = by_kind_ns_name.get(("Secret", ns, secret_name))
                    if secret_nr:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=secret_nr.id,
                            relationship="accesses_secret",
                            details="Workload mounts or references sensitive credentials from Secret.",
                        )
                    else:
                        graph.nodes[source_id].unresolved_references.append(f"Secret.{secret_name}")

                elif rel.startswith("PersistentVolumeClaim."):
                    pvc_name = rel.split(".", 1)[1]
                    pvc_nr = by_kind_ns_name.get(("PersistentVolumeClaim", ns, pvc_name))
                    if pvc_nr:
                        graph.add_edge(
                            source_id=source_id,
                            target_id=pvc_nr.id,
                            relationship="mounts_storage",
                            details="Workload mounts persistent volume claim storage.",
                        )

        # 4. RoleBinding / ClusterRoleBinding -> Role / ClusterRole & Subjects
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = attrs.get("roleRef", {}) or sec_meta.get("roleRef", {})
            ref_kind = role_ref.get("kind", "Role")
            ref_name = role_ref.get("name")
            if ref_kind == "ClusterRole":
                target_role = by_kind_ns_name.get(("ClusterRole", "", ref_name))
            else:
                target_role = by_kind_ns_name.get(("Role", ns, ref_name))

            subjects = attrs.get("subjects", []) or sec_meta.get("subjects", [])
            for sub in subjects:
                sub_kind = sub.get("kind", "ServiceAccount")
                sub_name = sub.get("name")
                sub_ns = sub.get("namespace") or ns or "default"
                sa_nr = by_kind_ns_name.get((sub_kind, sub_ns, sub_name))

                if sa_nr and target_role:
                    # Link ServiceAccount -> RoleBinding -> Role
                    graph.add_edge(
                        source_id=sa_nr.id,
                        target_id=source_id,
                        relationship="binds_to",
                        details=f"{kind} associates ServiceAccount with RBAC role.",
                    )
                    graph.add_edge(
                        source_id=source_id,
                        target_id=target_role.id,
                        relationship="grants_role",
                        details=f"{kind} grants permissions defined in {ref_kind} '{ref_name}'.",
                    )
                elif sa_nr and not target_role:
                    graph.nodes[source_id].unresolved_references.append(f"{ref_kind}.{ref_name}")
                elif not sa_nr and sub_name:
                    graph.nodes[source_id].unresolved_references.append(f"{sub_kind}.{sub_name}")

        # 5. Role / ClusterRole -> Sensitive Resources (Secrets)
        elif kind == "Role":
            rules = attrs.get("rules", []) or sec_meta.get("rules", [])
            # Role can ONLY access Secrets in its own namespace
            for other_nr in normalized_infrastructure.resources:
                if other_nr.type == "Secret" and _get_k8s_namespace(other_nr) == ns:
                    if any(_rule_grants_secret_read(r, secret_name=other_nr.name) for r in rules):
                        graph.add_edge(
                            source_id=source_id,
                            target_id=other_nr.id,
                            relationship="grants_permission",
                            details="RBAC Role grants access permissions (get/list/watch/*) over Secrets in same namespace.",
                        )

        elif kind == "ClusterRole":
            rules = attrs.get("rules", []) or sec_meta.get("rules", [])
            # ClusterRole only grants permissions if bound
            # A. Cluster-wide if bound by ClusterRoleBinding
            if source_id in cluster_wide_roles:
                for other_nr in normalized_infrastructure.resources:
                    if other_nr.type == "Secret":
                        if any(_rule_grants_secret_read(r, secret_name=other_nr.name) for r in rules):
                            graph.add_edge(
                                source_id=source_id,
                                target_id=other_nr.id,
                                relationship="grants_permission",
                                details="ClusterRole grants cluster-wide read access permissions over Secrets via ClusterRoleBinding.",
                            )
            # B. Scoped to specific namespace(s) if bound by RoleBinding
            target_namespaces = cluster_role_namespaces.get(source_id, set())
            for t_ns in target_namespaces:
                for other_nr in normalized_infrastructure.resources:
                    if other_nr.type == "Secret" and _get_k8s_namespace(other_nr) == t_ns:
                        if any(_rule_grants_secret_read(r, secret_name=other_nr.name) for r in rules):
                            graph.add_edge(
                                source_id=source_id,
                                target_id=other_nr.id,
                                relationship="grants_permission",
                                details=f"ClusterRole grants read access permissions over Secrets in namespace '{t_ns}' via RoleBinding.",
                            )


# ---------------------------------------------------------------------------
# Directed Attack Path Discovery Algorithm
# ---------------------------------------------------------------------------


def discover_attack_paths(
    graph: DirectedAttackGraph,
    max_depth: int = MAX_TRAVERSAL_DEPTH,
    max_paths: int = MAX_DISCOVERED_PATHS,
) -> list[AttackPath]:
    """
    Traverse the directed infrastructure graph from external entry points
    to sensitive resources using depth-first search.
    """
    discovered_paths: list[AttackPath] = []
    seen_paths: set[tuple[str, ...]] = set()

    entry_nodes = [n for n in graph.nodes.values() if n.is_entry_point]

    for entry_node in entry_nodes:
        # Check direct exposure: Entry point IS a sensitive resource (e.g. Public S3 bucket)
        if entry_node.is_sensitive:
            path_tuple = (entry_node.id,)
            if path_tuple not in seen_paths:
                seen_paths.add(path_tuple)
                discovered_paths.append(
                    _build_attack_path(
                        graph=graph,
                        path_id=f"AP-{len(discovered_paths) + 1:03d}",
                        resource_path=[entry_node.id],
                        hops=[],
                    )
                )

        # Depth-First Search from this entry point
        stack: list[tuple[str, list[str], list[GraphEdge]]] = [
            (entry_node.id, [entry_node.id], [])
        ]

        while stack and len(discovered_paths) < max_paths:
            current_id, current_path, current_edges = stack.pop()

            if len(current_path) >= max_depth:
                continue

            current_node = graph.nodes.get(current_id)
            if not current_node:
                continue

            for edge in graph.adjacency.get(current_id, []):
                next_id = edge.target
                if next_id in current_path:
                    # Loop / cycle detected: prune branch
                    continue

                next_node = graph.nodes.get(next_id)
                if not next_node:
                    continue

                new_path = current_path + [next_id]
                new_edges = current_edges + [edge]

                # Check if target is a Sensitive Resource
                if next_node.is_sensitive:
                    # Kubernetes namespace boundary enforcement:
                    # If path passed through a namespace-scoped RoleBinding or Role, target Secret must be in that same namespace.
                    if graph.source_format == IaCFormat.KUBERNETES.value:
                        violates_ns = False
                        for prev_id in new_path:
                            prev_node = graph.nodes.get(prev_id)
                            if prev_node and prev_node.resource_type in ("RoleBinding", "Role"):
                                binding_ns = _get_k8s_namespace(prev_node)
                                target_ns = _get_k8s_namespace(next_node)
                                if binding_ns and target_ns and binding_ns != target_ns:
                                    violates_ns = True
                                    break
                        if violates_ns:
                            continue

                    path_tuple = tuple(new_path)
                    if path_tuple not in seen_paths:
                        seen_paths.add(path_tuple)
                        attack_path = _build_attack_path(
                            graph=graph,
                            path_id=f"AP-{len(discovered_paths) + 1:03d}",
                            resource_path=new_path,
                            hops=new_edges,
                        )
                        discovered_paths.append(attack_path)

                # Continue traversing if not reaching limit
                if len(new_path) < max_depth:
                    stack.append((next_id, new_path, new_edges))

    return discovered_paths


# ---------------------------------------------------------------------------
# Attack Path Risk Assessment & Narrative Builder
# ---------------------------------------------------------------------------


def _build_attack_path(
    graph: DirectedAttackGraph,
    path_id: str,
    resource_path: list[str],
    hops: list[GraphEdge],
) -> AttackPath:
    """Assess severity, confidence, provisional status, and narrative for a discovered path."""
    entry_id = resource_path[0]
    target_id = resource_path[-1]

    entry_node = graph.nodes[entry_id]
    target_node = graph.nodes[target_id]

    # Collect all findings across nodes in path
    all_findings: list[dict[str, Any]] = []
    has_unresolved_ref = False
    for res_id in resource_path:
        n = graph.nodes.get(res_id)
        if n:
            all_findings.extend(n.findings)
            if n.unresolved_references:
                has_unresolved_ref = True

    finding_threat_ids = sorted({f.get("threat_id") for f in all_findings if f.get("threat_id")})
    severities = {f.get("severity", "").upper() for f in all_findings}
    detection_statuses = {f.get("detection_status", "") for f in all_findings}

    # 1. Conservative Severity Calculation derived strictly from actual findings
    if "CRITICAL" in severities or (
        "HIGH" in severities and any(graph.nodes[r].is_privilege for r in resource_path)
    ):
        severity = "Critical"
    elif "HIGH" in severities:
        severity = "High"
    elif "MEDIUM" in severities:
        severity = "Medium"
    else:
        severity = "Low"

    # 2. Confidence and Provisional Assessment Status
    has_provisional_hop = any(not h.is_confirmed for h in hops)
    has_needs_review = "Needs Review" in detection_statuses
    has_confirmed_findings = "Confirmed" in detection_statuses

    is_provisional = False
    if not all_findings:
        is_provisional = True
    elif has_needs_review or has_unresolved_ref or has_provisional_hop:
        is_provisional = True

    if is_provisional:
        assessment_status = "Provisional"
        if has_unresolved_ref or has_provisional_hop or not all_findings:
            confidence = "Low"
        else:
            confidence = "Medium"
    else:
        assessment_status = "Confirmed"
        confidence = "High"

    # 3. Limitations
    limitations: list[str] = []
    if not all_findings:
        limitations.append(
            "Path topology is inferred from structural relationships without supporting confirmed security findings."
        )
    if has_needs_review and has_confirmed_findings:
        limitations.append(
            "Path combines mixed confirmed threat findings with provisional (Needs Review) evidence requiring manual verification."
        )
    elif has_needs_review and not has_confirmed_findings:
        limitations.append(
            "Path relies entirely on provisional (Needs Review) findings that require manual verification."
        )
    if has_provisional_hop:
        limitations.append(
            "Path traverses one or more conditional or provisional IAM/RBAC policy relationships."
        )
    if has_unresolved_ref:
        for res_id in resource_path:
            unresolved = graph.nodes[res_id].unresolved_references
            if unresolved:
                limitations.append(
                    f"Resource '{res_id}' has external or unresolved references: {', '.join(unresolved)}."
                )

    if graph.source_format == IaCFormat.KUBERNETES.value:
        limitations.append(
            "Analysis is static and does not evaluate live runtime cluster NetworkPolicies outside this manifest."
        )
    elif graph.source_format in (IaCFormat.TERRAFORM.value, IaCFormat.CLOUDFORMATION.value):
        limitations.append(
            "Analysis assumes standard AWS security boundary defaults without evaluating unmodeled VPC peering, SCPs, or dynamic IAM conditions."
        )

    # 4. Build Human-Readable Narrative
    if len(resource_path) == 1:
        description = (
            f"Direct public exposure of sensitive resource '{target_id}'. "
            "Public access permissions permit unauthorized external access."
        )
    else:
        description = (
            f"Potential attack path starting from exposed entry point '{entry_id}', "
            f"progressing through {len(resource_path) - 2} intermediate resource(s), "
            f"and reaching sensitive target '{target_id}'."
        )

    if assessment_status == "Provisional":
        description = f"[Provisional] {description}"

    # 6. Format Evidence Hops
    evidence_hops: list[dict[str, Any]] = []
    for idx, hop in enumerate(hops, 1):
        evidence_hops.append(
            {
                "step": idx,
                "source": hop.source,
                "target": hop.target,
                "relationship": hop.relationship,
                "details": hop.details,
            }
        )

    return AttackPath(
        path_id=path_id,
        source_format=graph.source_format,
        entry_point=entry_id,
        target_resource=target_id,
        resource_path=resource_path,
        severity=severity,
        confidence=confidence,
        assessment_status=assessment_status,
        description=description,
        evidence=evidence_hops,
        related_findings=finding_threat_ids,
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# Public Entry Point
# ---------------------------------------------------------------------------


def analyze_attack_paths(
    resources: list[dict[str, Any]],
    threat_findings: list[dict[str, Any]],
    source_format: str = IaCFormat.TERRAFORM.value,
    normalized_infrastructure: NormalizedInfrastructure | None = None,
    infrastructure_map: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Execute end-to-end relationship-aware attack path analysis.

    Returns a list of standardized attack path dictionaries.
    """
    if not resources:
        return []

    graph = build_directed_attack_graph(
        resources=resources,
        threat_findings=threat_findings,
        source_format=source_format,
        normalized_infrastructure=normalized_infrastructure,
    )

    discovered = discover_attack_paths(graph)
    return [p.to_dict() for p in discovered]
