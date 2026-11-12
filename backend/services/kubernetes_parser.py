"""
services/kubernetes_parser.py
-----------------------------
Kubernetes YAML Manifest Parser (Stage 4).

Parses single-document and multi-document Kubernetes YAML manifests into the
common `NormalizedInfrastructure` model using `NormalizedResource`.

Key Capabilities:
1. Multi-document support using YAML separators (`---`), safely ignoring empty documents.
2. Full structural parsing for standard Kubernetes kinds:
   Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob,
   Service, Ingress, ConfigMap, Secret, ServiceAccount, Role, ClusterRole,
   RoleBinding, ClusterRoleBinding, NetworkPolicy, PersistentVolume,
   PersistentVolumeClaim, Namespace.
3. Extensible generic kind preservation for Custom Resource Definitions (CRDs).
4. Security metadata extraction:
   - Container security context: privileged, allowPrivilegeEscalation, runAsUser,
     runAsNonRoot, readOnlyRootFilesystem, capabilities (add/drop), hostNetwork,
     hostPID, hostIPC, hostPath volumes, image, and imagePullPolicy.
   - Workload settings: replicas, serviceAccountName, automountServiceAccountToken.
   - Network settings: Service types/ports, Ingress TLS/backends, NetworkPolicy ingress/egress.
   - RBAC settings: rules, verbs, resources, apiGroups, subjects, roleRef.
   - Storage settings: accessModes, storageClassName, volumeName, volume types.
5. Deterministic relationship resolution across co-located manifest documents
   (Service-to-workload selectors, Ingress-to-Service, RoleBinding-to-Role/subjects,
   Workload-to-ServiceAccount/Volumes, PVC-to-PV).
6. Strict format detection that never misidentifies CloudFormation or generic YAML.
"""

from __future__ import annotations

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

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB maximum manifest size
MAX_DOCUMENT_COUNT = 500          # Maximum documents per manifest file

# Standard recognized Kubernetes resource kinds
KNOWN_K8S_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
    "ServiceAccount",
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
    "NetworkPolicy",
    "PersistentVolume",
    "PersistentVolumeClaim",
    "Namespace",
}

CLUSTER_SCOPED_KINDS = {
    "ClusterRole",
    "ClusterRoleBinding",
    "PersistentVolume",
    "Namespace",
    "CustomResourceDefinition",
    "Node",
    "StorageClass",
}

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
}


# ---------------------------------------------------------------------------
# Security Metadata & Spec Extraction Helpers
# ---------------------------------------------------------------------------


def _get_pod_spec(kind: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Locate the PodSpec dict regardless of workload wrapping level."""
    if not isinstance(spec, dict):
        return {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = spec.get("jobTemplate", {})
        if isinstance(job_template, dict):
            job_spec = job_template.get("spec", {})
            if isinstance(job_spec, dict):
                pod_template = job_spec.get("template", {})
                if isinstance(pod_template, dict):
                    return pod_template.get("spec", {}) or {}
        return {}
    # Deployment, StatefulSet, DaemonSet, ReplicaSet, Job
    template = spec.get("template", {})
    if isinstance(template, dict):
        return template.get("spec", {}) or {}
    return {}


def _extract_container_security(containers: list[Any]) -> list[dict[str, Any]]:
    """Extract container-level security configurations without assuming defaults."""
    extracted: list[dict[str, Any]] = []
    if not isinstance(containers, list):
        return extracted

    for c in containers:
        if not isinstance(c, dict):
            continue

        c_sec = c.get("securityContext") or {}
        caps = c_sec.get("capabilities") or {}

        c_meta: dict[str, Any] = {
            "name": c.get("name", ""),
            "image": c.get("image", ""),
            "imagePullPolicy": c.get("imagePullPolicy"),
            "privileged": c_sec.get("privileged"),
            "allowPrivilegeEscalation": c_sec.get("allowPrivilegeEscalation"),
            "runAsUser": c_sec.get("runAsUser"),
            "runAsGroup": c_sec.get("runAsGroup"),
            "runAsNonRoot": c_sec.get("runAsNonRoot"),
            "readOnlyRootFilesystem": c_sec.get("readOnlyRootFilesystem"),
            "capabilities_add": caps.get("add", []),
            "capabilities_drop": caps.get("drop", []),
            "seccompProfile": c_sec.get("seccompProfile"),
        }
        extracted.append(c_meta)

    return extracted


def _extract_attributes(kind: str, doc: dict[str, Any]) -> dict[str, Any]:
    """
    Extract comprehensive resource attributes preserving original spec
    and enriching with structured security metadata.
    """
    spec = doc.get("spec")
    attrs: dict[str, Any] = dict(spec) if isinstance(spec, dict) else {}
    metadata = doc.get("metadata") or {}

    # Store metadata info in attributes
    attrs["_metadata"] = {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "labels": metadata.get("labels", {}),
        "annotations": metadata.get("annotations", {}),
    }

    # Extract workload-specific security metadata
    if kind in WORKLOAD_KINDS:
        pod_spec = _get_pod_spec(kind, attrs)
        pod_sec = pod_spec.get("securityContext") or {}

        all_containers = []
        if isinstance(pod_spec.get("containers"), list):
            all_containers.extend(pod_spec.get("containers", []))
        if isinstance(pod_spec.get("initContainers"), list):
            all_containers.extend(pod_spec.get("initContainers", []))

        attrs["security_metadata"] = {
            "hostNetwork": pod_spec.get("hostNetwork", False),
            "hostPID": pod_spec.get("hostPID", False),
            "hostIPC": pod_spec.get("hostIPC", False),
            "serviceAccountName": pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount"),
            "automountServiceAccountToken": pod_spec.get("automountServiceAccountToken"),
            "podSecurityContext": pod_sec,
            "containers": _extract_container_security(all_containers),
            "volumes": pod_spec.get("volumes", []),
        }

    # Extract Service metadata
    elif kind == "Service":
        attrs["security_metadata"] = {
            "type": attrs.get("type", "ClusterIP"),
            "ports": attrs.get("ports", []),
            "selector": attrs.get("selector", {}),
        }

    # Extract Ingress metadata
    elif kind == "Ingress":
        attrs["security_metadata"] = {
            "tls": attrs.get("tls", []),
            "rules": attrs.get("rules", []),
            "defaultBackend": attrs.get("defaultBackend"),
        }

    # Extract RBAC metadata
    elif kind in ("Role", "ClusterRole"):
        rules = doc.get("rules", [])
        attrs["rules"] = rules
        attrs["security_metadata"] = {"rules": rules}

    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        role_ref = doc.get("roleRef", {})
        subjects = doc.get("subjects", [])
        attrs["roleRef"] = role_ref
        attrs["subjects"] = subjects
        attrs["security_metadata"] = {"roleRef": role_ref, "subjects": subjects}

    # Extract ConfigMap / Secret metadata
    elif kind == "ConfigMap":
        attrs["data"] = doc.get("data", {})
        attrs["binaryData"] = doc.get("binaryData", {})

    elif kind == "Secret":
        attrs["type"] = doc.get("type", "Opaque")
        attrs["data"] = doc.get("data", {})
        attrs["stringData"] = doc.get("stringData", {})
        attrs["immutable"] = doc.get("immutable", False)

    # Extract NetworkPolicy metadata
    elif kind == "NetworkPolicy":
        attrs["security_metadata"] = {
            "podSelector": attrs.get("podSelector", {}),
            "policyTypes": attrs.get("policyTypes", []),
            "ingress": attrs.get("ingress", []),
            "egress": attrs.get("egress", []),
        }

    # Extract ServiceAccount metadata
    elif kind == "ServiceAccount":
        automount = doc.get("automountServiceAccountToken")
        attrs["automountServiceAccountToken"] = automount
        attrs["secrets"] = doc.get("secrets", [])
        attrs["imagePullSecrets"] = doc.get("imagePullSecrets", [])
        attrs["security_metadata"] = {"automountServiceAccountToken": automount}

    # Extract Storage metadata
    elif kind in ("PersistentVolume", "PersistentVolumeClaim"):
        attrs["security_metadata"] = {
            "accessModes": attrs.get("accessModes", []),
            "storageClassName": attrs.get("storageClassName"),
            "volumeName": attrs.get("volumeName"),
            "capacity": attrs.get("capacity"),
        }

    return attrs


# ---------------------------------------------------------------------------
# Relationship Resolution Helpers
# ---------------------------------------------------------------------------


def _resolve_relationships(
    doc_entries: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """
    Perform deterministic relationship resolution across all co-located documents
    in the manifest file. Returns mapping: resource_id -> list of referenced resource_ids/names.
    """
    rel_map: dict[str, list[str]] = {}

    # Build lookup index by name and kind
    res_by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in doc_entries:
        n = entry["name"]
        res_by_name.setdefault(n, []).append(entry)

    for entry in doc_entries:
        res_id = entry["id"]
        kind = entry["kind"]
        doc = entry["doc"]
        spec = doc.get("spec", {}) or {}
        rels: list[str] = []

        # 1. RoleBinding / ClusterRoleBinding -> Role / ClusterRole & Subjects
        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = doc.get("roleRef", {})
            if isinstance(role_ref, dict):
                ref_name = role_ref.get("name")
                ref_kind = role_ref.get("kind", "Role")
                if ref_name:
                    rels.append(f"{ref_kind}.{ref_name}")

            for sub in doc.get("subjects", []):
                if isinstance(sub, dict) and sub.get("name"):
                    sub_kind = sub.get("kind", "ServiceAccount")
                    rels.append(f"{sub_kind}.{sub['name']}")

        # 2. Ingress -> Backend Services
        elif kind == "Ingress":
            # Check rules
            for rule in spec.get("rules", []):
                if isinstance(rule, dict):
                    http = rule.get("http", {})
                    if isinstance(http, dict):
                        for p in http.get("paths", []):
                            if isinstance(p, dict):
                                backend = p.get("backend", {})
                                # Ingress v1
                                svc = backend.get("service", {})
                                if isinstance(svc, dict) and svc.get("name"):
                                    rels.append(f"Service.{svc['name']}")
                                # Ingress v1beta1
                                elif backend.get("serviceName"):
                                    rels.append(f"Service.{backend['serviceName']}")
            # Check defaultBackend
            def_backend = spec.get("defaultBackend", {})
            if isinstance(def_backend, dict):
                svc = def_backend.get("service", {})
                if isinstance(svc, dict) and svc.get("name"):
                    rels.append(f"Service.{svc['name']}")

        # 3. Workload (Pod, Deployment, etc.) -> ServiceAccount & Volume Resources
        elif kind in WORKLOAD_KINDS:
            pod_spec = _get_pod_spec(kind, spec)
            sa_name = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
            if sa_name and sa_name != "default":
                rels.append(f"ServiceAccount.{sa_name}")

            for vol in pod_spec.get("volumes", []):
                if isinstance(vol, dict):
                    if vol.get("configMap", {}).get("name"):
                        rels.append(f"ConfigMap.{vol['configMap']['name']}")
                    if vol.get("secret", {}).get("secretName"):
                        rels.append(f"Secret.{vol['secret']['secretName']}")
                    if vol.get("persistentVolumeClaim", {}).get("claimName"):
                        rels.append(f"PersistentVolumeClaim.{vol['persistentVolumeClaim']['claimName']}")

        # 4. PVC -> PV (Static binding)
        elif kind == "PersistentVolumeClaim":
            vol_name = spec.get("volumeName")
            if vol_name:
                rels.append(f"PersistentVolume.{vol_name}")

        # 5. Service -> Target Workload (Deterministic selector matching)
        elif kind == "Service":
            selector = spec.get("selector", {})
            if isinstance(selector, dict) and selector:
                for target_entry in doc_entries:
                    if target_entry["kind"] in WORKLOAD_KINDS:
                        target_spec = target_entry["doc"].get("spec", {})
                        pod_spec_candidate = _get_pod_spec(target_entry["kind"], target_spec)
                        # Check labels on workload template or metadata
                        target_labels = (
                            target_entry["doc"].get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
                            or target_entry["doc"].get("metadata", {}).get("labels", {})
                        )
                        if isinstance(target_labels, dict):
                            # Selector must match target labels
                            if all(target_labels.get(k) == v for k, v in selector.items()):
                                rels.append(target_entry["id"])

        # Deduplicate while preserving order
        rel_map[res_id] = list(dict.fromkeys(rels))

    return rel_map


# ---------------------------------------------------------------------------
# Kubernetes Parser Implementation
# ---------------------------------------------------------------------------


class KubernetesParser(BaseIaCParser):
    """
    Parser implementation for Kubernetes YAML manifests.

    Supports single- and multi-document YAML manifests, standard Kubernetes kinds,
    generic CRDs, security context extraction, and inter-manifest relationship resolution.
    """

    @property
    def format_name(self) -> IaCFormat:
        return IaCFormat.KUBERNETES

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".yaml", ".yml")

    def can_parse(self, filename: str, content: str = "") -> bool:
        """
        Fast and safe format identification for Kubernetes manifests.

        Ensures:
        1. File has .yaml or .yml extension.
        2. Content is non-empty.
        3. Never claims CloudFormation templates (templates with 'Resources' containing 'AWS::*').
        4. Validates that at least one document has 'apiVersion', 'kind', and 'metadata.name'.
        """
        if not filename:
            return False

        fn_lower = filename.lower()
        if not (fn_lower.endswith(".yaml") or fn_lower.endswith(".yml")):
            return False

        if not content or not content.strip():
            return False

        # Reject CloudFormation templates immediately
        if "AWSTemplateFormatVersion" in content:
            return False
        if "AWS::" in content and "Resources:" in content:
            return False

        try:
            docs = list(yaml.safe_load_all(content))
            valid_k8s_docs = 0

            for doc in docs:
                if doc is None:
                    continue
                if not isinstance(doc, dict):
                    continue

                api_version = doc.get("apiVersion")
                kind = doc.get("kind")
                metadata = doc.get("metadata")

                if (
                    isinstance(api_version, str)
                    and api_version.strip()
                    and isinstance(kind, str)
                    and kind.strip()
                    and isinstance(metadata, dict)
                    and metadata.get("name")
                ):
                    valid_k8s_docs += 1

            return valid_k8s_docs > 0
        except Exception:
            return False

    def parse(self, content: str, filename: str = "") -> NormalizedInfrastructure:
        """
        Parse single- or multi-document Kubernetes YAML manifest into NormalizedInfrastructure.

        Raises:
            MalformedIaCError: On invalid YAML syntax, empty content, missing required
                               fields (apiVersion, kind, metadata.name), or document limits exceeded.
        """
        if not content or not content.strip():
            raise MalformedIaCError("File is empty.")

        # File size safeguard
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise MalformedIaCError("Kubernetes manifest exceeds maximum supported size (10 MB).")

        # 1. Parse YAML documents safely
        try:
            raw_docs = list(yaml.safe_load_all(content))
        except Exception as exc:
            raise MalformedIaCError(f"Invalid Kubernetes YAML syntax: {exc}") from exc

        # 2. Filter out empty documents (from leading, trailing, or consecutive '---')
        non_empty_docs: list[tuple[int, dict[str, Any]]] = []
        for idx, doc in enumerate(raw_docs):
            if doc is not None:
                non_empty_docs.append((idx, doc))

        if not non_empty_docs:
            raise MalformedIaCError("Kubernetes manifest contains no valid YAML documents.")

        if len(non_empty_docs) > MAX_DOCUMENT_COUNT:
            raise MalformedIaCError(f"Manifest exceeds maximum document limit of {MAX_DOCUMENT_COUNT} documents.")

        # 3. First pass: validate required fields and collect document entries
        doc_entries: list[dict[str, Any]] = []
        for doc_idx, doc in non_empty_docs:
            if not isinstance(doc, dict):
                raise MalformedIaCError(f"Document {doc_idx} is not a valid YAML mapping/object.")

            api_version = doc.get("apiVersion")
            if not api_version or not isinstance(api_version, str) or not api_version.strip():
                raise MalformedIaCError(f"Document {doc_idx} is missing required 'apiVersion' field.")

            kind = doc.get("kind")
            if not kind or not isinstance(kind, str) or not kind.strip():
                raise MalformedIaCError(f"Document {doc_idx} is missing required 'kind' field.")

            kind = kind.strip()
            metadata = doc.get("metadata")
            if not isinstance(metadata, dict):
                raise MalformedIaCError(f"Document {doc_idx} ({kind}) is missing required 'metadata' section.")

            name = metadata.get("name")
            if not name or not isinstance(name, str) or not name.strip():
                raise MalformedIaCError(f"Document {doc_idx} ({kind}) is missing required 'metadata.name' field.")

            name = name.strip()
            namespace = metadata.get("namespace", "default") if kind not in CLUSTER_SCOPED_KINDS else ""

            # Stable resource ID
            if namespace:
                res_id = f"{kind}.{namespace}.{name}"
            else:
                res_id = f"{kind}.{name}"

            doc_entries.append({
                "doc_idx": doc_idx,
                "id": res_id,
                "name": name,
                "namespace": namespace,
                "kind": kind,
                "api_version": api_version.strip(),
                "doc": doc,
            })

        # 4. Second pass: resolve relationships across the manifest documents
        relationship_map = _resolve_relationships(doc_entries)

        # 5. Build NormalizedResource objects
        normalized_resources: list[NormalizedResource] = []
        manifest_warnings: list[str] = []

        for entry in doc_entries:
            res_id = entry["id"]
            kind = entry["kind"]
            name = entry["name"]
            namespace = entry["namespace"]
            doc = entry["doc"]
            doc_idx = entry["doc_idx"]

            res_warnings: list[str] = []
            parsing_status = ParsingStatus.VALID.value

            # Generic handling for unknown / CRD kinds
            if kind not in KNOWN_K8S_KINDS:
                res_warnings.append(f"Generic Kubernetes resource kind '{kind}' preserved.")

            attributes = _extract_attributes(kind, doc)
            relationships = relationship_map.get(res_id, [])

            norm_res = NormalizedResource(
                id=res_id,
                name=name,
                type=kind,
                source_format=IaCFormat.KUBERNETES.value,
                provider=PlatformProvider.KUBERNETES.value,
                attributes=attributes,
                relationships=relationships,
                source_file=filename,
                source_location={
                    "format": "kubernetes",
                    "doc_index": doc_idx,
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "api_version": entry["api_version"],
                    "file": filename,
                },
                parsing_status=parsing_status,
                validation_errors=res_warnings,
                raw_declaration=doc,
            )
            normalized_resources.append(norm_res)

        return NormalizedInfrastructure(
            source_format=IaCFormat.KUBERNETES.value,
            source_file=filename,
            resources=normalized_resources,
            parsing_status=ParsingStatus.VALID.value,
            validation_errors=manifest_warnings,
            metadata={
                "documents_count": len(normalized_resources),
                "kinds_summary": sorted({r.type for r in normalized_resources}),
            },
        )
