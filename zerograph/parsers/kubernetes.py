"""Kubernetes manifests: service accounts, RBAC, secrets and workloads.

Objects from every file are collected first, then resolved together, because a
RoleBinding often lives in a different file from the Role it references.
"""

from __future__ import annotations

from collections import Counter

from ..loader import line_of
from ..model import LLM_KEYS, Graph, is_credential_name

WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
RBAC = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
HANDLED = WORKLOADS | RBAC | {"ServiceAccount", "Secret"}
READ_VERBS = {"get", "list", "watch", "*"}
ESCALATING = {"pods", "pods/exec", "pods/attach", "deployments", "daemonsets", "statefulsets",
              "jobs", "cronjobs", "serviceaccounts/token", "nodes/proxy"}
RBAC_RESOURCES = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}

_ALL = {"apiGroups": ["*"], "resources": ["*"]}
# Built-in ClusterRoles that manifests usually reference without defining (approximated).
BUILTIN_CLUSTER_ROLES = {
    "cluster-admin": [{**_ALL, "verbs": ["*"]}],
    "admin": [{**_ALL, "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}],
    "edit": [{**_ALL, "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]}],
    "view": [{"apiGroups": ["*"], "resources": ["pods", "services", "configmaps", "deployments"],
              "verbs": ["get", "list", "watch"]}],
}


class Objects:
    """Manifests collected across files: (doc, rel) pairs."""

    def __init__(self) -> None:
        self.items: list[tuple[dict, str]] = []
        self.skipped: Counter = Counter()

    def add(self, doc: dict, rel: str) -> None:
        if doc.get("kind") == "List":
            for item in doc.get("items") or []:
                if isinstance(item, dict):
                    self.add(item, rel)
        elif doc.get("kind") in HANDLED:
            self.items.append((doc, rel))
        else:
            self.skipped[str(doc.get("kind"))] += 1


def _meta(doc):
    md = doc.get("metadata") or {}
    return str(md.get("name") or "?"), str(md.get("namespace") or "default"), md


def sa_id(ns: str, name: str) -> str:
    return f"k8s:sa:{ns}/{name}"


def build(objs: Objects, g: Graph) -> None:
    if objs.skipped:
        kinds = ", ".join(f"{k} x{n}" for k, n in sorted(objs.skipped.items()))
        g.warn(f"skipped unsupported Kubernetes kinds: {kinds}")
    roles: dict[tuple[str, str], tuple[list, str, int | None]] = {}
    secrets: dict[str, list[str]] = {}  # namespace -> secret node ids
    for doc, rel in objs.items:
        kind = doc["kind"]
        name, ns, md = _meta(doc)
        if kind == "ServiceAccount":
            _sa(g, ns, name, rel, line_of(doc))
            if doc.get("automountServiceAccountToken") is False:
                g.nodes[sa_id(ns, name)].attrs["automount"] = False
        elif kind == "Secret":
            keys = sorted(set(doc.get("data") or {}) | set(doc.get("stringData") or {}))
            sec = f"secret:k8s:{ns}/{name}"
            g.add_node(sec, "secret", f"{name} (k8s secret, {ns})", 5, rel, line_of(doc),
                       source="kubernetes Secret", keys=keys, type=doc.get("type"))
            secrets.setdefault(ns, []).append(sec)
        elif kind in ("Role", "ClusterRole"):
            scope = "" if kind == "ClusterRole" else ns
            roles[(kind, scope + "/" + name)] = (doc.get("rules") or [], rel, line_of(doc))
    # Workloads first, so Group subjects such as system:serviceaccounts see every SA.
    for doc, rel in objs.items:
        if doc["kind"] in WORKLOADS:
            _workload(g, doc, rel)
    for doc, rel in objs.items:
        if doc["kind"] in ("RoleBinding", "ClusterRoleBinding"):
            _binding(g, doc, rel, roles, secrets)


def _sa(g: Graph, ns: str, name: str, rel=None, line=None) -> str:
    node_id = sa_id(ns, name)
    g.add_node(node_id, "identity", f"sa {ns}/{name}", 0, rel, line, platform="kubernetes",
               namespace=ns, _aliases=[node_id, f"k8s:{ns}/{name}"])
    return node_id


def _binding(g, doc, rel, roles, secrets) -> None:
    name, ns, _ = _meta(doc)
    ref = doc.get("roleRef") or {}
    ref_kind, ref_name = ref.get("kind"), ref.get("name")
    cluster_wide = doc["kind"] == "ClusterRoleBinding"
    if ref_kind == "ClusterRole":
        found = roles.get(("ClusterRole", "/" + str(ref_name)))
    else:
        found = roles.get(("Role", f"{ns}/{ref_name}"))
    if found is None and ref_kind == "ClusterRole" and ref_name in BUILTIN_CLUSTER_ROLES:
        found = (BUILTIN_CLUSTER_ROLES[ref_name], None, None)
    if found is None:
        g.warn(f"{rel}: {doc['kind']} {name} references unknown {ref_kind} {ref_name}")
        return
    rules = found[0]
    scope = "cluster" if cluster_wide else ns
    subjects = _subjects(g, doc.get("subjects") or [], ns)
    line = line_of(doc, "roleRef") or line_of(doc)
    for rule in rules:
        if not isinstance(rule, dict) or not rule.get("resources"):
            continue
        perm = _permission(g, scope, rule, ref_name, secrets)
        for subject in subjects:
            g.add_edge(subject, perm, f"{doc['kind']} {name} -> {ref_kind} {ref_name}", rel, line)


def _subjects(g, subjects, ns) -> list[str]:
    out = []
    for s in subjects:
        if not isinstance(s, dict):
            continue
        if s.get("kind") == "ServiceAccount":
            out.append(_sa(g, str(s.get("namespace") or ns), str(s.get("name"))))
        elif s.get("kind") == "Group" and str(s.get("name", "")).startswith("system:serviceaccounts"):
            target_ns = str(s["name"]).split(":")[2] if s["name"].count(":") == 2 else None
            out += [n.id for n in list(g.nodes.values()) if n.id.startswith("k8s:sa:")
                    and (target_ns is None or n.attrs.get("namespace") == target_ns)]
    return out


def _permission(g, scope, rule, role_name, secrets) -> str:
    verbs = sorted({str(v) for v in rule.get("verbs") or []})
    resources = sorted({str(r) for r in rule.get("resources") or []})
    verb_text = "*" if "*" in verbs else ",".join(verbs)
    res_text = "*" if "*" in resources else ",".join(resources)
    names = rule.get("resourceNames")
    severity = _severity(scope, set(verbs), set(resources))
    where = "cluster-wide" if scope == "cluster" else f"in {scope}"
    if verb_text == "*" and res_text == "*":
        label = f"ALL verbs on ALL resources {where}"
        if scope == "cluster":
            label += " (cluster-admin)"
    else:
        label = f"{verb_text} {res_text} {where}"
    if names:
        label += f" (only {', '.join(map(str, names))})"
    node_id = f"k8s:perm:{scope}:{res_text}:{verb_text}:{','.join(map(str, names or []))}"
    g.add_node(node_id, "resource", label, severity, verbs=verbs, resources=resources,
               scope=scope, role=role_name)
    if READ_VERBS & set(verbs) and ({"secrets", "*"} & set(resources)):
        pools = secrets.values() if scope == "cluster" else [secrets.get(scope, [])]
        for pool in pools:
            for sec in pool:
                if not names or sec.rsplit("/", 1)[1] in names:
                    g.add_edge(node_id, sec, "can read")
    return node_id


def _severity(scope, verbs, resources) -> int:
    cluster = scope == "cluster"
    write = bool(verbs - {"get", "list", "watch"})
    if "*" in resources and "*" in verbs:
        return 9 if cluster else 7
    if write and (RBAC_RESOURCES & resources or {"bind", "escalate", "impersonate"} & verbs):
        return 8
    if write and (ESCALATING & resources or "*" in resources):
        return 7 if cluster else 6
    if "secrets" in resources or "*" in resources:
        return 6 if READ_VERBS & verbs else 4
    return 4 if write else 2


def _pod_spec(doc) -> dict:
    spec = doc.get("spec") or {}
    if doc["kind"] == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    if doc["kind"] != "Pod":
        spec = ((spec.get("template") or {}).get("spec") or {})
    return spec if isinstance(spec, dict) else {}


def _workload(g, doc, rel) -> None:
    name, ns, md = _meta(doc)
    spec = _pod_spec(doc)
    wid = f"k8s:{doc['kind'].lower()}:{ns}/{name}"
    line = line_of(doc)
    g.add_node(wid, "identity", f"{doc['kind']} {ns}/{name}", 0, rel, line, platform="kubernetes",
               namespace=ns, _aliases=[f"k8s:{ns}/{name}", wid])
    sa_name = str(spec.get("serviceAccountName") or spec.get("serviceAccount") or "default")
    sa = _sa(g, ns, sa_name)
    automount = spec.get("automountServiceAccountToken")
    if automount is None:
        automount = g.nodes[sa].attrs.get("automount", True)
    if automount:
        g.add_edge(wid, sa, "runs as (token mounted)", rel, line_of(spec, "serviceAccountName") or line)
    else:
        g.add_edge(wid, sa, "assigned (token not mounted)", rel, line, transitive=False)

    if spec.get("hostNetwork"):
        g.add_edge(wid, g.capability("host:network"), "hostNetwork", rel, line_of(spec, "hostNetwork"))
    if spec.get("hostPID"):
        g.add_edge(wid, g.capability("host:pid"), "hostPID", rel, line_of(spec, "hostPID"))
    for vol in spec.get("volumes") or []:
        if not isinstance(vol, dict):
            continue
        if isinstance(vol.get("hostPath"), dict):
            g.add_edge(wid, g.host_path(str(vol["hostPath"].get("path"))), "hostPath", rel, line_of(vol))
        if isinstance(vol.get("secret"), dict):
            _secret_ref(g, wid, ns, vol["secret"].get("secretName"), rel, line_of(vol))

    agent = str((md.get("labels") or {}).get("zerograph.io/agent", "")).lower() == "true"
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        if not isinstance(c, dict):
            continue
        sc = c.get("securityContext") or {}
        caps = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
        if sc.get("privileged") or caps & {"SYS_ADMIN", "ALL"}:
            g.add_edge(wid, g.capability("host:root"), "privileged container", rel, line_of(sc) or line_of(c))
        for env in c.get("env") or []:
            if not isinstance(env, dict):
                continue
            key = str(env.get("name"))
            agent = agent or key in LLM_KEYS
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {})
            if ref:
                _secret_ref(g, wid, ns, ref.get("name"), rel, line_of(env))
            elif is_credential_name(key):
                secret = g.env_secret(key, rel, line_of(env), "value" in env)
                g.add_edge(wid, secret, "holds", rel, line_of(env))
        for src in c.get("envFrom") or []:
            if isinstance(src, dict) and isinstance(src.get("secretRef"), dict):
                _secret_ref(g, wid, ns, src["secretRef"].get("name"), rel, line_of(src))
    if agent:
        g.nodes[wid].attrs["_agent_hint"] = True


def _secret_ref(g, wid, ns, name, rel, line) -> None:
    if not name:
        return
    sec = f"secret:k8s:{ns}/{name}"
    g.add_node(sec, "secret", f"{name} (k8s secret, {ns})", 5, source="kubernetes Secret")
    g.add_edge(wid, sec, "mounts secret", rel, line)
