from conftest import edges, targets

RBAC = """\
apiVersion: v1
kind: ServiceAccount
metadata: {name: bot, namespace: ai}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: quiet, namespace: ai}
automountServiceAccountToken: false
---
apiVersion: v1
kind: Secret
metadata: {name: creds, namespace: ai}
data: {password: c2VjcmV0LXZhbHVl}
---
apiVersion: v1
kind: Secret
metadata: {name: other, namespace: prod}
stringData: {token: plain-text-value}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: ai}
rules:
  - {apiGroups: [""], resources: [secrets], verbs: [get, list]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: bot-reader, namespace: ai}
subjects: [{kind: ServiceAccount, name: bot}]
roleRef: {kind: Role, name: reader}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules:
  - {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: quiet-everything, namespace: ai}
subjects: [{kind: ServiceAccount, name: quiet}]
roleRef: {kind: ClusterRole, name: everything}
"""

ADMIN = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ops-admin}
subjects: [{kind: ServiceAccount, name: ops, namespace: kube-system}]
roleRef: {kind: ClusterRole, name: cluster-admin}
"""

WORKLOADS = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: agent, namespace: ai}
spec:
  template:
    spec:
      serviceAccountName: bot
      hostNetwork: true
      volumes:
        - {name: root, hostPath: {path: /}}
      containers:
        - name: main
          securityContext: {privileged: true}
          env:
            - {name: OPENAI_API_KEY, valueFrom: {secretKeyRef: {name: creds, key: password}}}
            - {name: DB_PASSWORD, value: hunter2}
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly, namespace: ai}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: quiet
          containers: [{name: c, image: x}]
---
apiVersion: v1
kind: Pod
metadata: {name: plain}
spec:
  containers: [{name: c, image: x}]
"""


def test_role_binding_resolves_verbs_and_secrets(scan_files):
    g = scan_files({"rbac.yaml": RBAC})
    perm = "k8s:perm:ai:secrets:get,list:"
    assert perm in targets(g, "k8s:sa:ai/bot")
    assert g.nodes[perm].severity == 6
    # Secret read reaches secrets in the namespace only.
    assert targets(g, perm) == {"secret:k8s:ai/creds"}
    assert g.nodes["secret:k8s:ai/creds"].attrs["keys"] == ["password"]


def test_rolebinding_to_clusterrole_is_namespace_scoped(scan_files):
    g = scan_files({"rbac.yaml": RBAC})
    perm = "k8s:perm:ai:*:*:"
    assert perm in targets(g, "k8s:sa:ai/quiet")
    assert g.nodes[perm].severity == 7
    assert "cluster-admin" not in g.nodes[perm].label


def test_cluster_role_binding_to_builtin_cluster_admin(scan_files):
    g = scan_files({"rbac.yaml": RBAC, "admin.yaml": ADMIN})
    perm = "k8s:perm:cluster:*:*:"
    assert perm in targets(g, "k8s:sa:kube-system/ops")
    assert g.nodes[perm].severity == 9
    assert "cluster-admin" in g.nodes[perm].label
    # Cluster-wide secret access reaches secrets in every namespace.
    assert {"secret:k8s:ai/creds", "secret:k8s:prod/other"} <= targets(g, perm)


def test_workload_privileges_and_service_account(scan_files):
    g = scan_files({"rbac.yaml": RBAC, "apps.yaml": WORKLOADS})
    wid = "k8s:deployment:ai/agent"
    out = targets(g, wid)
    assert {"k8s:sa:ai/bot", "cap:host:network", "cap:host:root", "secret:k8s:ai/creds",
            "secret:env:DB_PASSWORD"} <= out
    assert g.nodes["agent:" + wid].kind == "agent"  # holds an LLM key
    # Pod with no serviceAccountName runs as the default SA.
    assert "k8s:sa:default/default" in targets(g, "k8s:pod:default/plain")


def test_unmounted_token_does_not_grant_rbac(scan_files):
    g = scan_files({"rbac.yaml": RBAC, "apps.yaml": WORKLOADS})
    edge = next(e for e in g.edges if e.src == "k8s:cronjob:ai/nightly")
    assert edge.dst == "k8s:sa:ai/quiet" and not edge.transitive


def test_group_subject_binds_every_service_account_in_namespace(scan_files):
    group = """\
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {name: all-sas, namespace: ai}
    subjects: [{kind: Group, name: "system:serviceaccounts:ai"}]
    roleRef: {kind: ClusterRole, name: view}
    """
    g = scan_files({"rbac.yaml": RBAC, "group.yaml": group})
    assert any("pods" in dst for dst, _ in edges(g, "k8s:sa:ai/bot"))
    assert any("pods" in dst for dst, _ in edges(g, "k8s:sa:ai/quiet"))


def test_unknown_role_reference_warns(scan_files):
    g = scan_files({"b.yaml": """\
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {name: x, namespace: ai}
    subjects: [{kind: ServiceAccount, name: bot}]
    roleRef: {kind: Role, name: missing}
    """})
    assert any("unknown Role missing" in w for w in g.warnings)
