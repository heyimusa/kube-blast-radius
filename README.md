# kube-blast-radius

`kube-blast-radius` explains the security impact of a Kubernetes manifest change.

It compares **before** and **after** rendered manifests, then reports new security-relevant capability, exposure, and workload-hardening changes. It is designed for GitOps pull-request review, where a short YAML diff can hide a meaningful change in effective access or network surface.

```text
rendered manifests before + rendered manifests after
                         ↓
              security-impact diff
                         ↓
      terminal report / JSON for CI and review systems
```

## Why another Kubernetes scanner?

Snapshot scanners are useful for finding insecure configuration. This tool asks a different question:

> What security-relevant capability or surface was introduced by this change?

Examples:

- a Role newly grants access to Secrets;
- a workload becomes privileged or enables `hostNetwork`;
- a Service changes from `ClusterIP` to `LoadBalancer` or `NodePort`;
- an Ingress adds a hostname;
- a NetworkPolicy is removed.

## Quick start

Raw multi-document YAML:

```bash
kube-blast-radius diff \
  --before rendered/main.yaml \
  --after rendered/pr.yaml
```

Kustomize directories, using `kubectl kustomize`:

```bash
kube-blast-radius diff \
  --mode kustomize \
  --before overlays/staging \
  --after overlays/production
```

Helm chart renders, with independent values files:

```bash
kube-blast-radius diff \
  --mode helm \
  --before charts/checkout \
  --after charts/checkout \
  --before-values values-current.yaml \
  --after-values values-next.yaml \
  --format json
```

Example output:

```text
HIGH  Role/payments/checkout: RBAC rule newly grants access to secrets (RBAC_SECRET_ACCESS_ADDED)
HIGH  Deployment/payments/checkout: workload newly enables hostNetwork (WORKLOAD_HOST_NETWORK_ADDED)
HIGH  Deployment/payments/checkout: workload newly adds a privileged container (WORKLOAD_PRIVILEGED_ADDED)
```

The CLI exits `1` when it emits a `HIGH` finding, `0` when no high-severity change is found, and `2` for input, parse, or renderer errors.

## Supported render modes

| Mode | Input | Renderer |
|---|---|---|
| `raw` | YAML file | None |
| `kustomize` | Directory containing `kustomization.yaml` | `kubectl kustomize` |
| `helm` | Helm chart directory | `helm template` |

Renderer commands use argument vectors rather than a shell and time out after 30 seconds. The tool never connects to a Kubernetes cluster or reads a kubeconfig. Raw mode does not write inputs; Kustomize and Helm inherit the behavior of their installed renderers, so run them in an isolated container/CI sandbox when rendering untrusted or remote-based sources.

## Container usage

Container image, with Kustomize and Helm renderers included:

```bash
docker run --rm --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$PWD:/work:ro" -w /work \
  ghcr.io/heyimusa/kube-blast-radius:main diff \
  --mode kustomize \
  --before overlays/main \
  --after overlays/pr
```

The image is published to `ghcr.io/heyimusa/kube-blast-radius` from GitHub Actions after changes land on `main` or a version tag is pushed. Pull requests build the image but never publish it.

See [container usage](docs-container.md) for renderer trust-boundary notes.

## v0.1 findings

| Code | Severity | Change detected |
|---|---|---|
| `RBAC_SECRET_ACCESS_ADDED` | High | A bound Role or ClusterRole newly includes Secret access. |
| `RBAC_WILDCARD_ACCESS_ADDED` | High | A bound role adds wildcard resource or verb access. |
| `RBAC_ESCALATION_VERB_ADDED` | High | A bound role adds `bind`, `escalate`, or `impersonate`. |
| `RBAC_RESOURCE_NAMES_WIDENED` | High | A bound role removes resource-name restrictions. |
| `RBAC_NON_RESOURCE_URL_ADDED` | Medium | A bound role adds non-resource URL access. |
| `RBAC_SECRET_ACCESS_BOUND` | High | A new binding grants access to a role that accesses Secrets. |
| `WORKLOAD_PRIVILEGED_ADDED` | High | A Deployment, StatefulSet, or DaemonSet newly adds a privileged container. |
| `WORKLOAD_HOST_NETWORK_ADDED` | High | A workload newly enables `hostNetwork`. |
| `WORKLOAD_HOST_PID_ADDED` | High | A workload newly enables `hostPID`. |
| `WORKLOAD_HOST_IPC_ADDED` | High | A workload newly enables `hostIPC`. |
| `WORKLOAD_HOST_PATH_ADDED` | High | A workload newly adds a hostPath volume. |
| `WORKLOAD_SERVICE_ACCOUNT_CHANGED` | High | A workload changes its effective ServiceAccount. |
| `WORKLOAD_RUN_AS_NON_ROOT_REMOVED` | High | A container no longer requires non-root execution. |
| `WORKLOAD_READ_ONLY_ROOT_FILESYSTEM_REMOVED` | High | A container loses a read-only root filesystem. |
| `WORKLOAD_CAPABILITY_ADDED` | High | A container adds Linux capabilities. |
| `WORKLOAD_PRIVILEGE_ESCALATION_ALLOWED` | High | A container newly allows privilege escalation. |
| `WORKLOAD_ROOT_USER_ADDED` | High | A container newly runs as UID 0. |
| `SERVICE_EXTERNAL_EXPOSURE_ADDED` | High | A Service becomes `NodePort` or `LoadBalancer`. |
| `INGRESS_HOST_ADDED` | High | An Ingress introduces a new hostname. |
| `TRAEFIK_INGRESS_ROUTE_HOST_ADDED` | High | A Traefik IngressRoute is newly introduced. |
| `TRAEFIK_INGRESS_ROUTE_MATCH_ADDED` | Medium | A Traefik IngressRoute adds a rule/match. |
| `INGRESS_DEFAULT_BACKEND_ADDED` | High | An Ingress adds a catch-all default backend. |
| `NETWORK_POLICY_REMOVED` | High | A NetworkPolicy disappears from the manifest set. |
| `ANALYSIS_UNSUPPORTED_KIND` | Info | A resource is present but outside enabled checks. |

## Explicit limits

This is intentionally an **offline change analyzer**, not a cluster security platform.

- It does not inspect a live cluster.
- It does not calculate complete NetworkPolicy reachability.
- It does not evaluate cloud IAM or admission-controller policy.
- It does not read Secret values.
- It does not claim compliance or complete privilege-escalation coverage.

The first goal is a reviewable change report that makes high-risk changes hard to overlook. Future versions can add effective RBAC subject reporting, container capabilities, hostPath mounts, ServiceAccount changes, Gateway API exposure, SARIF, and a GitHub Action.

## Development

```bash
go test ./...
go vet ./...
go run ./cmd/kube-blast-radius diff \
  --before testdata/before/manifests.yaml \
  --after testdata/after/manifests.yaml
```

## Security model

Use the tool only on manifests and render inputs you are authorized to inspect. Treat Helm charts as code from your own reviewed source: Helm templating is executed by Helm itself, and a malicious chart is outside this tool's trust boundary.

## License

Apache-2.0. See [LICENSE](LICENSE).
