# Contributing to kube-blast-radius

Thanks for improving `kube-blast-radius`.

## Before opening a change

- Read the [README](README.md), especially the explicit limits.
- Keep the tool an **offline manifest-change analyzer**. Do not add cluster,
  kubeconfig, registry, or credential access without a separately discussed
  design and threat model.
- Use only synthetic and sanitized fixtures. Never commit customer manifests,
  credentials, internal hostnames, or Secret values.

## Development checks

Run the same baseline checks as CI:

```sh
go test -race ./...
go vet ./...
go build ./cmd/kube-blast-radius
```

For a finding change, add a focused before/after fixture and assert both the
finding and exit-code behavior. The versioned acceptance fixtures under
`acceptance/` are executable examples of the release-level contract.

## Pull requests

Explain the user-visible behavior, the input boundary, and any new limitation.
Update the README's findings or explicit-limits sections when the public
contract changes. A PR must not claim that static manifest analysis proves
runtime reachability, cluster state, policy enforcement, image safety, or
compliance.

## Reporting problems

Use the issue forms for missed/incorrect findings and unsupported inputs. For a
security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
