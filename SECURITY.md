# Security policy

## Supported versions

Security fixes are applied to the latest released version of `kube-blast-radius`.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.

Use GitHub's private security-advisory reporting for this repository, including:

- a concise description and affected version or commit;
- a minimal, sanitized reproduction when possible;
- impact and any proposed mitigation; and
- safe contact details for follow-up.

Do not include credentials, customer manifests, internal hostnames, kubeconfig
content, or other sensitive material. Reports receive an acknowledgement within
seven days when contact details are provided.

## Security scope

`kube-blast-radius` is an offline change analyzer for explicitly supplied
Kubernetes manifests. It does not connect to clusters or registries, read a
kubeconfig, execute a shell, or inspect Secret values.

A missed finding, an incorrect finding, or unsupported manifest/render input is
important but is not automatically a security vulnerability. Please use the
appropriate issue form for those reports.
