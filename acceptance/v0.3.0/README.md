# v0.3.0 release acceptance evidence

This directory is a sanitized, reproducible acceptance case for the planned
`v0.3.0` release. It exercises the new **literal image-reference transition**
findings using explicitly supplied rendered manifest data.

It is static/offline analysis only. The fixture does not contact a registry or
cluster and does not establish image integrity, signature status, provenance,
SBOM contents, vulnerability status, runtime behavior, or safety.

## Inputs

- `before.yaml` contains one Deployment with a digest-qualified application
  image, an init container, and an ephemeral container.
- `after.yaml` removes the application digest, introduces `:latest` for that
  application image, changes the init-container reference, and uses a
  `:latest@sha256:...` form for the ephemeral container.
- `expected.json` is the exact JSON result, ordered according to the tool's
  severity/code ordering.

All names, registry hosts, digests, and namespaces are synthetic placeholders.

## Reproducible acceptance procedure

Run these commands from the repository root. The fixture is copied to a
private temporary directory and made traversable/readable for the container's
non-root UID without weakening the container runtime restrictions.

```sh
set -eu
image=kube-blast-radius:acceptance
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

cp acceptance/v0.3.0/before.yaml "$fixture/before.yaml"
cp acceptance/v0.3.0/after.yaml "$fixture/after.yaml"
cp acceptance/v0.3.0/expected.json "$fixture/expected.json"
chmod 755 "$fixture"
chmod 644 "$fixture"/*.yaml "$fixture"/expected.json

docker build -t "$image" .
```

### Positive control

The test intentionally includes high findings, so it must exit `1` while
producing the exact expected JSON result.

```sh
set +e
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 \
  -v "$fixture:/input:ro" \
  "$image" diff \
  --before /input/before.yaml --after /input/after.yaml --format json \
  > "$fixture/actual.json"
status=$?
set -e
test "$status" = 1
cmp --silent "$fixture/actual.json" "$fixture/expected.json"
```

### Negative control

The unmodified before fixture compared to itself must exit `0` and emit an
empty result.

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges:true --user 65532:65532 \
  -v "$fixture:/input:ro" \
  "$image" diff \
  --before /input/before.yaml --after /input/before.yaml --format json \
  > "$fixture/negative.json"
printf '{\n  "findings": []\n}\n' > "$fixture/empty.json"
cmp --silent "$fixture/negative.json" "$fixture/empty.json"
```

The controls prove only the documented static reference-transition behavior.
They do not prove an image is trusted or safe.
