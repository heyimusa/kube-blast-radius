# Container usage

The image bundles `kube-blast-radius`, `kubectl` (for Kustomize rendering), and Helm. It has no kubeconfig and runs as non-root. Mount only reviewed inputs read-only and keep its filesystem read-only:

```bash
docker build -t kube-blast-radius .
docker run --rm --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$PWD:/work:ro" -w /work \
  kube-blast-radius diff \
  --mode kustomize \
  --before overlays/main \
  --after overlays/pr
```

Helm rendering may write temporary/cache data depending on the installed Helm version and chart inputs. Use an isolated CI runner/container, mount only explicit chart and values files, and do not provide cloud, registry, or Kubernetes credentials.
