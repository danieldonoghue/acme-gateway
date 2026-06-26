# Kubernetes Deployment

Two deployment methods are provided, each with a different philosophy:

| | Helm | Kustomize |
|---|---|---|
| **Target audience** | Any Kubernetes cluster; minimal prerequisites | Platform teams managing config as plain YAML |
| **Configuration** | `values.yaml` drives everything; `helm install` is nearly ready out of the box | Base + overlay model; operators supply their own `config.yaml`, TLS secrets, and patches |
| **Upgrades** | `helm upgrade` | `kubectl apply -k` with image / patch changes |
| **Templating** | Go templates | Strategic merge / JSON patches |

Choose **Helm** if you want to be up and running quickly and are comfortable with `helm install`.  
Choose **Kustomize** if you prefer to keep plain YAML in source control and compose resources with overlays.

---

## Prerequisites (both methods)

- Kubernetes ≥ 1.25
- A container image of `acme-gateway` published to a registry you can pull from
- A TLS certificate for the gateway's public hostname — **or** DNS hook commands if using bootstrap mode, which self-provisions the certificate via dns-01 (see [TLS certificates](#tls-certificates) below)
- Persistent storage available (default `StorageClass` or named class) for the SQLite state database

---

## TLS certificates

acme-gateway terminates TLS itself — it needs a certificate for its own HTTPS listener before it can serve any ACME traffic. Three sources are supported:

### 1. cert-manager (recommended for most clusters)

If [cert-manager](https://cert-manager.io/) is installed, the Helm chart can create a `Certificate` resource that cert-manager will issue and renew automatically.

```yaml
# values.yaml (Helm)
tls:
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod   # name of your ClusterIssuer or Issuer
      kind: ClusterIssuer
```

cert-manager creates a Kubernetes Secret named `<release>-acme-gateway-tls` containing `tls.crt` and `tls.key`. The chart mounts that Secret automatically.

For Kustomize, create the cert-manager `Certificate` resource separately and use its output secret name in the `secretGenerator` (see [Kustomize docs](kustomize/README.md)).

### 2. Existing TLS Secret (`tls.existingSecret`)

If you already have (or separately create) a Kubernetes Secret of type `kubernetes.io/tls`, tell the chart its name:

```yaml
# values.yaml (Helm)
tls:
  existingSecret: acme-gateway-tls   # name of the Secret in the same namespace
```

A `kubernetes.io/tls` Secret has two keys:

| Key | Content |
|-----|---------|
| `tls.crt` | PEM certificate chain (leaf + intermediates) |
| `tls.key` | PEM private key |

Common ways to create one:

```bash
# From files on disk
kubectl create secret tls acme-gateway-tls \
  --cert=fullchain.pem \
  --key=privkey.pem \
  --namespace=<your-namespace>

# From a cert-manager Certificate (cert-manager creates the secret for you;
# just note the secretName from the Certificate spec and use it here)
```

cert-manager, Vault Agent, external-secrets, and most CI/CD secret managers can all produce `kubernetes.io/tls` Secrets. As long as the Secret exists in the same namespace before the Pod starts, the chart will mount it.

> **Note:** when using an external cert source (not bootstrap mode), the gateway loads the certificate once on startup. To pick up a renewed certificate you must roll the Deployment (`kubectl rollout restart deployment/<name>`). Tools like [Reloader](https://github.com/stakater/Reloader) can do this automatically when the Secret changes.

### 3. Bootstrap mode (dns-01 self-provisioning)

The gateway can obtain and renew its own certificate via an ACME dns-01 challenge using operator-supplied hook commands. This removes the external dependency on cert-manager but requires working DNS automation.

Limitation (intentional): hook execution is per-upstream and uses one configured deploy/cleanup implementation. The gateway does not infer authoritative DNS provider from SOA/NS and does not perform per-domain provider selection internally.

For containerized deployments, prefer compiled hook binaries from [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks) instead of shell scripts.

Hook hardening options are available under each `dns_hook` block:
- `propagation`: authoritative nameserver quorum check, run in the background before the upstream challenge is triggered. The timeout is non-fatal — on timeout the gateway triggers the upstream anyway (the TXT is already published). Lower `quorum_percent` (e.g. `80`) for CAs whose anycast nameservers converge unevenly. See [docs/decisions/0008](../docs/decisions/0008-asynchronous-answer-challenge-processing.md).
- `delegation`: optional `_acme-challenge` CNAME delegation support (with optional `allowed_zone_suffixes`; if omitted, any delegated zone is accepted).

Hooks also receive source/effective target env vars (`*_SOURCE` and `*_EFFECTIVE`) so scripts can write to delegated effective names when delegation is enabled.

```yaml
# values.yaml (Helm)
config:
  bootstrap:
    enabled: true
    domain: "acme-gateway.example.com"
    contactEmail: "ops@example.com"
    upstream: letsencrypt
    dnsHook:
      # Preferred: direct executable hook binaries (distroless-safe).
      deployScript: "/hooks/bind-dns-deploy"
      cleanupScript: "/hooks/bind-dns-cleanup"
```

    Mount `/hooks/bind-dns-deploy` and `/hooks/bind-dns-cleanup` (for example via initContainer + `emptyDir`) so they are executable in the gateway container.

Optional wrapper mode: set `dnsHooks.enabled=true` to mount chart-managed scripts at `/etc/acme-gateway/hooks/*` and point `config.bootstrap.dnsHook.*` there. This mode can run shell scripts only when using a shell-capable image.

In bootstrap mode the gateway writes the obtained certificate to the PVC so it survives restarts.

---

## Helm chart

See [helm/acme-gateway/README.md](helm/acme-gateway/README.md) for full reference.

**Quick start:**

```bash
helm install acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway \
  --create-namespace \
  --set config.server.baseURL=https://acme-gateway.example.com \
  --set config.upstreams.letsencrypt.contactEmail=ops@example.com \
  --set tls.existingSecret=acme-gateway-tls
```

---

## Kustomize

See [kustomize/README.md](kustomize/README.md) for full reference.

**Quick start:**

```bash
# 1. Edit overlays/production/config.yaml with your values
# 2. Place your TLS cert files in the overlay directory:
#      deploy/kustomize/overlays/production/tls.crt
#      deploy/kustomize/overlays/production/tls.key
# 3. Apply
kubectl apply -k deploy/kustomize/overlays/production
```
