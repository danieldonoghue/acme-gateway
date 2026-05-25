# acme-gateway Helm Chart

Deploys [acme-gateway](../../README.md) — an ACMEv2 gateway that routes certificate requests to multiple upstream CAs — onto any Kubernetes cluster.

## Prerequisites

- Helm ≥ 3.10
- Kubernetes ≥ 1.25
- A container image of `acme-gateway` (set `image.repository` and `image.tag`)
- A TLS certificate source (see [TLS options](#tls-options))
- Persistent storage (default `StorageClass` or set `persistence.storageClass`)

## Quick start

### With cert-manager (recommended)

```bash
helm install acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway \
  --create-namespace \
  --set image.repository=ghcr.io/your-org/acme-gateway \
  --set image.tag=v1.0.0 \
  --set config.server.baseURL=https://acme-gateway.example.com \
  --set config.upstreams.letsencrypt.contactEmail=ops@example.com \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.name=letsencrypt-prod
```

### With an existing TLS Secret

```bash
# 1. Create the secret first (or let cert-manager / your secret manager do it)
kubectl create secret tls acme-gateway-tls \
  --cert=fullchain.pem --key=privkey.pem \
  --namespace acme-gateway

# 2. Install the chart
helm install acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway \
  --create-namespace \
  --set image.repository=ghcr.io/your-org/acme-gateway \
  --set image.tag=v1.0.0 \
  --set config.server.baseURL=https://acme-gateway.example.com \
  --set config.upstreams.letsencrypt.contactEmail=ops@example.com \
  --set tls.existingSecret=acme-gateway-tls
```

### With a values file (recommended for production)

```bash
helm install acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway \
  --create-namespace \
  --values my-values.yaml
```

## TLS options

Exactly one of the following must be configured. See the [deploy README](../README.md#tls-certificates) for background on each option.

| Option | When to use |
|--------|-------------|
| `tls.certManager.enabled: true` | cert-manager is installed; easiest automated renewal |
| `tls.existingSecret: <name>` | You manage certs externally (Vault, manual, CI/CD) |
| `config.bootstrap.enabled: true` + `dnsHooks` | No cert-manager; you have DNS automation scripts |

## Upgrading

```bash
helm upgrade acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway \
  --values my-values.yaml
```

The Deployment uses `strategy: Recreate` (required for SQLite single-writer). Upgrades will briefly interrupt ACME traffic while the old Pod terminates and the new one starts — plan upgrades during low-traffic periods if uptime is critical.

## Uninstalling

```bash
helm uninstall acme-gateway --namespace acme-gateway
```

> **Warning:** this does not delete the PVC. The SQLite database — which contains upstream ACME account keypairs — is retained. Delete it manually once you are sure you no longer need the data:
> ```bash
> kubectl delete pvc acme-gateway-data --namespace acme-gateway
> ```

---

## Values reference

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/your-org/acme-gateway` | Container image repository |
| `image.tag` | _(Chart.appVersion)_ | Image tag; defaults to chart's `appVersion` |
| `image.pullPolicy` | `IfNotPresent` | |
| **Server** | | |
| `config.server.listen` | `:8443` | Container-internal listen address. Keep at a non-privileged port; the Service maps `443 → 8443`. |
| `config.server.baseURL` | `https://acme-gateway.example.com` | **Required.** Public HTTPS URL seen by ACME clients. Must match the TLS cert SAN. |
| **State** | | |
| `config.state.dbPath` | `/var/lib/acme-gateway/state.db` | SQLite database path (inside the PVC mount) |
| **Bootstrap** | | |
| `config.bootstrap.enabled` | `false` | Enable self-provisioning of the server TLS cert via dns-01 |
| `config.bootstrap.upstream` | `letsencrypt` | Upstream ID to use for bootstrap cert |
| `config.bootstrap.domain` | `""` | Hostname for the bootstrap cert |
| `config.bootstrap.contactEmail` | `""` | Contact email for the bootstrap ACME account |
| `config.bootstrap.renewBeforeDays` | `30` | Renew the cert this many days before expiry |
| **Upstreams** | | |
| `config.upstreams.<id>.directoryURL` | _(Let's Encrypt)_ | ACME directory URL for this upstream CA |
| `config.upstreams.<id>.contactEmail` | `certadmin@example.com` | **Required.** Contact email for ACME account registration |
| `config.upstreams.<id>.accountCount` | `1` | Independent ACME accounts for load spreading (LE only; EAB upstreams need separate entries) |
| `config.upstreams.<id>.caCertPath` | `""` | Path to PEM file for private CA TLS trust (mount via `extraVolumes`) |
| `config.upstreams.<id>.eab.keyID` | `""` | EAB key ID; use `${ENV_VAR}` to reference a Secret via `extraEnv` |
| `config.upstreams.<id>.eab.hmacKey` | `""` | EAB HMAC key |
| **Profiles** | | |
| `config.profiles` | `{tlsserver: "..."}` | Map of profile name → description exposed to ACME clients |
| **Routing** | | |
| `config.routing.rules` | _(single tlsserver rule)_ | Ordered list of routing rules; first match wins |
| `config.routing.defaultUpstream` | `letsencrypt` | Upstream to use when no rule matches |
| **TLS** | | |
| `tls.existingSecret` | `""` | Name of a pre-existing `kubernetes.io/tls` Secret to mount |
| `tls.certManager.enabled` | `false` | Create a cert-manager `Certificate` resource |
| `tls.certManager.issuerRef.name` | `letsencrypt-prod` | cert-manager Issuer or ClusterIssuer name |
| `tls.certManager.issuerRef.kind` | `ClusterIssuer` | |
| `tls.certManager.duration` | `2160h` | Certificate validity duration (90 days) |
| `tls.certManager.renewBefore` | `720h` | Renew this long before expiry (30 days) |
| **DNS Hooks** | | |
| `dnsHooks.enabled` | `false` | Mount DNS hook scripts (required when `bootstrap.enabled: true`) |
| `dnsHooks.deployScript` | _(stub)_ | Shell script to create dns-01 TXT record |
| `dnsHooks.cleanupScript` | _(stub)_ | Shell script to remove dns-01 TXT record |
| **Extras** | | |
| `extraEnv` | `[]` | Additional env vars (use for EAB secrets referenced as `${VAR}` in config) |
| `extraEnvFrom` | `[]` | Inject all keys from a Secret/ConfigMap as env vars |
| `extraVolumes` | `[]` | Additional volumes (e.g. private CA cert) |
| `extraVolumeMounts` | `[]` | Additional volume mounts |
| **Persistence** | | |
| `persistence.enabled` | `true` | Create a PVC for the SQLite database |
| `persistence.storageClass` | `""` | Storage class; empty uses cluster default |
| `persistence.size` | `1Gi` | |
| `persistence.existingClaim` | `""` | Use an existing PVC instead of creating one |
| **Service** | | |
| `service.type` | `LoadBalancer` | Service type; use `ClusterIP` + Ingress TCP passthrough if preferred |
| `service.port` | `443` | External port |
| **Pod** | | |
| `podSecurityContext.fsGroup` | `65532` | GID for volume ownership; matches the `nonroot` user in the distroless release image (adjust for custom images) |
| `resources` | _(see values.yaml)_ | Container resource requests/limits |
| `nodeSelector` | `{}` | |
| `tolerations` | `[]` | |
| `affinity` | `{}` | |

### Routing rule structure

```yaml
config:
  routing:
    rules:
      - match:
          profile: "tlsserver"        # optional: client --preferred-profile value
          keyType: "RSA"              # optional: RSA or ECDSA
          domainSuffix: ".internal"   # optional: domain suffix match
        upstream: "private-ca"        # required: upstream ID from config.upstreams
        upstreamProfile: "tlsserver"  # optional: "" = strip, "$passthrough" = forward, "name" = override
```

All `match` fields are optional and ANDed together. Rules are evaluated in order; the first match wins. If no rule matches, `config.routing.defaultUpstream` is used.

### Using EAB credentials securely

Never put EAB secrets directly in values files. Instead, create a Kubernetes Secret and reference it via environment variables:

```bash
kubectl create secret generic acme-gateway-eab \
  --from-literal=PRIVATE_CA_EAB_KID=<kid> \
  --from-literal=PRIVATE_CA_EAB_HMAC=<hmac> \
  --namespace acme-gateway
```

```yaml
# values.yaml
extraEnvFrom:
  - secretRef:
      name: acme-gateway-eab

config:
  upstreams:
    private-ca:
      directoryURL: "https://acme.your-ca.example/directory"
      contactEmail: "ops@example.com"
      eab:
        keyID: "${PRIVATE_CA_EAB_KID}"
        hmacKey: "${PRIVATE_CA_EAB_HMAC}"
```
