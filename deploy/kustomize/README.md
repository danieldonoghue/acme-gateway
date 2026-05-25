# acme-gateway Kustomize

Deploys [acme-gateway](../../README.md) using plain Kubernetes YAML composed with [Kustomize](https://kustomize.io/).

## Structure

```
kustomize/
├── base/                        # Structural resources shared by all environments
│   ├── deployment.yaml          # Deployment (image is a placeholder; set in overlays)
│   ├── pvc.yaml                 # PersistentVolumeClaim for the SQLite database
│   ├── service.yaml             # LoadBalancer Service on port 443
│   └── serviceaccount.yaml
└── overlays/
    ├── production/              # Production environment
    │   ├── kustomization.yaml
    │   ├── config.yaml          # acme-gateway config — edit this
    │   ├── deployment-patch.yaml # Resource / env patches
    │   ├── tls.crt              # TLS cert chain — create this (not committed)
    │   └── tls.key              # TLS private key — create this (not committed)
    └── staging/                 # Staging environment (uses LE staging endpoint)
        ├── kustomization.yaml
        ├── config.yaml
        ├── deployment-patch.yaml
        ├── tls.crt              # (not committed)
        └── tls.key              # (not committed)
```

The **base** contains everything that never changes between environments: the Deployment structure, Service, PVC, and ServiceAccount. It references two resources by name that overlays must provide:

- `acme-gateway-config` ConfigMap — generated from `config.yaml` in the overlay
- `acme-gateway-tls` Secret — generated from `tls.crt` + `tls.key` in the overlay

**Overlays** are where all environment-specific configuration lives. You must edit them before applying.

---

## Before you apply

### 1. Edit `config.yaml`

Open `overlays/production/config.yaml` (or `overlays/staging/config.yaml`) and fill in every value marked **REQUIRED**:

```yaml
server:
  base_url: "https://acme-gateway.example.com"  # REQUIRED: your actual hostname

upstreams:
  letsencrypt:
    contact_email: "ops@example.com"            # REQUIRED: ACME account email
```

See [config.yaml.example](../../config.yaml.example) in the repository root for the full set of options including private CA upstreams, EAB, routing rules, and bootstrap configuration.

### 2. Set the image

In `overlays/production/kustomization.yaml`, replace the placeholder with your actual image:

```yaml
images:
  - name: acme-gateway
    newName: ghcr.io/danieldonoghue/acme-gateway
    newTag: v0.0.2
```

### 3. Provide the TLS certificate

Create the certificate files in the overlay directory. These must **not** be committed to version control.

**Option A — from existing files:**
```bash
cp /path/to/fullchain.pem deploy/kustomize/overlays/production/tls.crt
cp /path/to/privkey.pem   deploy/kustomize/overlays/production/tls.key
```

**Option B — from a cert-manager managed Secret:**
```bash
# Export from an existing kubernetes.io/tls Secret:
kubectl get secret <cert-manager-secret> -n <ns> \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > deploy/kustomize/overlays/production/tls.crt
kubectl get secret <cert-manager-secret> -n <ns> \
  -o jsonpath='{.data.tls\.key}' | base64 -d > deploy/kustomize/overlays/production/tls.key
```

Alternatively, manage the cert-manager `Certificate` resource separately and reference its output secret directly in the overlay's `secretGenerator` (replacing the `files:` source with an appropriate `kubectl` patch or Argo CD / Flux sync).

**Option C — self-signed cert for staging/testing:**
```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 90 \
  -keyout deploy/kustomize/overlays/staging/tls.key \
  -out    deploy/kustomize/overlays/staging/tls.crt \
  -subj "/CN=acme-gateway-staging.example.com" \
  -addext "subjectAltName=DNS:acme-gateway-staging.example.com"
```

> **Important:** the gateway loads the certificate once at startup. To rotate a certificate, update the Secret and then run `kubectl rollout restart deployment/acme-gateway -n <namespace>`. Tools like [Reloader](https://github.com/stakater/Reloader) can automate this.

### 4. (Optional) EAB credentials for private CA upstreams

If any upstream requires External Account Binding, create an env file with the credentials and add a `secretGenerator` entry in `kustomization.yaml`:

```bash
# Create eab.env (do NOT commit this file)
cat > deploy/kustomize/overlays/production/eab.env <<EOF
PRIVATE_CA_EAB_KID=<your-kid>
PRIVATE_CA_EAB_HMAC=<your-hmac>
EOF
```

Uncomment the `secretGenerator` block for `acme-gateway-eab` in `kustomization.yaml`, then uncomment the `envFrom` block in `deployment-patch.yaml`. Reference the variables in `config.yaml` using `${PRIVATE_CA_EAB_KID}` syntax.

---

## Applying

```bash
# Dry run — preview what will be applied
kubectl diff -k deploy/kustomize/overlays/production

# Apply
kubectl apply -k deploy/kustomize/overlays/production

# Watch rollout
kubectl rollout status deployment/acme-gateway -n acme-gateway
```

For staging:
```bash
kubectl apply -k deploy/kustomize/overlays/staging
```

---

## Customising the base

If the base manifests need adjusting for your environment (e.g. different storage class, node affinity, additional labels), add a patch in the overlay rather than editing the base directly. This keeps the base reusable:

```yaml
# overlays/production/kustomization.yaml
patches:
  - path: deployment-patch.yaml
    target:
      kind: Deployment
      name: acme-gateway
  - path: pvc-patch.yaml          # additional patch
    target:
      kind: PersistentVolumeClaim
      name: acme-gateway-data
```

```yaml
# overlays/production/pvc-patch.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: acme-gateway-data
spec:
  storageClassName: fast-ssd
```

---

## Notes

**Single replica only.** The Deployment is fixed at `replicas: 1` because acme-gateway uses SQLite, which supports only a single writer. The `strategy: Recreate` ensures the old Pod is fully terminated before the new one starts.

**Namespace.** Each overlay sets its own namespace (`acme-gateway` for production, `acme-gateway-staging` for staging). Create the namespace before applying if it does not exist:
```bash
kubectl create namespace acme-gateway
```

**State backup.** The SQLite database on the PVC holds the gateway's upstream ACME account keypairs. Back it up. Loss requires re-registering accounts with every upstream CA.
