## Install

### Docker

```bash
docker pull ghcr.io/danieldonoghue/acme-gateway:%%VERSION%%
```

### Binary (linux/amd64 or linux/arm64)

```bash
tar -xzf acme-gateway_%%VERSION%%_linux_amd64.tar.gz
sudo install -m 0755 acme-gateway_%%VERSION%%_linux_amd64/acme-gateway /usr/local/bin/acme-gateway

# Optional: install example DNS hooks for dns-01 upstreams
sudo install -d /etc/acme-gateway/hooks.d/examples
sudo cp acme-gateway_%%VERSION%%_linux_amd64/hooks.d/examples/*.sh /etc/acme-gateway/hooks.d/examples/
```

### Debian package (Debian 12/13, amd64/arm64)

```bash
sudo dpkg -i acme-gateway_%%DEB_VERSION%%_debian12_amd64.deb
```

The package installs the binary to `/usr/local/bin/acme-gateway`, drops a config example at `/etc/acme-gateway/config.yaml.example`, installs DNS hook examples at `/etc/acme-gateway/hooks.d/examples/`, creates the `acme-gateway` system user, and registers a systemd unit.

---

## Configure

Copy the example config and edit it before first start:

```bash
sudo cp /etc/acme-gateway/config.yaml.example /etc/acme-gateway/config.yaml
sudo $EDITOR /etc/acme-gateway/config.yaml
```

Key settings:

| Key | Description |
|-----|-------------|
| `server.listen` | Address to bind, e.g. `":443"` |
| `server.base_url` | Public HTTPS base URL clients will use |
| `state.db_path` | SQLite database path (must be writable) |
| `upstreams.<name>.directory_url` | ACMEv2 directory URL of the upstream CA |
| `upstreams.<name>.eab` | External Account Binding credentials (private CAs) |
| `bootstrap.enabled` | `true` to obtain the gateway's own TLS cert via ACME on first start |
| `bootstrap.upstream` | Which upstream CA to use for the gateway's own cert |
| `rules` | Ordered list of routing rules mapping domains/profiles to an upstream |

Sensitive values (EAB keys, etc.) support `${ENV_VAR}` interpolation in the config file.

---

## Run

### systemd (binary or .deb install)

```bash
sudo systemctl enable --now acme-gateway
sudo journalctl -fu acme-gateway
```

### Docker

```bash
docker run -d \
  --name acme-gateway \
  -p 443:443 \
  -v /etc/acme-gateway/config.yaml:/etc/acme-gateway/config.yaml:ro \
  -v /var/lib/acme-gateway:/var/lib/acme-gateway \
  ghcr.io/danieldonoghue/acme-gateway:%%VERSION%% \
  -config /etc/acme-gateway/config.yaml
```

---

## What's changed
