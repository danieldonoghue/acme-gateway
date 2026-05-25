{{/*
Expand the name of the chart.
*/}}
{{- define "acme-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "acme-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label.
*/}}
{{- define "acme-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "acme-gateway.labels" -}}
helm.sh/chart: {{ include "acme-gateway.chart" . }}
{{ include "acme-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "acme-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "acme-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "acme-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "acme-gateway.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Fully-qualified image reference (repository:tag).
Falls back to Chart.AppVersion when image.tag is not set.
*/}}
{{- define "acme-gateway.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Name of the TLS Secret the Deployment should mount.
Prefers tls.existingSecret; falls back to the cert-manager-managed secret name.
*/}}
{{- define "acme-gateway.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else }}
{{- printf "%s-tls" (include "acme-gateway.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Render the full config.yaml content (un-indented).
Used by the ConfigMap template via: include "acme-gateway.configYaml" . | indent 4
*/}}
{{- define "acme-gateway.configYaml" -}}
server:
  listen: {{ .Values.config.server.listen | quote }}
  base_url: {{ .Values.config.server.baseURL | quote }}
{{- if not .Values.config.server.tls }}
  tls: false
{{- end }}

state:
  db_path: {{ .Values.config.state.dbPath | quote }}

bootstrap:
  enabled: {{ .Values.config.bootstrap.enabled }}
  cert_path: {{ .Values.config.bootstrap.certPath | quote }}
  key_path: {{ .Values.config.bootstrap.keyPath | quote }}
{{- if .Values.config.bootstrap.enabled }}
  upstream: {{ .Values.config.bootstrap.upstream | quote }}
  domain: {{ .Values.config.bootstrap.domain | quote }}
  contact_email: {{ .Values.config.bootstrap.contactEmail | quote }}
  challenge: {{ .Values.config.bootstrap.challenge | quote }}
  renew_before_days: {{ .Values.config.bootstrap.renewBeforeDays }}
  dns_hook:
    deploy_script: {{ .Values.config.bootstrap.dnsHook.deployScript | quote }}
    cleanup_script: {{ .Values.config.bootstrap.dnsHook.cleanupScript | quote }}
{{- end }}

upstreams:
{{- range $id, $u := .Values.config.upstreams }}
  {{ $id }}:
    directory_url: {{ $u.directoryURL | quote }}
    contact_email: {{ $u.contactEmail | quote }}
{{- if $u.accountCount }}
    account_count: {{ $u.accountCount }}
{{- end }}
{{- if $u.caCertPath }}
    ca_cert_path: {{ $u.caCertPath | quote }}
{{- end }}
{{- if $u.eab }}
    eab:
      key_id: {{ $u.eab.keyID | quote }}
      hmac_key: {{ $u.eab.hmacKey | quote }}
{{- end }}
{{- end }}

profiles:
{{- range $name, $desc := .Values.config.profiles }}
  {{ $name }}: {{ $desc | quote }}
{{- end }}

routing:
{{- if .Values.config.routing.rules }}
  rules:
{{- range .Values.config.routing.rules }}
  - match:
{{- if .match.profile }}
      profile: {{ .match.profile | quote }}
{{- end }}
{{- if .match.keyType }}
      key_type: {{ .match.keyType | quote }}
{{- end }}
{{- if .match.domainSuffix }}
      domain_suffix: {{ .match.domainSuffix | quote }}
{{- end }}
    upstream: {{ .upstream | quote }}
{{- if .upstreamProfile }}
    upstream_profile: {{ .upstreamProfile | quote }}
{{- end }}
{{- end }}
{{- else }}
  rules: []
{{- end }}
  default_upstream: {{ .Values.config.routing.defaultUpstream | quote }}
{{- end }}

{{/*
Validate TLS configuration.
When config.server.tls is true (default): exactly one TLS source must be configured.
When config.server.tls is false (external termination): no TLS sources may be set.
Call at the top of the Deployment template to fail fast on misconfiguration.
*/}}
{{- define "acme-gateway.validateTLS" -}}
{{- if .Values.config.server.tls -}}
  {{- $sources := list -}}
  {{- if .Values.tls.existingSecret -}}{{- $sources = append $sources "tls.existingSecret" -}}{{- end -}}
  {{- if .Values.tls.certManager.enabled -}}{{- $sources = append $sources "tls.certManager.enabled" -}}{{- end -}}
  {{- if .Values.config.bootstrap.enabled -}}{{- $sources = append $sources "config.bootstrap.enabled" -}}{{- end -}}
  {{- if eq (len $sources) 0 -}}
  {{- fail "acme-gateway: no TLS source configured. Set one of: tls.existingSecret, tls.certManager.enabled=true, or config.bootstrap.enabled=true" -}}
  {{- end -}}
  {{- if gt (len $sources) 1 -}}
  {{- fail (printf "acme-gateway: conflicting TLS sources (%s). Configure exactly one of: tls.existingSecret, tls.certManager.enabled, or config.bootstrap.enabled." (join ", " $sources)) -}}
  {{- end -}}
{{- else -}}
  {{- /* External TLS termination — no certificate managed at the gateway. */ -}}
  {{- if .Values.tls.existingSecret -}}
  {{- fail "acme-gateway: tls.existingSecret must not be set when config.server.tls is false (no TLS listener in external termination mode)" -}}
  {{- end -}}
  {{- if .Values.tls.certManager.enabled -}}
  {{- fail "acme-gateway: tls.certManager.enabled must not be set when config.server.tls is false (no TLS listener in external termination mode)" -}}
  {{- end -}}
  {{- if .Values.config.bootstrap.enabled -}}
  {{- fail "acme-gateway: config.bootstrap.enabled cannot be true when config.server.tls is false" -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{/*
Validate: bootstrap mode requires persistence.enabled=true.
Without a persistent volume the bootstrapped cert and upstream account keypairs
are lost on every Pod restart, burning CA rate limits each time.
*/}}
{{- define "acme-gateway.validateBootstrap" -}}
{{- if and .Values.config.bootstrap.enabled (not .Values.persistence.enabled) -}}
{{- fail "acme-gateway: config.bootstrap.enabled requires persistence.enabled=true; without persistent storage the bootstrapped cert and account keys are lost on every Pod restart, burning CA rate limits." -}}
{{- end -}}
{{- if and .Values.config.bootstrap.enabled (not .Values.dnsHooks.enabled) -}}
{{- fail "acme-gateway: config.bootstrap.enabled requires dnsHooks.enabled=true; the bootstrap dns-01 flow executes the hook scripts mounted from the dns-hooks ConfigMap." -}}
{{- end -}}
{{- end -}}

{{/*
Hostname extracted from config.server.baseURL for TLS Certificate SANs.
Strips the scheme and port so e.g. https://acme.example.com:8443 → acme.example.com.
Safe to use directly as a dnsNames entry.
Only valid when config.server.tls is true.
*/}}
{{- define "acme-gateway.certHostname" -}}
{{- if not .Values.config.server.tls -}}
{{- fail "acme-gateway: acme-gateway.certHostname is not applicable when config.server.tls is false" -}}
{{- end -}}
{{- $host := .Values.config.server.baseURL | regexFind "://([^/:]+)" | trimPrefix "://" -}}
{{- if not $host -}}
{{- fail (printf "acme-gateway: cannot extract hostname from config.server.baseURL=%q; expected https://hostname or https://hostname:port" .Values.config.server.baseURL) -}}
{{- end -}}
{{- $host -}}
{{- end -}}
