{{- define "opnsense-exporter.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "opnsense-exporter.fullname" -}}
{{- $name := include "opnsense-exporter.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "opnsense-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "opnsense-exporter.selectorLabels" -}}
app.kubernetes.io/name: {{ include "opnsense-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "opnsense-exporter.labels" -}}
helm.sh/chart: {{ include "opnsense-exporter.chart" . }}
{{ include "opnsense-exporter.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "opnsense-exporter.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{- define "opnsense-exporter.securityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "opnsense-exporter.env" -}}
- name: OPNSENSE_EXPORTER_INSTANCE_LABEL
  value: {{ .Values.opnsense.instanceLabel | quote }}
- name: OPNSENSE_EXPORTER_OPS_API
  value: {{ required "opnsense.address is required" .Values.opnsense.address | quote }}
- name: OPNSENSE_EXPORTER_OPS_PROTOCOL
  value: {{ .Values.opnsense.protocol | quote }}
- name: OPS_API_KEY_FILE
  value: /etc/opnsense-exporter/creds/api-key
- name: OPS_API_SECRET_FILE
  value: /etc/opnsense-exporter/creds/api-secret
{{- end }}

{{/*
opnsense-exporter.reservedFlagReason takes a bare flag name (no leading --, no value)
and returns the curated value that already sets it, or empty if the flag is not
chart-managed. Shared by the extraArgs check and the settings check below so the two
reserved-flag lists cannot drift apart -- a flag added to one and not the other would
let extraArgs and settings disagree about what's safe to set.
*/}}
{{- define "opnsense-exporter.reservedFlagReason" -}}
{{- if or (eq . "opnsense.api-key") (eq . "opnsense.api-secret") -}}
already set via the mounted credentials Secret (opnsense.existingSecret)
{{- else if eq . "opnsense.address" -}}
already set via opnsense.address
{{- else if eq . "opnsense.protocol" -}}
already set via opnsense.protocol
{{- else if eq . "exporter.instance-label" -}}
already set via opnsense.instanceLabel
{{- else if eq . "web.listen-address" -}}
already set via ports.http
{{- else if eq . "config.check" -}}
it is never renderable via settings or extraArgs: a one-shot validate-and-exit flag that would turn every pod start into a no-op that exits 0
{{- else if eq . "logs.enabled" -}}
already set via receivers.syslog.enabled / receivers.zenarmor.enabled
{{- else if hasPrefix "logs.syslog." . -}}
already set via receivers.syslog.*
{{- else if hasPrefix "logs.zenarmor." . -}}
already set via receivers.zenarmor.*
{{- else if eq . "flow.enabled" -}}
already set via receivers.netflow.enabled
{{- else if hasPrefix "flow.netflow." . -}}
already set via receivers.netflow.*
{{- end -}}
{{- end }}

{{- define "opnsense-exporter.args" -}}
{{- range $arg := .Values.extraArgs }}
{{- $name := (splitn "=" 2 (trimPrefix "--" $arg))._0 }}
{{- $reason := include "opnsense-exporter.reservedFlagReason" $name }}
{{- if $reason }}
{{- fail (printf "extraArgs may not set chart-managed or secret flag %q: %s" $arg $reason) }}
{{- end }}
{{- end }}
{{- if or .Values.receivers.syslog.enabled .Values.receivers.zenarmor.enabled }}
- "--logs.enabled"
{{- end }}
{{- if .Values.receivers.syslog.enabled }}
- "--logs.syslog.enabled"
- "--logs.syslog.listen-udp=:{{ .Values.ports.syslog }}"
- "--logs.syslog.listen-tcp=:{{ .Values.ports.syslog }}"
{{- if .Values.receivers.syslog.allowedPeers }}
- "--logs.syslog.allowed-peers={{ join "," .Values.receivers.syslog.allowedPeers }}"
{{- end }}
{{- end }}
{{- if .Values.receivers.zenarmor.enabled }}
- "--logs.zenarmor.enabled"
- "--logs.zenarmor.listen-http=:{{ .Values.ports.zenarmor }}"
{{- if .Values.receivers.zenarmor.allowedPeers }}
- "--logs.zenarmor.allowed-peers={{ join "," .Values.receivers.zenarmor.allowedPeers }}"
{{- end }}
{{- end }}
{{- if .Values.receivers.netflow.enabled }}
- "--flow.enabled"
- "--flow.netflow.enabled"
- "--flow.netflow.listen=:{{ .Values.ports.netflow }}"
{{- range .Values.receivers.netflow.allowedPeers }}
- "--flow.netflow.allowed-peers={{ . }}"
{{- end }}
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- range $name, $value := .Values.settings }}
{{- $reason := include "opnsense-exporter.reservedFlagReason" $name }}
{{- if $reason }}
{{- fail (printf "settings.%s conflicts with a chart-managed flag: %s. Set it there instead, or drop the curated value if settings should win." $name $reason) }}
{{- end }}
{{- if kindIs "slice" $value }}
{{- range $item := $value }}
- "--{{ $name }}={{ $item }}"
{{- end }}
{{- else }}
- "--{{ $name }}={{ $value }}"
{{- end }}
{{- end }}
{{- end }}
