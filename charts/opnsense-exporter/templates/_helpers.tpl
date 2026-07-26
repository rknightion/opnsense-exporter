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

{{- define "opnsense-exporter.args" -}}
{{- range $arg := .Values.extraArgs }}
{{- if or
  (eq $arg "--opnsense.api-key") (hasPrefix "--opnsense.api-key=" $arg)
  (eq $arg "--opnsense.api-secret") (hasPrefix "--opnsense.api-secret=" $arg)
  (eq $arg "--opnsense.address") (hasPrefix "--opnsense.address=" $arg)
  (eq $arg "--opnsense.protocol") (hasPrefix "--opnsense.protocol=" $arg)
  (eq $arg "--exporter.instance-label") (hasPrefix "--exporter.instance-label=" $arg)
  (eq $arg "--web.listen-address") (hasPrefix "--web.listen-address=" $arg)
  (eq $arg "--config.check") (hasPrefix "--config.check=" $arg)
  (eq $arg "--logs.enabled") (hasPrefix "--logs.enabled=" $arg)
  (hasPrefix "--logs.syslog." $arg)
  (hasPrefix "--logs.zenarmor." $arg)
  (eq $arg "--flow.enabled") (hasPrefix "--flow.enabled=" $arg)
  (hasPrefix "--flow.netflow." $arg) }}
{{- fail (printf "extraArgs may not set chart-managed or secret flag %q" $arg) }}
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
{{- end }}
