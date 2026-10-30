{{- define "lumen.name" -}}lumen{{- end }}
{{- define "lumen.fullname" -}}
{{- printf "%s-lumen" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "lumen.labels" -}}
app.kubernetes.io/name: {{ include "lumen.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
