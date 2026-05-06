{{/*
Expand the name of the chart.
*/}}
{{- define "june-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "june-api.fullname" -}}
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
Common labels
*/}}
{{- define "june-api.labels" -}}
helm.sh/chart: {{ include "june-api.chart" . }}
{{ include "june-api.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "june-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "june-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create chart name and version as used by the chart label
*/}}
{{- define "june-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the secret that contains sensitive application settings.
*/}}
{{- define "june-api.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-secrets" (include "june-api.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Name of the optional local PostgreSQL resources.
*/}}
{{- define "june-api.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "june-api.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the optional local PostgreSQL data volume.
*/}}
{{- define "june-api.postgresql.dataName" -}}
{{- printf "%s-data" (include "june-api.postgresql.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Name of the migration job for this Helm release revision.
*/}}
{{- define "june-api.migrations.fullname" -}}
{{- printf "%s-migrations-%v" (include "june-api.fullname" .) .Release.Revision | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels for the optional local PostgreSQL resources.
*/}}
{{- define "june-api.postgresql.labels" -}}
{{ include "june-api.labels" . }}
app.kubernetes.io/component: postgresql
{{- end }}

{{/*
Selector labels for the optional local PostgreSQL resources.
*/}}
{{- define "june-api.postgresql.selectorLabels" -}}
{{ include "june-api.selectorLabels" . }}
app.kubernetes.io/component: postgresql
{{- end }}
