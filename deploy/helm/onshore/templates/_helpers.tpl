{{- define "rv.labels" -}}
app.kubernetes.io/name: onshore
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .name }}
{{- end -}}

{{- define "rv.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .name }}
{{- end -}}

{{- define "rv.secret" -}}
- name: {{ .key }}
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.existingSecret }}
      key: {{ .from | default .key }}
{{- end -}}

{{/* A hardened Deployment. Args: root, name, image, port, replicas, resources, env (rendered string). */}}
{{- define "rv.deployment" -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .name }}
  labels: {{- include "rv.labels" . | nindent 4 }}
spec:
  replicas: {{ .replicas }}
  selector:
    matchLabels: {{- include "rv.selector" . | nindent 6 }}
  template:
    metadata:
      labels: {{- include "rv.labels" . | nindent 8 }}
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        fsGroup: 65532
        seccompProfile: { type: RuntimeDefault }
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels: {{- include "rv.selector" . | nindent 14 }}
      containers:
        - name: {{ .name }}
          image: "{{ .root.Values.image.registry }}/{{ .image }}:{{ .root.Values.image.tag }}"
          imagePullPolicy: {{ .root.Values.image.pullPolicy }}
          ports:
            - containerPort: {{ .port }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
          env:
            - { name: RV_TLS_CERT, value: /tls/cert.pem }
            - { name: RV_TLS_KEY, value: /tls/key.pem }
{{ .env | indent 12 }}
          readinessProbe:
            tcpSocket: { port: {{ .port }} }
            periodSeconds: 5
          livenessProbe:
            tcpSocket: { port: {{ .port }} }
            periodSeconds: 20
          resources: {{- toYaml .resources | nindent 12 }}
          volumeMounts:
            - { name: tls, mountPath: /tls, readOnly: true }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - name: tls
          secret:
            secretName: {{ .root.Values.internalTlsSecretPrefix }}-{{ .name }}
        - name: tmp
          emptyDir: { medium: Memory }
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .name }}
  labels: {{- include "rv.labels" . | nindent 4 }}
spec:
  selector: {{- include "rv.selector" . | nindent 4 }}
  ports:
    - port: {{ .port }}
      targetPort: {{ .port }}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ .name }}
spec:
  maxUnavailable: 1
  selector:
    matchLabels: {{- include "rv.selector" . | nindent 6 }}
{{- end -}}

{{/* A NetworkPolicy mirroring the Compose networks. Args: root, name, port, from (list), egress (rendered string). */}}
{{- define "rv.netpol" -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ .name }}
spec:
  podSelector:
    matchLabels: {{- include "rv.selector" . | nindent 6 }}
  policyTypes: [Ingress, Egress]
  ingress:
    - ports: [{ port: {{ .port }} }]
      from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: {{ .root.Values.ingress.controllerNamespace }}
{{- range .from }}
        - podSelector:
            matchLabels:
              app.kubernetes.io/component: {{ . }}
{{- end }}
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
{{ .egress | indent 4 }}
{{- end -}}
