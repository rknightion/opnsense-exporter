---
title: Kubernetes
description: Deploy the OPNsense Exporter on Kubernetes with secrets, Deployment manifests, and Prometheus Operator scrape configuration
tags:
  - Deployment
  - Kubernetes
---

# Kubernetes Deployment

Deploy the OPNsense Exporter in a Kubernetes cluster with proper secret management and Prometheus integration.

## Prerequisites

- A Kubernetes cluster with kubectl access
- OPNsense API credentials (key and secret)
- Optional: [Prometheus Operator](https://prometheus-operator.dev/) for automated scrape configuration

## Step 1: Create the Secret

When you [generate API keys](https://docs.opnsense.org/development/how-tos/api.html#creating-keys) on OPNsense, you get a `.txt` file with the key and secret. Add your OPNsense host and protocol to this file:

```text title="opnsense_apikey.txt"
key=xt...Nt
secret=EK...ho
host=opnsense.lan
protocol=https
```

Create the Secret in your cluster:

```bash
kubectl create secret generic opnsense-exporter-cfg \
  --from-env-file=opnsense_apikey.txt
```

## Step 2: Deploy the exporter

The following manifest creates a Deployment and a ClusterIP Service. API credentials are mounted as files from the Secret, and connection settings are injected as environment variables.

```yaml title="deployment.yaml"
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: opnsense-exporter
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: opnsense-exporter
  template:
    metadata:
      labels:
        app.kubernetes.io/name: opnsense-exporter
    spec:
      containers:
        - name: opnsense-exporter
          image: ghcr.io/rknightion/opnsense-exporter:latest
          imagePullPolicy: Always
          volumeMounts:
            - name: api-key-vol
              mountPath: /etc/opnsense-exporter/creds
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
          ports:
            - name: metrics-http
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /
              port: metrics-http
          readinessProbe:
            httpGet:
              path: /
              port: metrics-http
          args:
            - "--log.level=info"
            - "--log.format=json"
          env:
            - name: OPNSENSE_EXPORTER_INSTANCE_LABEL
              value: "opnsense"
            - name: OPNSENSE_EXPORTER_OPS_API
              valueFrom:
                secretKeyRef:
                  name: opnsense-exporter-cfg
                  key: host
            - name: OPNSENSE_EXPORTER_OPS_PROTOCOL
              valueFrom:
                secretKeyRef:
                  name: opnsense-exporter-cfg
                  key: protocol
            - name: OPS_API_KEY_FILE
              value: /etc/opnsense-exporter/creds/api-key
            - name: OPS_API_SECRET_FILE
              value: /etc/opnsense-exporter/creds/api-secret
          resources:
            requests:
              memory: 64Mi
              cpu: 100m
            limits:
              memory: 128Mi
              cpu: 500m
      volumes:
        - name: api-key-vol
          secret:
            secretName: opnsense-exporter-cfg
            items:
              - key: key
                path: api-key
              - key: secret
                path: api-secret
---
kind: Service
apiVersion: v1
metadata:
  name: opnsense-exporter
spec:
  selector:
    app.kubernetes.io/name: opnsense-exporter
  type: ClusterIP
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
```

Apply the manifest:

```bash
kubectl apply -f deployment.yaml
```

## Step 3: Configure Prometheus scraping

### Prometheus Operator (ScrapeConfig)

If you are running the Prometheus Operator, create a `ScrapeConfig` resource:

```yaml title="scrape.yaml"
apiVersion: monitoring.coreos.com/v1alpha1
kind: ScrapeConfig
metadata:
  name: opnsense-exporter
  labels:
    # Match the label selector your Prometheus uses for ScrapeConfig discovery
    release: "kube-prom"
spec:
  scrapeInterval: 60s
  scrapeTimeout: 3s
  metricsPath: /metrics
  staticConfigs:
    - labels:
        job: opnsense-exporter
      targets:
        - opnsense-exporter.default.svc:8080
```

### Prometheus Operator (ServiceMonitor)

Alternatively, use a `ServiceMonitor`:

```yaml title="servicemonitor.yaml"
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: opnsense-exporter
  labels:
    release: "kube-prom"
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: opnsense-exporter
  endpoints:
    - port: http
      interval: 30s
      path: /metrics
```

### Static Prometheus config

If you are not using the Prometheus Operator, add a scrape job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: opnsense
    scrape_interval: 30s
    static_configs:
      - targets:
          - opnsense-exporter.default.svc:8080
```

## Verify the deployment

```bash
kubectl run debug --rm -i --tty --restart=Never --image=alpine -- \
  wget --quiet -O- opnsense-exporter.default.svc.cluster.local:8080/metrics | head -20
```

## Security considerations

The deployment manifest follows security best practices:

- **Read-only root filesystem** -- no writable paths in the container
- **Non-root user** -- runs as UID 65534
- **Dropped capabilities** -- all Linux capabilities are dropped
- **No privilege escalation** -- `allowPrivilegeEscalation: false`
- **File-based secrets** -- API credentials are mounted as files, not passed as environment variables

!!! tip "Self-signed certificates"
    If your OPNsense uses a self-signed certificate, add `OPNSENSE_EXPORTER_OPS_INSECURE: "true"` to the env section. For production, consider adding the CA certificate to the container's trust store instead.

## Disabling collectors

Add disable flags to the `args` array in the Deployment:

```yaml
args:
  - "--log.level=info"
  - "--log.format=json"
  - "--exporter.disable-cron-table"
  - "--exporter.disable-arp-table"
```

Or use environment variables:

```yaml
env:
  - name: OPNSENSE_EXPORTER_DISABLE_CRON_TABLE
    value: "true"
```
