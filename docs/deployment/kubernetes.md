---
title: Kubernetes
description: Deploy opnsense2otel on Kubernetes with secrets, Deployment manifests, and Prometheus Operator scrape configuration
tags:
  - Deployment
  - Kubernetes
---

# Kubernetes Deployment

Deploy opnsense2otel in a Kubernetes cluster with file-based secrets and Prometheus integration.

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
kubectl create secret generic opnsense2otel-cfg \
  --from-env-file=opnsense_apikey.txt
```

## Step 2: Deploy the exporter

The following manifest creates a Deployment and a ClusterIP Service. API credentials are mounted as files from the Secret, and connection settings are injected as environment variables.

<!-- docgen:begin:kubernetes-deployment -->
```yaml title="deployment.yaml"
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: opnsense2otel
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: opnsense2otel
  template:
    metadata:
      labels:
        app.kubernetes.io/name: opnsense2otel
    spec:
      # The exporter is a pure HTTP scrape target and never calls the Kubernetes API,
      # so don't mount a ServiceAccount token (shrinks the pivot surface on compromise).
      automountServiceAccountToken: false
      containers:
        - name: opnsense2otel
          # Pin to an immutable release tag, not :latest — :latest is retagged every
          # release, so a pod reschedule could silently pull a breaking version with no
          # deploy event to correlate. The tag tracks version.txt and is rewritten on
          # each release by release-please via the x-release-please-version marker below;
          # keep that marker on the image line or the tag stops updating. Published tags
          # carry no leading "v" (the git tag is v2.2.1, the image tag is 2.2.1).
          image: ghcr.io/rknightion/opnsense2otel:4.1.0 # x-release-please-version
          imagePullPolicy: IfNotPresent
          # In pod, mount OPNSense API credentials as files
          volumeMounts:
            # name must match the volume name below
            - name: api-key-vol
              mountPath: /etc/opnsense2otel/creds
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            seccompProfile:
              type: RuntimeDefault
          ports:
            # Default value for --web.listen-address= is 8080
            - name: metrics-http
              containerPort: 8080
            # The syslog receiver (--logs.syslog.enabled), off by default. Both
            # protocols are declared because OPNsense can be configured to send over
            # either; the exporter listens on both by default. Port 5514, not 514:
            # 514 is privileged and this container runs as a non-root user.
            - name: syslog-udp
              containerPort: 5514
              protocol: UDP
            - name: syslog-tcp
              containerPort: 5514
              protocol: TCP
          # /-/healthy: process liveness only — no firewall dependency. Do NOT
          # point readinessProbe at /-/ready here: when Prometheus scrapes via
          # Service endpoints, a not-ready pod stops being scraped and the
          # opnsense_up=0 signal is lost exactly when the firewall is down.
          livenessProbe:
            httpGet:
              path: /-/healthy
              port: metrics-http
          readinessProbe:
            httpGet:
              path: /-/healthy
              port: metrics-http
          # See main readme; some configuration options can be set via env-vars
          ##
          args:
            - "--log.level=info"
            - "--log.format=json"
          env:
            - name: OPN2OTEL_INSTANCE_LABEL
              value: "opnsense"
            - name: OPN2OTEL_OPS_API
              valueFrom:
                secretKeyRef:
                  name: opnsense2otel-cfg
                  key: host
            - name: OPN2OTEL_OPS_PROTOCOL
              valueFrom:
                secretKeyRef:
                  name: opnsense2otel-cfg
                  key: protocol
            # Env var points to a location on disk, make sure the value set here matches the volumeMount path
            - name: OPS_API_KEY_FILE
              value: /etc/opnsense2otel/creds/api-key
            - name: OPS_API_SECRET_FILE
              value: /etc/opnsense2otel/creds/api-secret
            # Only enable if using self-signed cert
            # - name: OPN2OTEL_OPS_INSECURE
            #   value: "true"

          # in basic testing with a home lab OPNsense 100m CPU and 64Mi memory are sufficient
          # however if your opnsense instance has a large number of rules, interfaces, etc...
          # you may need to adjust these values
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
            secretName: opnsense2otel-cfg
            items:
              - key: key
                path: api-key
              - key: secret
                path: api-secret
---
kind: Service
apiVersion: v1
metadata:
  name: opnsense2otel
spec:
  selector:
    app.kubernetes.io/name: opnsense2otel
  type: ClusterIP
  ports:
    - name: http
      protocol: TCP
      port: 8080
      targetPort: 8080
    # Syslog receiver (--logs.syslog.enabled), off by default. A ClusterIP is only
    # reachable from inside the cluster, so the firewall cannot push to it as-is:
    # to use the receiver, expose these via a LoadBalancer/NodePort Service (or set
    # `type: LoadBalancer` here) and point the OPNsense logging target at that
    # address. See docs/syslog-receiver.md.
    - name: syslog-udp
      protocol: UDP
      port: 5514
      targetPort: 5514
    - name: syslog-tcp
      protocol: TCP
      port: 5514
      targetPort: 5514
```
<!-- docgen:end:kubernetes-deployment -->

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
  name: opnsense2otel
  labels:
    # Match the label selector your Prometheus uses for ScrapeConfig discovery
    release: "kube-prom"
spec:
  scrapeInterval: 60s
  # This bounds only the HTTP snapshot replay. OPNsense API polling runs in the
  # background under its own poll intervals and request timeouts, so scrapeTimeout
  # no longer controls collector fan-out.
  scrapeTimeout: 30s
  metricsPath: /metrics
  staticConfigs:
    - labels:
        job: opnsense2otel
      targets:
        - opnsense2otel.default.svc:8080
```

### Prometheus Operator (ServiceMonitor)

Alternatively, use a `ServiceMonitor`:

```yaml title="servicemonitor.yaml"
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: opnsense2otel
  labels:
    release: "kube-prom"
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: opnsense2otel
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
          - opnsense2otel.default.svc:8080
```

## Verify the deployment

```bash
kubectl run debug --rm -i --tty --restart=Never --image=alpine - \
  wget --quiet -O- opnsense2otel.default.svc.cluster.local:8080/metrics | head -20
```

## Security considerations

The deployment manifest is hardened:

- **Read-only root filesystem** - no writable paths in the container
- **Non-root user** - runs as UID 65532
- **Dropped capabilities** - all Linux capabilities are dropped
- **No privilege escalation** - `allowPrivilegeEscalation: false`
- **File-based secrets** - API credentials are mounted as files, not passed as environment variables

!!! tip "Self-signed certificates"
    If your OPNsense uses a self-signed certificate, add `OPN2OTEL_OPS_INSECURE: "true"` to the env section. For production, add the CA certificate to the container's trust store instead.

## Restrict access with a NetworkPolicy

The `/metrics` endpoint requires no authentication by default, so restrict which pods can reach it. A sample manifest is provided at [`deploy/k8s/networkpolicy.yaml`](https://github.com/rknightion/opnsense2otel/blob/main/deploy/k8s/networkpolicy.yaml):

```yaml title="networkpolicy.yaml"
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: opnsense2otel
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: opnsense2otel
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              # Placeholder: the namespace your monitoring stack runs in
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              # Placeholder: the labels on your Prometheus pods
              app.kubernetes.io/name: prometheus
      ports:
        - protocol: TCP
          port: 8080
```

Adjust the `namespaceSelector` and `podSelector` placeholders to match where your Prometheus runs, then apply:

```bash
kubectl apply -f networkpolicy.yaml
```

!!! note
    NetworkPolicy is only enforced if your cluster's CNI supports it (Calico, Cilium, and similar). On clusters without a policy-capable CNI the manifest is accepted but has no effect.

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
  - name: OPN2OTEL_DISABLE_CRON_TABLE
    value: "true"
```
