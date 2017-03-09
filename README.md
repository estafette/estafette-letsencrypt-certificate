# estafette-letsencrypt-certificate

This small Kubernetes application creates and renews Let's Encrypt SSL certificates in any secret with the correct annotations

[![License](https://img.shields.io/github/license/estafette/estafette-letsencrypt-certificate.svg)](https://github.com/estafette/estafette-letsencrypt-certificate/blob/master/LICENSE)

## Why?

In order to create and renew certificates automatically every 60 days this application decouples that responsibility from any deployments and moves it into the Kubernetes cluster itself.

## Usage

First deploy this application to your Kubernetes cluster using the following manifest.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: estafette
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: estafette-letsencrypt-certificate
  namespace: estafette
  labels:
    app: estafette-letsencrypt-certificate
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: estafette-letsencrypt-certificate
  template:
    metadata:
      labels:
        app: estafette-letsencrypt-certificate
    spec:
      containers:
      - name: estafette-letsencrypt-certificate
        image: estafette/estafette-letsencrypt-certificate:latest
        env:
        - name: "CF_API_EMAIL"
          value: "myemail@mydomain.com"
        - name: "CF_API_KEY"
          value: "****"
        resources:
          requests:
            cpu: 10m
            memory: 16Mi
          limits:
            cpu: 50m
            memory: 128Mi
        livenessProbe:
          httpGet:
            path: /metrics
            port: 9101
          initialDelaySeconds: 30
          timeoutSeconds: 1
```

Once it's running put the following annotations on a secret and deploy. The estafette-letsencrypt-certificate application will watch changes to secrets and process those. Once approximately every 300 seconds it also scans all secrets as a safety net.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: myapplication-letsencrypt-certificate
  namespace: mynamespace
  labels:
    app: myapplication
  annotations:
    estafette.io/letsencrypt-certificate: "true"
    estafette.io/letsencrypt-certificate-hostnames: "mynamespace.mydomain.com"
type: Opaque
```

In the secret a ssl.crt, ssl.pem and ssl.key file will be stored. Mount these in your application (or sidecar container) as follows.

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: myapplication
  namespace: mynamespace
  labels:
    app: myapplication
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapplication
  template:
    metadata:
      labels:
        app: myapplication
    spec:
      containers:
      - name: myapplication
        image: nginx
        ports:
        - name: http
          containerPort: 80
        - name: https
          containerPort: 443
        volumeMounts:
        - name: ssl-certificate
          mountPath: /etc/nginx/ssl
      volumes:
      - name: ssl-certificate
        secret:
          secretName: myapplication-letsencrypt-certificate
          items:
            - key: ssl.crt
              path: nginx.crt
            - key: ssl.pem
              path: nginx.pem
            - key: ssl.key
              path: nginx.key
```