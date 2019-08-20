# estafette-letsencrypt-certificate

This small Kubernetes application creates and renews Let's Encrypt SSL certificates in any secret with the correct annotations

[![License](https://img.shields.io/github/license/estafette/estafette-letsencrypt-certificate.svg)](https://github.com/estafette/estafette-letsencrypt-certificate/blob/master/LICENSE)

## Why?

In order to create and renew certificates automatically every 60 days this application decouples that responsibility from any deployments and moves it into the Kubernetes cluster itself.

## Usage

Deploy with Helm:

```
brew install kubernetes-helm
helm init --history-max 25 --upgrade
lint helm chart with helm lint chart/estafette-letsencrypt-certificate
chart helm package chart/estafette-letsencrypt-certificate --version 0.1.0
helm upgrade estafette-letsencrypt-certificate estafette-letsencrypt-certificate-0.1.0.tgz --namespace estafette --install --dry-run --debug --set secret.cloudflare.email=*** --set secret.cloudflare.key=*** --set secret.letsencrypt.json=*** --set secret.letsencrypt.key=***
```

Or deploy without Helm:

```
curl https://raw.githubusercontent.com/estafette/estafette-letsencrypt-certificate/master/kubernetes.yaml -o kubernetes.yaml
export NAMESPACE=estafette
export APP_NAME=estafette-letsencrypt-certificate
export TEAM_NAME=tooling
export VERSION=0.1.0
export GO_PIPELINE_LABEL=1.0.104
export CF_API_EMAIL=***
export CF_API_KEY=***
export ACCOUNT_JSON=***
export ACCOUNT_KEY=***
export CPU_REQUEST=150m
export MEMORY_REQUEST=819Mi
export CPU_LIMIT=350m
export MEMORY_LIMIT=819Mi
cat kubernetes.yaml | envsubst | kubectl apply -n ${NAMESPACE} -f -
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

In the secret an ssl.crt, ssl.pem and ssl.key file will be stored. Mount these in your application (or sidecar container) as follows. Re-applying the secret doesn't overwrite the certificates.

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
