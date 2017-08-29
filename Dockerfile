FROM scratch

LABEL maintainer="estafette.io" \
      description="The estafette-letsencrypt-certificate component is a Kubernetes controller that retrieves and renews tls certificates from Letsencrypt for annotated Kubernetes secrets"

COPY ca-certificates.crt /etc/ssl/certs/
COPY estafette-letsencrypt-certificate /

ENTRYPOINT ["/estafette-letsencrypt-certificate"]
