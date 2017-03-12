FROM scratch

MAINTAINER estafette.io

COPY ca-certificates.crt /etc/ssl/certs/
COPY estafette-letsencrypt-certificate /

ENTRYPOINT ["/estafette-letsencrypt-certificate"]
