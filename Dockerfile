FROM scratch

COPY ca-certificates.crt /etc/ssl/certs/
COPY estafette-letsencrypt-certificate /

CMD ["/estafette-letsencrypt-certificate"]