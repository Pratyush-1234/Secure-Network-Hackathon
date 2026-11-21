# Attacker / benign-client toolbox for the Shield Wall lab.
# Everything runs inside this container, so nothing gets installed on the host.
FROM python:3.13-alpine
RUN apk add --no-cache bash curl jq ffuf nikto perl-json perl-xml-writer perl-net-ssleay perl-io-socket-ssl \
      nmap nmap-scripts openssl bind-tools coreutils \
 && pip install --no-cache-dir sqlmap==1.10.11
WORKDIR /work
CMD ["sleep", "infinity"]
