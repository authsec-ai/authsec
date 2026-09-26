# Local Samba AD DC for the inventory adapter tests.
# Debian trixie ships Samba >= 4.21, which has gMSA (service-account) support.
# Credentials in the entrypoint are placeholders. Do not point this image at a
# real directory and do not commit generated keys or certificates.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        samba \
        samba-ad-dc \
        samba-dsdb-modules \
        krb5-user \
        ldap-utils \
        ldb-tools \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 389 636

ENTRYPOINT ["/entrypoint.sh"]
