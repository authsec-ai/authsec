#!/bin/bash
# Seeds a throwaway Samba AD and serves LDAP/LDAPS in the foreground.
# Every password is a local placeholder. The TLS CA is generated at start and
# is not committed.
set -euo pipefail

REALM="AUTHSEC.TEST"
DOMAIN="AUTHSEC"
ADMIN_PASS="CANARY-SECRET-DO-NOT-LEAK-1"
BASE="DC=authsec,DC=test"
SAM="/var/lib/samba/private/sam.ldb"
TLS_DIR="/var/lib/samba/private/tls"

if [ ! -f "$SAM" ]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="$ADMIN_PASS" \
        --host-name=dc \
        --use-rfc2307
fi

samba-tool domain passwordsettings set --complexity=off --min-pwd-length=8 || true

mkdir -p "$TLS_DIR"
if [ ! -f "$TLS_DIR/ca.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.pem" -days 365 \
        -subj "/CN=AuthSec Test CA"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/dc.key" -out /tmp/dc.csr \
        -subj "/CN=dc.authsec.test"
    openssl x509 -req -in /tmp/dc.csr \
        -CA "$TLS_DIR/ca.pem" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
        -out "$TLS_DIR/dc.pem" -days 365 \
        -extfile <(printf "subjectAltName=DNS:dc.authsec.test,DNS:localhost,IP:127.0.0.1\n")
    chmod 0600 "$TLS_DIR/ca.key" "$TLS_DIR/dc.key"
fi

# Point Samba at the generated certificate. Append only once.
if ! grep -q "tls keyfile" /etc/samba/smb.conf; then
    cat >> /etc/samba/smb.conf <<EOF

    tls enabled = yes
    tls keyfile = $TLS_DIR/dc.key
    tls certfile = $TLS_DIR/dc.pem
    tls cafile = $TLS_DIR/ca.pem
EOF
fi

create_user() {
    local name="$1" pass="$2"
    shift 2
    if ! samba-tool user show "$name" >/dev/null 2>&1; then
        samba-tool user create "$name" "$pass" "$@"
    fi
}

create_user alice "CANARY-SECRET-DO-NOT-LEAK-2" --given-name=Alice --surname=Example --mail-address=alice@authsec.test || true
create_user nomail "CANARY-SECRET-DO-NOT-LEAK-3" --given-name=No --surname=Mail || true
create_user disabled "CANARY-SECRET-DO-NOT-LEAK-4" --given-name=Disabled --surname=User || true
samba-tool user disable disabled || true
create_user locked "CANARY-SECRET-DO-NOT-LEAK-5" --given-name=Locked --surname=User || true

# Expired account plus a lockoutTime. The lockout bit on userAccountControl is
# computed; lockoutTime is what a reader observes as a locked account.
ldbmodify -H "$SAM" <<EOF || true
dn: CN=locked,CN=Users,$BASE
changetype: modify
replace: accountExpires
accountExpires: 1
-
replace: lockoutTime
lockoutTime: 133000000000000000
EOF

samba-tool group add parentgrp || true
samba-tool group add childgrp || true
samba-tool group addmembers parentgrp childgrp || true
samba-tool group addmembers childgrp alice || true
samba-tool computer create ws01 || true
samba-tool spn add HTTP/invoice.authsec.test alice || true

if samba-tool service-account create --help >/dev/null 2>&1; then
    samba-tool service-account create gmsa-invoice --dns-host-name=gmsa.authsec.test || true
elif samba-tool service-account --help >/dev/null 2>&1; then
    samba-tool service-account create gmsa-invoice || true
fi

# sMSA is optional. A schema that lacks the class must not fail the container.
ldbadd -H "$SAM" <<EOF || echo "sMSA seed skipped (class unavailable)"
dn: CN=smsa-invoice,CN=Managed Service Accounts,$BASE
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-ManagedServiceAccount
sAMAccountName: smsa-invoice$
userAccountControl: 4096
EOF

samba -i -M single &
samba_pid=$!

ready=0
for _ in $(seq 1 90); do
    if ldapsearch -x -H ldap://127.0.0.1 -D "Administrator@${REALM}" -w "$ADMIN_PASS" \
        -b "$BASE" -s base dn >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 2
done

if [ "$ready" -ne 1 ]; then
    echo "AD did not become ready" >&2
    kill "$samba_pid" || true
    exit 1
fi

echo "AUTHSEC_AD_READY"
wait "$samba_pid"
