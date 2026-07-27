#!/bin/bash

CURVE=secp256r1
DAYS=730

######

DIR=PKI

######

set -e  -u

if [[ $# -lt 1 ]] ; then
    echo "Missing card certificate identifier" 1>&2
    exit 1
fi
if [[ $# -gt 1 ]] ; then
    echo "Too many parameters" 1>&2
    exit 2
fi

if [[ ! -e "$DIR/private/ca.key.pem" ]] ; then
    echo "Missing CA (please execute generate_ca.sh)" 1>&2
    exit 2
fi


NAME="$1"

mkdir -p "$DIR/csr"

openssl ecparam -name "$CURVE" -genkey -check -noout -outform der -out "$DIR/private/$NAME.key.der"

openssl req -config openssl.cnf -new -sha256 -keyform der -key "$DIR/private/$NAME.key.der" -outform pem -out "$DIR/csr/$NAME.csr.pem"

openssl ca -config openssl.cnf -extensions card_cert -days $DAYS -md sha256 -in "$DIR/csr/$NAME.csr.pem" -out "$DIR/certs/$NAME.cert.pem"

openssl x509 -inform pem -in "$DIR/certs/$NAME.cert.pem" -outform der -out "$DIR/certs/$NAME.cert.der"

rm "$DIR/certs/$NAME.cert.pem"

