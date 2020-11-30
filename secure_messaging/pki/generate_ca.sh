#!/bin/bash

CURVE=secp521r1
DAYS=1825

######

DIR=PKI

######

set -e -u

if [[ -e "$DIR/private/ca.key.pem" ]] ; then
    echo "CA already exists, please remove it manually if you want to generate a new one" 1>&2
    exit 2
fi

mkdir -p "$DIR/private" "$DIR/certs"

openssl ecparam -name "$CURVE" -genkey -check -noout -outform pem -out "$DIR/private/ca.key.pem"

openssl req -config openssl.cnf -extensions v3_ca -days $DAYS -new -x509 -sha256 -keyform pem -key "$DIR/private/ca.key.pem" -outform pem -out "$DIR/certs/ca.cert.pem"

touch $DIR/index.txt

echo 1000 > $DIR/serial

echo 1000 > $DIR/crlnumber
