#!/bin/bash

# This script generates an initial keypair for development purposes.

mv -f ./dev/tlskey.p12 ./dev/tlskey.p12.bak
mv -f ./dev/pubCert.crt ./dev/pubCert.crt.bak

# Exporting environment variables for key creation
#
export $(cat .env | grep HOSTNAME)
export $(cat .env | grep HOSTNAME_PF)
export $(cat .env | grep HOSTNAME_AM)
export $(cat .env | grep HOSTNAME_PD)
export $(cat .env | grep HOSTNAME_PLAYGROUND)
export $(cat .env | grep SSL_PWD)

# Create private key
#
keytool -genkey \
  -alias tlskey \
  -keystore dev/tlskey.p12 \
  -storetype PKCS12 \
  -keyalg RSA -storepass ${SSL_PWD} \
  -keypass ${SSL_PWD} \
  -validity 365 \
  -keysize 2048 \
  -dname "CN=${HOSTNAME}" \
  -ext san=dns:${HOSTNAME},dns:${HOSTNAME_PF},dns:${HOSTNAME_PD},dns:${HOSTNAME_AM},dns:${HOSTNAME_PLAYGROUND},dns:localhost

# Export public cert
#
keytool -exportcert \
  -keystore dev/tlskey.p12 \
  -storetype PKCS12 \
  -storepass ${SSL_PWD} \
  -keypass ${SSL_PWD} \
  -alias tlskey \
  -file dev/pubCert.crt \
  -rfc

# Unset all variables
#
unset HOSTNAME
unset HOSTNAME_PF
unset HOSTNAME_AM
unset HOSTNAME_PD
unset HOSTNAME_PLAYGROUND
unset SSL_PWD