#!/bin/bash

sudo keytool \
    -importcert \
    -noprompt \
    -keystore $JAVA_HOME/lib/security/cacerts \
    -storepass changeit \
    -alias entrust_ov_tls_issuing_rsa_ca_2 \
    -file "certs_to_trust/Entrust OV TLS Issuing RSA CA 2.crt" \
    -trustcacerts
