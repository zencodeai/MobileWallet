#!/bin/bash

# Dump DER encoded certificate information using openssl
# Usage: dumpcert.sh <certfile>
openssl x509 -inform der -in $1 -text -noout
