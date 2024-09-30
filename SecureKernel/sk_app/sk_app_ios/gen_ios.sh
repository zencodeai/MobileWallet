#!/bin/bash

set -e

echo Generate RESTfull client
java -jar ../swagger-codegen-cli.jar generate -l swift5 -i ../openapi.yaml -o ./sk_app/sk_app_swagger_client
