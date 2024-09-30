#!/bin/bash

OBPAPI_HOME=$HOME/Workspace/OpenBankProject/OBP-API

export MAVEN_OPTS="-Xss128m" && cd $OBPAPI_HOME && mvn install -pl .,obp-commons && mvn jetty:run -pl obp-api
