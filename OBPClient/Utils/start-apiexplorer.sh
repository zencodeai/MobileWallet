#!/bin/bash

APIEXPL_HOME=$HOME/Workspace/OpenBankProject/API-Explorer

cd $APIEXPL_HOME && mvn -Djetty.port=8082 jetty:run

