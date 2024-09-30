#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Setup wrapper environment
pushd ./
cd $WRAPPER_HOME
python3 -m venv ./.venv
. ./.venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
popd

# -----------------------------------------------------------------------------
echo -- Setup admin environment
pushd ./
cd $BACKEND_ADMIN_HOME
python3 -m venv ./.venv
. ./.venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
popd

# -----------------------------------------------------------------------------
echo -- Setup backend environment
pushd ./
cd $BACKEND_APP_HOME
python3 -m venv ./.venv
. ./.venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cp -v $WRAPPER_HOME/sk_definitions.json ./data/
popd
