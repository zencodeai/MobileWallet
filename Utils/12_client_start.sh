#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Start client
cd $WRAPPER_HOME
. ./.venv/bin/activate
python sk_main.py
deactivate
