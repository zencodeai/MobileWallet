#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Start admin tool
cd $BACKEND_ADMIN_HOME
. ./.venv/bin/activate
python main.py
deactivate
