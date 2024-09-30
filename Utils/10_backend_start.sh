#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Start backend
cd $BACKEND_APP_HOME
. ./.venv/bin/activate
python -m uvicorn main:app --reload
deactivate
