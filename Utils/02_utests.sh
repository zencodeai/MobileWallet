#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Test build
cd $SK_HOME/build
ctest
