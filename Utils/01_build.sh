#!/bin/bash

set -e

# -----------------------------------------------------------------------------
# Common definitions
common_dir="$(dirname "$0")"
source "$common_dir/common.sh"

# -----------------------------------------------------------------------------
echo -- Setup venv
cd $DEMOS_HOME
rm -rf ./.venv
python3 -m venv ./.venv

# -----------------------------------------------------------------------------
echo -- Activate venv
. ./.venv/bin/activate

# -----------------------------------------------------------------------------
echo -- Install mbedtls requirements
pip install --upgrade pip
cd $SK_HOME
pip install -r $MBEDTLS_HOME/scripts/basic.requirements.txt

# -----------------------------------------------------------------------------
echo -- Generate mbedtls configuration independent files, required on desktop
pushd ./
cd $MBEDTLS_HOME
tests/scripts/check-generated-files.sh -u
popd

# -----------------------------------------------------------------------------
echo -- Generate secure kernel definitions
cd $SK_HOME
python utils/sk_definitions.py

# -----------------------------------------------------------------------------
echo -- Prepare build
cmake --no-warn-unused-cli -DCMAKE_BUILD_TYPE:STRING=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/gcc -DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/g++ -S$SK_HOME -B$SK_HOME/build -G Ninja

# -----------------------------------------------------------------------------
echo -- Build
cmake --build $SK_HOME/build --config Debug --target all
