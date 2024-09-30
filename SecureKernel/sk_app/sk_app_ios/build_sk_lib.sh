#!/bin/bash

set -e

POT_HOME=$HOME/Workspace/MobileWallet
SK_IOS_APP_HOME=$POT_HOME/SecureKernel/sk_app/sk_app_ios
SK_IOS_HOME=$SK_IOS_APP_HOME/sk_app/sk

# Build sk using script from https://github.com/leetal/ios-cmake

cd $SK_IOS_HOME
rm -rf ./build ./lib
/usr/bin/env cmake . -B build -G Xcode -DCMAKE_TOOLCHAIN_FILE=$SK_IOS_APP_HOME/ios.toolchain.cmake -DPLATFORM=OS64COMBINED -DSHARED=false
/usr/bin/env cmake --build build --config Release
/usr/bin/env cmake --install build --config Release
