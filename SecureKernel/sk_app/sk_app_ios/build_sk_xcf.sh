#!/bin/bash

set -e

POT_HOME=$HOME/Workspace/MobileWallet
SK_IOS_APP_HOME=$POT_HOME/SecureKernel/sk_app/sk_app_ios
SK_IOS_HOME=$SK_IOS_APP_HOME/sk_app/sk
SK_IOS_LIB_HOME=$SK_IOS_APP_HOME/sk_app/sk_lib

# Clean up
rm -rf $SK_IOS_APP_HOME/output

# build iOS archive
cd $SK_IOS_LIB_HOME
/usr/bin/env xcodebuild archive \
-scheme sk_lib \
-destination "generic/platform=iOS" \
-archivePath $SK_IOS_APP_HOME/output/sk_lib \
SKIP_INSTALL=NO \
BUILD_LIBRARY_FOR_DISTRIBUTION=YES

# build iOS simulator archive
cd $SK_IOS_LIB_HOME
/usr/bin/env xcodebuild archive \
-scheme sk_lib \
-destination "generic/platform=iOS Simulator" \
-archivePath $SK_IOS_APP_HOME/output/sk_lib-Sim \
SKIP_INSTALL=NO \
BUILD_LIBRARY_FOR_DISTRIBUTION=YES

# build iOS framework
cd $SK_IOS_APP_HOME/output
/usr/bin/env xcodebuild -create-xcframework \
-framework ./sk_lib.xcarchive/Products/Library/Frameworks/sk_lib.framework \
-framework ./sk_lib-Sim.xcarchive/Products/Library/Frameworks/sk_lib.framework \
-output ./sk_lib.xcframework
