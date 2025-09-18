#!/bin/bash
set -e

# Remote target
TARGET="milkv:/home/debian/keystone-examples"

# Paths to files
DRIVER="build-generic64/buildroot.build/build/keystone-driver-36ae4dec0d43a9dc/keystone-driver.ko"
EXAMPLES="
build-generic64/buildroot.build/build/keystone-examples-4adb8e217550b549/hello-native/hello-native.ke
build-generic64/buildroot.build/build/keystone-examples-4adb8e217550b549/attestation/attestor.ke
build-generic64/buildroot.build/build/keystone-examples-4adb8e217550b549/hello-secret/hello-secret.ke
"

echo "[*] Copying driver..."
scp "$DRIVER" "$TARGET"

echo "[*] Copying example enclaves..."
scp $EXAMPLES "$TARGET"

echo "[+] All files copied"
