#!/bin/bash

set -e
set -o pipefail

# Initialize and update git submodules
git submodule update --init --recursive

pushd deps > /dev/null

# Patch submodule deps
# For every patch file in deps/patches, apply it to the corresponding submodule
for patch_file in patches/*.patch; do
    # Extract submodule name from patch file name
    patch_filename=$(basename "$patch_file")
    submodule_name="${patch_filename%_dep.patch}"
    echo "Applying patch $patch_file to submodule $submodule_name"
    # Change to submodule directory
    pushd "$submodule_name" > /dev/null
    # Apply the patch
    git apply "../$patch_file"
    # Return to original directory
    popd > /dev/null
done

popd > /dev/null


