#!/bin/bash

set -eou pipefail

pushd "${PROGRAM}"

echo "Setup environment"
export LANG=C
export LC_LANG=C
export LANGUAGE=C

export CC=cc
export CXX=cxx

echo "Initializing submodules"
git submodule update --init --recursive

echo "Meson: setting up builddir"
# In master but not in 5.5.3
# -Dmalloc=disabled \
meson build_dir \
    --prefix=/usr/local \
    --default-library=static \
    -Dcapng=disabled \
    -Dclient=disabled \
    -Dconfig_tests=disabled \
    -Ddnstap=disabled \
    -Dextra_tests=disabled \
    -Dinstall_root_keys=enabled \
    -Dkres_gen_test=false \
    -Dmanaged_ta=disabled \
    -Dsystemd_files=disabled \
    -Dunit_tests=disabled \
    -Dutils=disabled

echo "Ninja: Compiling"
ninja -C build_dir
ninja install -C build_dir
