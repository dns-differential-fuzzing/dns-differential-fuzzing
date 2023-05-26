#!/bin/bash

set -eou pipefail

# Strip the directory name with the version number from the path and replace it with "${PROGRAM}"
tar --extract --one-top-level="${PROGRAM}" --strip-components=1 --file="${PROGRAM}".tar.gz
pushd "${PROGRAM}"

echo "Setup environment"
export LANG=C
export LC_LANG=C
export LANGUAGE=C

export CC=cc
export CXX=cxx

echo "Configure ${PROGRAM}"
# --enable-pie          Enable Position-Independent Executable (eg. to fully benefit from ASLR, small performance penalty)
# --enable-static-exe   enable to compile executables statically against (event) uninstalled libs, for debug purposes
# --enable-fully-static enable to compile fully static
# --disable-shared      build shared libraries [default=yes]

./configure \
    --enable-pie \
    --enable-fully-static \
    --disable-shared

echo "Build ${PROGRAM}"
make -j
echo "Install ${PROGRAM} (/usr/local/)"
make install
