#!/bin/bash

set -eou pipefail

# Strip the directory name with the version number from the path and replace it with unbound
tar --extract --one-top-level="${PROGRAM}" --strip-components=1 --file="${PROGRAM}".tar.gz
pushd "${PROGRAM}"

echo "Setup environment"
export LANG=C
export LC_LANG=C
export LANGUAGE=C

export CC=cc
export CXX=cxx

echo "Configure ${PROGRAM}"
if [ ! -f VERSION ] ; then
    echo "VERSION=$VERSION" >VERSION
fi
export PREFIX=/usr/local/
export RPM_BUILD_ROOT=$PREFIX
./configure

cat Makefile

echo "Build ${PROGRAM}"
make -j
echo "Install ${PROGRAM} (/usr/local/)"
make install
