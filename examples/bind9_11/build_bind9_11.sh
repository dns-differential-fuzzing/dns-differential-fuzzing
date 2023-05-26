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
autoreconf -fi

# --enable-static[=PKGS]                    build static libraries [default=no]
# --enable-shared[=PKGS]                    build shared libraries [default=yes]
# --enable-developer                        enable developer build settings
#                                           => REQUIRED for static build
#
# --disable-chroot                          disable chroot
# --disable-linux-caps                      disable Linux capabilities
# --enable-fixed-rrset                      enable fixed rrset ordering [default=no]
# --enable-querytrace                       enable very verbose query trace logging [default=no]
#
# --with-libxml2                            build with libxml2 library [yes|no|auto] (default is auto)
# --with-lmdb=[PATH]                        use LMDB library [default=auto], optionally specify the prefix for lmdb library
# --with-pkcs11=PATH                        Build with PKCS11 support [no|path] (PATH is for the PKCS11 provider)
# --with-readline=yes|no|libedit|readline   specify readline library [default auto]
# --with-zlib                               build with zlib for HTTP compression [default=yes]
# --with-tuning=small                       Specify server tuning (default or small)
# --enable-full-report                      report values of all configure options
# --with-gssapi=[PATH|[/path/]krb5-config]  Specify path for system-supplied GSSAPI [default=yes]
# --with-openssl=PATH                       Build with OpenSSL yes|no|path. (Crypto is required for DNSSEC)

    # --disable-maintainer-mode \
    # --enable-shared=no \
    # --enable-developer \
./configure \
    --disable-chroot \
    --disable-linux-caps \
    --disable-querytrace \
    --enable-fixed-rrset=yes \
    --with-pkcs11=no \
    --with-lmdb=no \
    --with-libxml2=no \
    --with-zlib=no \
    --with-readline=no \
    --enable-full-report \
    --with-gssapi=no \
    --with-openssl=no \
    --with-libjson=no \
    --with-tuning=default

echo "Build ${PROGRAM}"
make -j
echo "Install ${PROGRAM} (/usr/local/)"
make install
