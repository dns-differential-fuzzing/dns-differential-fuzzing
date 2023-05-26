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
# --disable-geoip                           support GeoIP2 geolocation ACLs if available
# --disable-linux-caps                      disable Linux capabilities
# --disable-tcp-fastopen                    disable TCP Fast Open support [default=yes]
# --disable-doh
# --enable-auto-validation                  turn on DNSSEC validation by default, using the IANA root key [default=yes]
# --enable-fixed-rrset                      enable fixed rrset ordering [default=no]
# --enable-querytrace                       enable very verbose query trace logging [default=no]
#
# --with-cmocka=detect                      enable CMocka based tests (default is detect)
# --with-jemalloc=detect                    enable jemalloc memory allocator (default is detect)
# --with-json-c                             build with json-c library [yes|no|detect] (default is detect)
# --with-libidn2=PATH                       enable IDN support using GNU libidn2 [yes|no(default)|path]
# --with-libxml2                            build with libxml2 library [yes|no|auto] (default is auto)
# --with-lmdb=[PATH]                        use LMDB library [default=auto], optionally specify the prefix for lmdb library
# --with-maxminddb=PATH                     Build with MaxMind GeoIP2 support (auto|yes|no|path) [default=auto]
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
    --enable-pthread-rwlock \
    --disable-geoip \
    --disable-tcp-fastopen \
    --disable-chroot \
    --disable-linux-caps \
    --disable-querytrace \
    --disable-doh \
    --enable-auto-validation=no \
    --enable-fixed-rrset=yes \
    --with-maxminddb=no \
    --with-pkcs11=no \
    --with-lmdb=no \
    --with-libxml2=no \
    --with-json-c=no \
    --with-zlib=no \
    --with-readline=no \
    --with-libidn2=no \
    --with-cmocka=no \
    --with-jemalloc=no \
    --with-tuning=small \
    --enable-full-report \
    --with-gssapi=no \
    --with-openssl=no

echo "Build ${PROGRAM}"
make -j
echo "Install ${PROGRAM} (/usr/local/)"
make install
