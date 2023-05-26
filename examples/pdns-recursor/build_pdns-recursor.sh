#!/bin/bash

set -eou pipefail

echo "Extract tarball"
tar  --extract --one-top-level="${PROGRAM}" --strip-components=1 --file="${PROGRAM}".tar.bz2
pushd "${PROGRAM}"


echo "Setup environment"
export LANG=C
export LC_LANG=C
export LANGUAGE=C

export CC=cc
export CXX=cxx

# Optional Features:
#   --disable-option-checking  ignore unrecognized --enable/--with options
#   --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
#   --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
#   --enable-silent-rules   less verbose build output (undo: "make V=1")
#   --disable-silent-rules  verbose build output (undo: "make V=0")
#   --enable-dependency-tracking
#                           do not reject slow dependency extractors
#   --disable-dependency-tracking
#                           speeds up one-time build
#   --enable-shared[=PKGS]  build shared libraries [default=yes]
#   --enable-static[=PKGS]  build static libraries [default=yes]
#   --enable-fast-install[=PKGS]
#                           optimize for fast installation [default=yes]
#   --disable-libtool-lock  avoid locking (might break parallel builds)
#   --enable-static-boost   Prefer the static boost libraries over the shared
#                           ones [no]
#   --enable-unit-tests     enable unit test building [default=no]
#   --enable-reproducible   Create reproducible builds. Use this only if you are
#                           a distribution maintainer and need reproducible
#                           builds. If you compile PowerDNS yourself, leave this
#                           disabled, as it might make debugging harder.
#                           [default=no]
#   --enable-verbose-logging
#                           enable verbose logging [default=no]
#   --enable-dns-over-tls   enable DNS over TLS support (requires GnuTLS or
#                           OpenSSL) [default=no]
#   --enable-nod            enable newly observed domains [default=auto]
#   --enable-dnstap         enable dnstap support [default=auto]
#   --disable-hardening     disable compiler security checks [default=no]
#   --enable-asan           enable AddressSanitizer [default=no]
#   --enable-msan           enable MemorySanitizer [default=no]
#   --enable-tsan           enable ThreadSanitizer [default=no]
#   --enable-lsan           enable LeakSanitizer [default=no]
#   --enable-ubsan          enable Undefined Behaviour Sanitizer [default=no]
#   --enable-malloc-trace   enable malloc-trace [default=no]
#   --enable-valgrind       enable Valgrind support [default=no]
#   --enable-systemd        Enable systemd support (default is DISABLED, but
#                           will be enabled when libraries are found)

echo "Configure ${PROGRAM}"
autoreconf -fi
./configure \
    --enable-nod=no \
    --enable-dnstap=no \
    --disable-geoip \
    --disable-tcp-fastopen \
    --disable-chroot \
    --disable-linux-caps \
    --disable-querytrace \
    --disable-doh \
    --disable-systemd \
    --disable-protobuf \
    --disable-ed448 \
    --disable-ed25519 \
    --sysconfdir="/usr/local/etc/pdns/"

echo "Making ${PROGRAM}"
make -j

echo "Install ${PROGRAM} (/usr/local/)"
make install
