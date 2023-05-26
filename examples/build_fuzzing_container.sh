#!/usr/bin/bash

set -euo pipefail
SCRIPTPATH=$(dirname "$(realpath "$0")")
pushd "$SCRIPTPATH"

PODMAN=podman
if ! command -v ${PODMAN} &> /dev/null; then
    if command -v docker &> /dev/null; then
        PODMAN=docker
    else
        echo "Neither podman nor docker are installed. Please install one of them."
        exit 1
    fi
fi

declare -a BUILD_ARGS=()

while [[ $# -ge 1 ]]; do
    case $1 in
        # -h|-\?|--help)
        #     show_help    # Display a usage synopsis.
        #     exit
        #     ;;
        -d|--debug)
            echo "Install debug tools"
            BUILD_ARGS+=("--build-arg=INSTALL_DEBUG_TOOLS=true")
            ;;
        -?*)
            printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
            ;;
        *)               # Default case: No more options, so break out of the loop.
            break
    esac

    shift
done

# Build fuzzing binary artifacts and copy them to the tools folder for the container image
cargo build --release --package coverage
cargo build --release --package dnsauth --bin dnsauth --features app
cp ../target/release/libcoverage.{a,so} ../target/release/dnsauth ./tools/

{
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./bind9/Dockerfile.bind9 -t bind9 .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./bind9_11/Dockerfile.bind9 -t bind9_11 .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./unbound/Dockerfile.unbound -t unbound .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./maradns/Dockerfile.maradns -t maradns .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./pdns-recursor/Dockerfile.powerdns -t pdns-recursor .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./knot-resolver/Dockerfile.knot-resolver -t knot-resolver .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./trust-dns/Dockerfile.trust-dns -t trust-dns .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" -f ./resolved/Dockerfile.resolved -t resolved .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./bind9/Dockerfile.bind9 -t bind9-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./bind9_11/Dockerfile.bind9 -t bind9_11-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./unbound/Dockerfile.unbound -t unbound-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./maradns/Dockerfile.maradns -t maradns-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./pdns-recursor/Dockerfile.powerdns -t pdns-recursor-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./knot-resolver/Dockerfile.knot-resolver -t knot-resolver-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./trust-dns/Dockerfile.trust-dns -t trust-dns-debug .
echo "${PODMAN}" build --jobs=0 "${BUILD_ARGS[@]}" --build-arg=INSTALL_DEBUG_TOOLS=true -f ./resolved/Dockerfile.resolved -t resolved-debug .
} | parallel --eta --bar --progress -j3
