#!/usr/bin/env bash
#
# build.sh -- one-step build for the D binding: libitb.so + dub build
# of the binding library + the eitb CLI. Prerequisites (Go, dmd /
# ldc2, dub) must be installed separately; see README.md
# "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack, DMD)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   COMPILER=ldc2 ./build.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/dlang"
COMPILER="${COMPILER:-dmd}"
echo "==> building D binding library (dub build, compiler=$COMPILER)"
dub build --compiler="$COMPILER"

echo "==> building eitb CLI"
"$COMPILER" -w -O -inline -I=source -of=eitb/eitb \
    eitb/source/eitb.d source/itb/*.d \
    -L-L"$DIST_DIR" -L-litb "-L-rpath=$DIST_DIR"

echo "==> ready: ./run_tests.sh"
