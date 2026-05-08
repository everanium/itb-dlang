#!/usr/bin/env bash
#
# build.sh -- one-step build for the D binding: libitb.so + dub build.
# Prerequisites (Go, dmd / ldc2, dub) must be installed separately;
# see README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack, DMD)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   COMPILER=ldc2 ./build.sh
#   COMPILER=gdc  ./build.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

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
echo "==> cleaning previous D-binding build artefacts (dub clean)"
dub clean 2>/dev/null || true
echo "==> building D binding (dub build, compiler=$COMPILER)"
dub build --compiler="$COMPILER"

echo "==> ready: ./run_tests.sh"
