#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the D binding. Builds
# libitb.so + the binding via build.sh, then compiles and runs the
# benches/bench_*.d binaries: encryptMessage, encryptStreamPump, and
# encryptStreamOneShot throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh
#   ITB_BENCH_MIN_SEC=1 ./run_bench.sh    # smoke run
#   COMPILER=ldc2 ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench mains
# apply the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to change
# the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

COMPILER="${COMPILER:-ldc2}"
BUILD_DIR="benches/build"
mkdir -p "$BUILD_DIR"

for bench in bench_message bench_stream bench_stream_one_shot; do
    echo "==> compiling $bench"
    # DMD accepts `-inline`; LDC2 inlines under `-O` and rejects the
    # DMD-only flag. Split the two compilers' flag lines.
    case "$COMPILER" in
        ldc2) OPT_FLAGS="-O3 -release" ;;
        *)    OPT_FLAGS="-O -inline -release" ;;
    esac
    "$COMPILER" -w $OPT_FLAGS -I=source -I=benches \
        -of="$BUILD_DIR/$bench" "benches/$bench.d" benches/bench_util.d \
        source/itb/*.d \
        -L-L"$DIST_DIR" -L-litb "-L-rpath=$DIST_DIR"
done

for bench in bench_message bench_stream bench_stream_one_shot; do
    case "$bench" in
        bench_message)          export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"    ;;
        bench_stream)           export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}" ;;
        bench_stream_one_shot)  export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}" ;;
    esac
    echo
    echo "==> running $bench (ITB_BENCH_MIN_SEC=$ITB_BENCH_MIN_SEC)"
    "./$BUILD_DIR/$bench"
done
