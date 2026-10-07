#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the D binding:
# rebuilds the utility when a source is newer than the binary (a
# no-op otherwise; libitb3.so and the binding library are assumed
# built by build.sh) and execs it with every argument passed through.
#
# The build output is captured rather than discarded: the compiler
# reports on stderr, and a redirect of stdout alone would let its
# lines join the utility's own output. Nothing is printed unless the
# build fails, in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both
#   COMPILER=ldc2 ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

REPO_ROOT="$(cd ../.. && pwd -P)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"
COMPILER="${COMPILER:-dmd}"

stale=0
if [ ! -x loop/loop ]; then
    stale=1
else
    for src in loop/*.d source/itb3/*.d; do
        if [ "$src" -nt loop/loop ]; then
            stale=1
            break
        fi
    done
fi

if [ "$stale" = 1 ]; then
    if ! build_output="$("$COMPILER" -w -O -inline -I=. -I=source -of=loop/loop \
        loop/*.d source/itb3/*.d \
        -L-L"$DIST_DIR" -L-litb3 "-L-rpath=$DIST_DIR" 2>&1)"; then
        printf '%s\n' "$build_output" >&2
        exit 1
    fi
fi

exec ./loop/loop "$@"
