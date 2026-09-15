#!/usr/bin/env bash
#
# build.sh -- one-step build for the D binding: libitb3.so + dub build
# of the binding library + the eitb CLI. Prerequisites (Go, dmd /
# ldc2, dub) must be installed separately; see README.md
# "Prerequisites" section.
#
# Every artefact this binding owns is removed first, so nothing the
# build produces can be a leftover from an earlier invocation.
#
# Usage:
#   ./build.sh             # default build (full asm stack, DMD)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#   COMPILER=ldc2 ./build.sh
#   ITB_SKIP_CLEAN=1 ./build.sh   # keep existing artefacts

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# ---- Clean ----------------------------------------------------------
# Artefacts this binding owns. The Go shared library under
# dist/linux-amd64/ is shared by every binding and stays untouched.
# eitb/eitb is a compiled binary here (the tracked launcher shells
# that some other bindings ship do not exist in this tree), and the
# compiler drops its object file beside it, hence the glob.
CLEAN_TARGETS=(
    .dub                  # per-package dub state
    lib                   # dub targetPath: libitb3_d.a
    tests/build           # per-test binaries + objects
    benches/build         # bench binaries + objects
    bench/bin             # bench binaries
    bench/results         # bench output
    eitb/bin              # eitb output directory
    eitb/eitb             # eitb CLI
    __test__library__     # dub test runner binary
    itb-binding
    itb-test-runner
    itb-bench
    itb-bench-single
    itb-bench-triple
)
CLEAN_GLOBS=(
    'eitb/*.o'            # compiler object dropped beside the CLI
)

clean_artefacts() {
    local rel abs tracked pat match

    # Expand the globs into the literal list so every match passes the
    # same validation as a hand-written entry.
    shopt -s nullglob
    for pat in "${CLEAN_GLOBS[@]}"; do
        for match in $pat; do
            CLEAN_TARGETS+=("$match")
        done
    done
    shopt -u nullglob

    # A build artefact is never tracked, so a hit here means the list
    # above is wrong. Abort rather than delete a source file.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tracked="$(git ls-files -- "${CLEAN_TARGETS[@]}")"
        if [ -n "$tracked" ]; then
            echo "clean: tracked files inside the clean scope:" >&2
            printf '%s\n' "$tracked" | sed 's/^/    /' >&2
            exit 1
        fi
    fi

    for rel in "${CLEAN_TARGETS[@]}"; do
        abs="$(readlink -m -- "$SCRIPT_DIR/$rel")"
        case "$abs" in
            "$SCRIPT_DIR"/?*) ;;
            *) echo "clean: '$rel' escapes $SCRIPT_DIR ($abs)" >&2; exit 1;;
        esac
        [ -e "$abs" ] || continue
        echo "[clean] rm -rf $abs"
        rm -rf -- "$abs"
    done
}

DUB_FORCE=(--force)
if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing artefacts"
    DUB_FORCE=()
else
    echo "==> cleaning previous artefacts"
    clean_artefacts
fi

cd "$REPO_ROOT"
echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared

cd "$REPO_ROOT/bindings/dlang"
COMPILER="${COMPILER:-dmd}"
echo "==> building D binding library (dub build, compiler=$COMPILER)"
# --force bypasses dub's up-to-date check. Without it dub restores the
# target from its user-global cache under ~/.dub/cache/, so the wipe
# above would be followed by a copy of an older artefact. Under
# ITB_SKIP_CLEAN=1 the flag is dropped so iteration stays incremental.
dub build --compiler="$COMPILER" "${DUB_FORCE[@]}"

echo "==> building eitb CLI"
"$COMPILER" -w -O -inline -I=source -of=eitb/eitb \
    eitb/source/eitb.d source/itb3/*.d \
    -L-L"$DIST_DIR" -L-litb3 "-L-rpath=$DIST_DIR"

echo "==> ready: ./run_tests.sh"
