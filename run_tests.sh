#!/usr/bin/env bash
#
# run_tests.sh -- Compile and run every D test program under tests/.
#
# Each tests/test_*.d is compiled to its own standalone executable in
# tests/build/, then run in turn. Per-process isolation gives every
# test a fresh libitb global state (profile registry, last-error slot)
# without needing an in-process serial lock. Test binaries are built
# with -unittest and run with --DRT-testmode=run-main so the library
# modules' unittest blocks (e.g. the opts query-encoding checks) run
# first and each test main runs after them.
#
# Compiler:
#   - DMD (default). Override via COMPILER=ldc2 ./run_tests.sh.
#
# Library lookup:
#   - libitb.so is linked from <repo>/dist/linux-amd64/ at compile
#     time; the same directory is baked into the binaries' rpath, so
#     no LD_LIBRARY_PATH is needed at run time.
#
# Usage:
#   ./run_tests.sh                        # build + compile + run all
#   ./run_tests.sh test_smoke             # only the named tests
#   COMPILER=ldc2 ./run_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

COMPILER="${COMPILER:-dmd}"
BUILD_DIR="$SCRIPT_DIR/tests/build"
mkdir -p "$BUILD_DIR"

# Collect test source files. Positional arguments act as a filter;
# otherwise compile every tests/test_*.d.
declare -a TEST_SOURCES=()
if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
        # Allow either "test_smoke" or "tests/test_smoke.d" form.
        local_path="${arg#tests/}"
        local_path="${local_path%.d}"
        TEST_SOURCES+=("tests/${local_path}.d")
    done
else
    while IFS= read -r -d '' f; do
        TEST_SOURCES+=("$f")
    done < <(find tests -maxdepth 1 -name 'test_*.d' -print0 | sort -z)
fi

if [[ ${#TEST_SOURCES[@]} -eq 0 ]]; then
    echo "no tests found under tests/test_*.d" >&2
    exit 0
fi

PASS=0
FAIL=0
FAILED=()

for src in "${TEST_SOURCES[@]}"; do
    name="$(basename "$src" .d)"
    bin="$BUILD_DIR/$name"

    printf "[compile] %-28s" "$name"
    if "$COMPILER" -w -unittest -I=source -of="$bin" "$src" source/itb/*.d \
        -L-L"$DIST_DIR" -L-litb "-L-rpath=$DIST_DIR" >/dev/null; then
        echo " ok"
    else
        echo " COMPILE FAILED"
        FAIL=$((FAIL + 1))
        FAILED+=("$name (compile)")
        continue
    fi

    printf "[run]     %-28s\n" "$name"
    if "$bin" --DRT-testmode=run-main; then
        PASS=$((PASS + 1))
    else
        echo "[FAIL]    $name"
        FAIL=$((FAIL + 1))
        FAILED+=("$name (run)")
    fi
done

echo
echo "==> $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
    printf '    failed: %s\n' "${FAILED[@]}"
    exit 1
fi
