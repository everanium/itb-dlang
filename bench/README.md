# ITB D Binding - Easy Mode Benchmark

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Two executables (`itb-bench-single`, `itb-bench-triple`) cover the
Easy Mode encryption / decryption surface exposed by the D binding
through two `void main()` entry points driven by one shared
`bench.common` module:

* `bench_single.d` - Single Ouroboros (mode = 1, 3 seeds + optional
  dedicated lockSeed). Walks the nine PRF-grade primitives plus one
  mixed-primitive variant.
* `bench_triple.d` - Triple Ouroboros (mode = 3, 7 seeds + optional
  dedicated lockSeed). Same nine + one mixed grid as the Single
  binary.

Both binaries pin **1024-bit ITB key width** and **16 MiB
non-deterministic-fill payload**, run four ops per case
(`encrypt`, `decrypt`, `encryptAuth`, `decryptAuth`), and emit a
Go-bench-style line per case (`name iters ns/op MB/s`).

The harness is a custom Go-bench-style runner in `source/common.d`
(no third-party bench framework - `std.datetime.stopwatch.StopWatch`
and an inline xorshift64* LCG cover the timing and random-fill
surfaces). One `dub build` invocation per sub-package drives the
whole compile.

## Prerequisites

Build the shared library and confirm the D toolchain (see the
binding [README](../README.md)):

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/dlang
dmd --version  # or ldc2 --version / gdc --version
```

A project-private opt-out tag is available when the 4-lane
chain-absorb wrapper is dead weight (hosts without AVX-512+VL).
The tag disables only the chain-absorb asm; upstream stdlib asm
stays engaged so the per-pixel single Func runs at upstream-asm
speed via `process_cgo`'s nil-`BatchHash` fallback:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The D binding loads `libitb.so` / `.dll` / `.dylib` at link time
through the `-litb` linker option declared by the bench
`dub.json`'s `lflags-posix-*` blocks and resolves it at run time
via the `-rpath=$ORIGIN/../../../../dist/linux-amd64` baked into
the binary; see `bench/dub.json` for the per-compiler lflags
specifics.

## Run

From the binding root (`bindings/dlang/`):

```bash
dub build :single --compiler=dmd --build=release
dub build :triple --compiler=dmd --build=release
./bench/bin/itb-bench-single
./bench/bin/itb-bench-triple
```

DMD release produces meaningfully faster bench binaries than LDC2
release on this binding's FFI hot path — counter-intuitive but
reproducible: LDC2 -O3 release pessimises the `extern (C)` call
pattern that dominates per-call cost on the 16 MiB encrypt / decrypt
path, dropping throughput by 25-66% versus DMD release on the
single-primitive arms. The recorded numbers in [BENCH.md](BENCH.md)
come from DMD with `--build=release`.

The DMD default `debug` build emits debug symbols and skips inlining,
systematically under-reporting throughput by 2-3x — always pass
`--build=release` when benchmarking.

Both binaries land in `bench/bin/` after build.

## Environment variables

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `ITB_NONCE_BITS`     | `128`   | Process-wide nonce width - `128`, `256`, or `512`. Maps to `itb.setNonceBits` before any encryptor is constructed. Mirrors `ITB_NONCE_BITS` from `bitbyte_test.go`. |
| `ITB_LOCKSEED`       | unset   | When set to a non-empty / non-`0` value, every encryptor in the run calls `Encryptor.setLockSeed(1)`. Easy Mode auto-couples `setBitSoup(1)` + `setLockSoup(1)`, so no separate flags are needed. The mixed-primitive cases attach a dedicated lockSeed primitive (via `primL`) only under this flag; otherwise `primL` is `null` so the no-LockSeed bench arm measures the plain mixed-primitive cost. |
| `ITB_BENCH_FILTER`   | unset   | Substring filter on bench-case names - only cases whose name contains the filter are run. Useful when iterating on one primitive / op. |
| `ITB_BENCH_MIN_SEC`  | `5.0`   | Minimum measured wall-clock seconds per case. The runner keeps doubling iteration count until the measured batch reaches the threshold, mirroring Go's `-benchtime=Ns`. The 5-second default absorbs the cold-cache / warm-up transient that distorts shorter measurement windows on the 16 MiB encrypt / decrypt path. |

Worker count is fixed at `itb.setMaxWorkers(0)` (auto-detect),
matching the Go bench default.

## Examples

Whole grid, default settings (128-bit nonces, no lockSeed):

```bash
./bench/bin/itb-bench-single
```

512-bit nonces with the dedicated lockSeed channel + auto-coupled
overlay:

```bash
ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-triple
```

Just the BLAKE3 row of the Single grid:

```bash
ITB_BENCH_FILTER=blake3_1024bit ./bench/bin/itb-bench-single
```

Only the encrypt-with-MAC ops across every primitive in the Triple
grid, with a longer 10-second per-case budget for tighter
confidence intervals:

```bash
ITB_BENCH_FILTER=encrypt_auth_16mb ITB_BENCH_MIN_SEC=10 \
    ./bench/bin/itb-bench-triple
```

Just the mixed-primitive cases on the Single side:

```bash
ITB_BENCH_FILTER=mixed ./bench/bin/itb-bench-single
```

## Output format

```
# easy_single primitives=9 key_bits=1024 mac=hmac-blake3 nonce_bits=128 lockseed=off workers=auto
# benchmarks=40 payload_bytes=16777216 min_seconds=5
bench_single_aescmac_1024bit_encrypt_16mb               4    493210110.0 ns/op    32.44 MB/s
bench_single_aescmac_1024bit_decrypt_16mb               4    488104225.0 ns/op    32.78 MB/s
...
```

The four columns are:

1. Bench-case name (matches the `BenchmarkSingle*` /
   `BenchmarkTriple*` Go cohort, snake-cased and without the `Ext`
   infix that the Go side carries for namespace reasons).
2. Iteration count chosen to reach `ITB_BENCH_MIN_SEC`.
3. Per-iter wall-clock cost in nanoseconds.
4. Throughput in MiB/s, derived from `payload_bytes / ns_per_op`.

Comparison with the Go bench cohort goes via `(MB/s ratio)` - the
throughput column is the most direct cross-language signal for how
much overhead the D binding adds on top of the underlying libitb
call path.

## Expected runtime

At the default `ITB_BENCH_MIN_SEC=5`, each pass walks 40 cases (9
single-primitive + 1 mixed x 4 ops) and converges per case in 5-15
wall-clock seconds depending on the primitive's per-byte cost. A
full pass therefore lands at 5-10 minutes; the four canonical
passes (Single +/-LockSeed, Triple +/-LockSeed) fill BENCH.md in
~30 minutes of total wall-clock time. Filter to a single primitive
(`ITB_BENCH_FILTER=blake3_1024bit`) for ~1-minute spot-check runs.

## Recorded results

A snapshot of the four canonical pass results (Single + Triple,
each with and without `ITB_LOCKSEED=1`) on Intel Core i7-11700K is
collected in [BENCH.md](BENCH.md). The same file briefly
discusses the FFI overhead the binding leaves on top of the native
Go path through the `extern (C)` declarations DMD / LDC2 / GDC
emit for every `itb.sys.*` symbol.
