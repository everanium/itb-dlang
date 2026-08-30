# ITB D Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). D speaks the C ABI natively, so the binding links
`libitb.so` at compile time (`-litb` with an rpath onto the dist
directory) — no loader code, no C compiler at build time beyond the D
toolchain's own linker driver. Every hash-name / MAC-name /
cipher-name / profile-name is an opaque string passed through to Go
for validation; the binding carries no ITB construction logic. The
public surface is one non-copyable `Pipeline` struct (`create` /
`open` / `rekey` / `close`, Single Message encrypt / decrypt,
whole-buffer and incremental stream sessions with slice pumps), an
`Opts`
query-string builder, `registerProfile`, and the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dlang dub
```

Generic Linux: a Go toolchain plus DMD (or LDC2) and dub. The scripts
default to DMD; override via `COMPILER=ldc2`.

## Build the shared library

The convenience driver builds `libitb.so`, the binding library, and
the eitb CLI in one step:

```bash
./bindings/dlang/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/dlang && dub build
```

## Library lookup

Linking is compile-time: the build scripts pass
`-L-L<repo>/dist/linux-amd64 -L-litb` plus
`-L-rpath=<repo>/dist/linux-amd64` so the produced binaries resolve
`libitb.so` without `LD_LIBRARY_PATH`. Out-of-repo deployments relink
against their own libitb location or ship the library on the default
loader path.

## Usage example

```d
import itb;

auto sender = Pipeline.create("singlemsg-triple-mac-v1");
auto receiver = Pipeline.open("singlemsg-triple-mac-v1", sender.blob);

auto wire = sender.encryptMessage(cast(const(ubyte)[]) "any text or binary data");
auto plain = receiver.decryptMessage(wire);
assert(plain == cast(const(ubyte)[]) "any text or binary data");
```

`Opts` overrides the profile default per call (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette); every
setter returns a fresh value that composes without aliasing:

```d
auto opts = Opts().withChunkSize(65536).withWrapper(false);
auto sender = Pipeline.create("singlemsg-triple-mac-v1", opts);
auto receiver = Pipeline.open("singlemsg-triple-mac-v1", sender.blob, opts);
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```d
ubyte[32] perm = 0x11; ubyte[32] wrap = 0x22;
sender.rekey(perm[], wrap[]);
auto receiver2 = Pipeline.open("singlemsg-triple-mac-v1", sender.blob);
```

`Pipeline.create` takes the role of the `init` constructor on the
other bindings (`init` is a reserved property name in D). For
streaming, `encryptStreamPump` / `decryptStreamPump` move a byte
slice through an incremental session with a bounded feed / drain
slice; the explicit `encryptStream` / `decryptStream` sessions expose
`write` / `end` / `read` / `drainAll` for caller-driven loops.
`Pipeline` and the stream sessions are non-copyable RAII structs —
the destructor frees the Go-side handle, and a session must not
outlive its Pipeline.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as an `ItbException` carrying
the status code plus the `ITB_LastError` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```d
itb.setMemoryLimit(512L * 1024 * 1024);
itb.setGCPercent(20);
```

## Testing

```bash
./bindings/dlang/run_tests.sh
```

The harness builds `libitb.so` + the binding, compiles every
`tests/test_*.d` into its own executable under `tests/build/`, and
runs them in turn (per-process isolation gives each test a fresh
libitb global state). Test binaries carry `-unittest` and run with
`--DRT-testmode=run-main` so module unittest blocks execute ahead of
each test main. The suite covers Single Message round trips per
shipped profile, stream pumps, incremental sessions with pathological
batch sizes, tampered-wire failure stickiness, mid-flight
cancellation, rekey, profile registration, and error mapping —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/dlang/run_bench.sh
```

Micro-benches: `encryptMessage` and `encryptStreamPump` throughput at
1 MiB / 16 MiB / 64 MiB, compiled `-O -inline -release`. The
wall-clock budget per case is `ITB_BENCH_MIN_SEC` (default 5);
`ITB_BENCH_MIN_SEC=1 ./run_bench.sh` gives a smoke run.

## eitb utility

A small CLI under `bindings/dlang/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests (built by `build.sh`):

```bash
./bindings/dlang/eitb/eitb version
./bindings/dlang/eitb/eitb hashes
./bindings/dlang/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/dlang/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- Stream sessions borrow their Pipeline without a compiler-enforced
  lifetime; keeping a session alive past its Pipeline's destruction
  is undefined behaviour on the Go side. Scope sessions inside the
  Pipeline's lifetime.
- libitb must be reachable at runtime through the rpath baked in at
  link time (or the OS default loader path).
- **`encryptMessage` / `decryptMessage` / `encryptStreamOneShot` /
  `decryptStreamOneShot` / `encryptStreamPump` / `decryptStreamPump`
  and the stream `drainAll` helper all return `BorrowedBytes`** —
  a move-only
  RAII struct that frees its `malloc`-backed buffer at scope exit.
  `alias opSlice this` makes the returned value transparently usable
  where a `ubyte[]` is expected (comparison, indexing,
  `.length`, passing to `const(ubyte)[]` parameters). **The
  implicit slice does NOT extend the buffer's lifetime** — writing
  `ubyte[] x = pipe.encryptMessage(p);` binds `x` to freed memory
  the moment the temporary drops. Use `auto x = pipe.encryptMessage(p);`
  (retains the `BorrowedBytes`), or capture the slice with
  `.dup` if you need a heap copy that outlives the RAII wrapper.
- **Loading the D binding disables druntime's parallel GC marking
  by default** (via a `pragma(crt_constructor)` in `itb.pipeline`
  that sets `gc:parallel:0` before runtime-option parsing). Without
  this, the druntime helper threads contend with libitb's Go
  worker pool on machines with many cores and D throughput drops
  to ~55% of native. Callers who need parallel GC marking for
  their own workload can override at process start via
  `--DRT-gcopt=parallel:N` or `rt_options` — the runtime-option
  parser sees the crt-constructor setting and the explicit
  override wins.
