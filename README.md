# ITB D Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Native `extern (C)` wrapper over the libitb shared library
(`cmd/cshared`). D speaks the C ABI directly — no FFI shim layer,
no runtime `dlopen`. The binding links against `-litb` at DUB
build time and bakes an `rpath` into produced executables so the
loader finds `libitb.so` next to the repository's `dist/` tree.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-dlang`. Substitute the
literal token in the recipes below.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools dmd gcc-d ldc dub
```

`dmd` is the reference compiler; `ldc` (LDC2) is the LLVM-backed
release compiler used for the bench arm; `gcc-d` ships GDC and is
optional. `dub` is the standard build manager.

## Build the shared library

The convenience driver `bindings/dlang/build.sh` builds `libitb.so`
plus the D library object in one step. Run it from anywhere:

```bash
./bindings/dlang/build.sh
```

The driver expands to two underlying steps — building libitb from
the repo root, then `dub build --compiler=$COMPILER` (default
`dmd`) on the binding side. Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/dlang && dub build
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

### Compiler selection

Three D compilers are exercised by the binding's CI matrix; all
three produce a clean object file from the source tree:

```bash
COMPILER=dmd  ./bindings/dlang/build.sh   # reference compiler (default)
COMPILER=ldc2 ./bindings/dlang/build.sh   # LLVM-backed release compiler
COMPILER=gdc  ./bindings/dlang/build.sh   # GCC-backed compiler
```

DMD is the default for both development and the bench harness — its
release codegen produces meaningfully faster binaries than LDC2 release
on this binding's FFI hot path (counter-intuitive but reproducible —
LDC2 -O3 release pessimises the `extern (C)` call pattern that
dominates this binding's per-call cost). LDC2 remains available for
environments that prefer the LLVM-backed release compiler. GDC accepts
the source unchanged and is available for environments that prefer the
GCC toolchain.

## Add to a DUB project

The package is published as `itb`. As a path dependency from
inside this repository, add to the consumer's `dub.json`:

```json
{
    "dependencies": {
        "itb": { "path": "bindings/dlang" }
    }
}
```

Package metadata: `name = "itb"`, `targetType = "library"`,
`targetPath = "lib"`, `sourcePaths = ["src"]`, `license = "MIT"`.
The only runtime dependency is `libitb.so` itself.

## Library lookup order

1. `LD_LIBRARY_PATH` resolved at process startup. The test runner
   exports it pointing at `<repo>/dist/linux-amd64/`.
2. The `rpath` baked into the produced binary at link time
   (`$ORIGIN/../../../dist/linux-amd64`). Installed binaries find
   `libitb` without `LD_LIBRARY_PATH`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```d
itb.setMemoryLimit(512L << 20);
itb.setGcPercent(20);
```

## Tests

```bash
./bindings/dlang/run_tests.sh
```

The harness compiles every `tests/test_*.d` to its own standalone
executable under `tests/build/` and runs each in turn. Per-process
isolation gives every test a fresh libitb global state without
needing an in-process serial lock. The 30 test files mirror the
cross-binding coverage: Single + Triple Ouroboros, mixed primitives,
authenticated paths, blob round-trip, streaming chunked I/O, error
paths, lockSeed lifecycle.

Override the compiler via the `COMPILER` environment variable:

```bash
COMPILER=ldc2 ./bindings/dlang/run_tests.sh
COMPILER=gdc  ./bindings/dlang/run_tests.sh
```

Filter to a subset by passing test names as positional arguments:

```bash
./bindings/dlang/run_tests.sh test_blake3 test_easy_blake3
```

## Benchmarks

A custom Go-bench-style harness lives under `bench/` and covers
the four ops (`encrypt`, `decrypt`, `encryptAuth`, `decryptAuth`)
across the nine PRF-grade primitives plus one mixed-primitive
variant for both Single and Triple Ouroboros at 1024-bit ITB key
width and 16 MiB payload. See [`bench/README.md`](bench/README.md)
for invocation / environment variables / output format and
[`bench/BENCH.md`](bench/BENCH.md) for recorded throughput results across the
canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `bench/BENCH.md` is driven by the wrapper script in the
binding root:

```bash
./bindings/dlang/run_bench.sh                  # full 4-pass canonical sweep
./bindings/dlang/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `bench/bin/itb-bench-single` /
`bench/bin/itb-bench-triple` invocations (built ahead of time via
`cd bench && dub build :single --compiler=dmd --build=release`
and the `:triple` counterpart).

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while preserving the deniability of the per-chunk MAC-Inside-Encrypt container. Each chunk's MAC binds the encrypted payload to a 32-byte CSPRNG stream anchor (written as a once-per-stream wire prefix), the cumulative pixel offset of preceding chunks, and a final-flag bit — defending against chunk reorder, replay within or across streams sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail. The wire format adds 32 bytes of stream prefix plus one byte of encrypted trailing flag per chunk; no externally visible MAC tag.

**Easy Mode:**

`Encryptor.encryptStreamAuth` consumes plaintext via a `reader` delegate (`size_t (ubyte[] buf)`) and emits the on-wire transcript via a `writer` delegate (`void (const(ubyte)[] data)`). Wrapping a `std.stdio.File` with `rawRead` / `rawWrite` produces the necessary block-level I/O. The MAC key is allocated CSPRNG-fresh inside the encryptor at constructor time.

```d
import std.stdio : File;
import itb;

enum SRC_PATH   = "/tmp/64mb.src";
enum INNER_PATH = "/tmp/64mb.inner";
enum ENC_PATH   = "/tmp/64mb.enc";
enum DST_PATH   = "/tmp/64mb.dst";
enum CHUNK_SIZE = 16UL * 1024 * 1024;

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

auto enc = Encryptor("areion512", 1024, "hmac-blake3", 1);
{
    // Stage 1: encrypt plaintext into a buffered inner-transcript file.
    auto fin  = File(SRC_PATH,   "rb");
    auto fout = File(INNER_PATH, "wb");
    size_t reader(ubyte[] buf) @trusted { return fin.rawRead(buf).length; }
    void   writer(const(ubyte)[] d) @trusted { fout.rawWrite(d); }
    enc.encryptStreamAuth(&reader, &writer, cast(size_t) CHUNK_SIZE);
}
{
    // Stage 2: pump the inner ITB transcript through one wrap-stream
    // session so the on-wire bytes carry no ITB framing.
    auto fin  = File(INNER_PATH, "rb");
    auto fout = File(ENC_PATH,   "wb");
    // Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    auto ww = WrapStreamWriter(Cipher.aes128Ctr, outerKey);
    scope(exit) ww.close();
    fout.rawWrite(ww.nonce);
    ubyte[1 << 20] buf;
    for (;;)
    {
        auto slice = fin.rawRead(buf[]);
        if (slice.length == 0) break;
        fout.rawWrite(ww.update(slice));
    }
}
{
    // Receiver — strip the leading nonce, unwrap each block, hand the
    // inner ITB transcript to decryptStreamAuth.
    auto fin  = File(ENC_PATH, "rb");
    auto innerOut = File(INNER_PATH, "wb");
    ubyte[] nonceBuf = new ubyte[nonceSize(Cipher.aes128Ctr)];
    {
        size_t got = 0;
        while (got < nonceBuf.length)
        {
            auto s = fin.rawRead(nonceBuf[got .. $]);
            if (s.length == 0) break;
            got += s.length;
        }
    }
    auto ur = UnwrapStreamReader(Cipher.aes128Ctr, outerKey, nonceBuf);
    scope(exit) ur.close();
    ubyte[1 << 20] buf;
    for (;;)
    {
        auto slice = fin.rawRead(buf[]);
        if (slice.length == 0) break;
        innerOut.rawWrite(ur.update(slice));
    }
    innerOut.close();

    auto innerIn = File(INNER_PATH, "rb");
    auto fout    = File(DST_PATH,   "wb");
    size_t reader(ubyte[] b) @trusted { return innerIn.rawRead(b).length; }
    void   writer(const(ubyte)[] d) @trusted { fout.rawWrite(d); }
    enc.decryptStreamAuth(&reader, &writer, cast(size_t) CHUNK_SIZE);
}
enc.close();
```

**Build + run:**

```json
// <itb>/itb_stream_auth_example/dub.json
{
    "name": "itb_stream_auth_example",
    "description": "ITB D binding Streaming AEAD full-flow file-I/O example.",
    "targetType": "executable",
    "targetName": "main",
    "sourcePaths": ["."],
    "importPaths": ["."],
    "dependencies": {
        "itb": { "path": "<itb>/bindings/dlang/" }
    },
    "lflags-posix-dmd": [
        "-L<itb>/dist/linux-amd64",
        "-litb",
        "-rpath=<itb>/dist/linux-amd64"
    ],
    "lflags-posix-ldc": [
        "-L<itb>/dist/linux-amd64",
        "-litb",
        "-rpath=<itb>/dist/linux-amd64"
    ]
}
```

The `lflags-posix-dmd` / `lflags-posix-ldc` arrays use bare `-L` / `-rpath=` switches (not the `-L-Wl,-rpath` wrapping) because `dub` rewrites the bare form into the linker's native syntax for both DMD and LDC2.

```sh
cd <itb>/itb_stream_auth_example && dub run
```

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Free functions `encryptStreamAuth` / `decryptStreamAuth` in `itb.streams` take three explicit `Seed` instances plus a `MAC` (32-byte key from `/dev/urandom`) and stream through the same chunked-AEAD construction. Reader / writer delegates wired to per-call `File` objects feed each side.

```d
import itb;

auto noise = Seed("areion512", 1024);
auto data  = Seed("areion512", 1024);
auto start = Seed("areion512", 1024);
auto macKey = csprngMacKey();           // 32 bytes from /dev/urandom
auto mac = MAC("hmac-blake3", macKey[]);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

{
    // Stage 1: encrypt plaintext into a buffered inner-transcript file.
    auto fin  = File(SRC_PATH,   "rb");
    auto fout = File(INNER_PATH, "wb");
    size_t reader(ubyte[] buf) @trusted { return fin.rawRead(buf).length; }
    void   writer(const(ubyte)[] d) @trusted { fout.rawWrite(d); }
    encryptStreamAuth(noise, data, start, mac,
                      &reader, &writer, cast(size_t) CHUNK_SIZE);
}
{
    // Stage 2: pump the inner ITB transcript through one wrap-stream
    // session so the on-wire bytes carry no ITB framing.
    auto fin  = File(INNER_PATH, "rb");
    auto fout = File(ENC_PATH,   "wb");
    // Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    auto ww = WrapStreamWriter(Cipher.aes128Ctr, outerKey);
    scope(exit) ww.close();
    fout.rawWrite(ww.nonce);
    ubyte[1 << 20] buf;
    for (;;)
    {
        auto slice = fin.rawRead(buf[]);
        if (slice.length == 0) break;
        fout.rawWrite(ww.update(slice));
    }
}
```

**Build + run:**

```sh
cd <itb>/itb_stream_auth_example && dub run --quiet
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

## Quick Start — `itb.Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The high-level `Encryptor` (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
`Seed` / `encrypt` / `decrypt` path with one constructor call: the
encryptor allocates its own three (Single) or seven (Triple) seeds
plus MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide `itb.set*` accessors. Two
encryptors with different settings can run side-by-side without
cross-contamination.

The MAC primitive is bound at construction time — the third
constructor argument selects one of the registry names
(`hmac-blake3` — recommended default, `hmac-sha256`, `kmac256`).
The encryptor allocates a fresh 32-byte CSPRNG MAC key alongside
the per-seed PRF keys; `enc.exportState()` carries all of them in
a single JSON blob. On the receiver side, `dec.importState(blob)`
restores the MAC key together with the seeds, so the encrypt-today
/ decrypt-tomorrow flow is one method call per side.

When the `macName` argument is `null` or the empty string `""` the
binding picks `hmac-blake3` rather than forwarding NULL through to
libitb's own default — HMAC-BLAKE3 measures the lightest
authenticated-mode overhead across the Easy Mode bench surface.

```d
// Sender

import itb;
import std.stdio : writefln;

// Per-instance configuration — mutates only this encryptor's
// Config. Two encryptors built side-by-side carry independent
// settings; process-wide itb.set* accessors are NOT consulted
// after construction. mode = 1 = Single Ouroboros (3 seeds);
// mode = 3 = Triple Ouroboros (7 seeds).
auto enc = Encryptor("areion512", 2048, "hmac-blake3", 1);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

enc.setNonceBits(512);    // 512-bit nonce (default: 128-bit)
enc.setBarrierFill(4);    // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
enc.setBitSoup(1);        // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                          // auto-enabled for Single Ouroboros if setLockSoup(1) is on
enc.setLockSoup(1);       // optional Insane Interlocked Mode: per-chunk PRF-keyed
                          // bit-permutation overlay on top of bit-soup;
                          // auto-enabled for Single Ouroboros if setBitSoup(1) is on

// enc.setLockSeed(1);    // optional dedicated lockSeed for the bit-permutation
                          // derivation channel — separates that PRF's keying
                          // material from the noiseSeed-driven noise-injection
                          // channel; auto-couples setLockSoup(1) +
                          // setBitSoup(1). Adds one extra seed slot
                          // (3 → 4 for Single, 7 → 8 for Triple). Must be
                          // called BEFORE the first encryptAuth — switching
                          // mid-session throws ITBError(Status.EasyLockSeedAfterEncrypt).

// Persistence blob — carries seeds + PRF keys + MAC key (and the
// dedicated lockSeed material when setLockSeed(1) is active).
auto blob = enc.exportState();
writefln("state blob: %d bytes", blob.length);
writefln("primitive: %s, keyBits: %d, mode: %d, mac: %s",
    enc.primitive, enc.keyBits, enc.mode, enc.macName);

auto plaintext = cast(const(ubyte)[]) "any text or binary data - including 0x00 bytes";
// auto chunkSize = 4 * 1024 * 1024;  // 4 MiB - bulk local crypto, not small-frame network streaming
// auto readSize  = 64 * 1024;        // app-driven feed granularity (independent of chunkSize)

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
auto encrypted = enc.encryptAuth(plaintext).dup;
writefln("encrypted: %d bytes", encrypted.length);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = wrapInPlace(Cipher.aes128Ctr, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;
writefln("wire: %d bytes", wire.length);

// Streaming alternative — slice plaintext into chunkSize pieces
// and call enc.encryptAuth() per chunk; each chunk carries its
// own MAC tag. enc.easyHeaderSize() + enc.parseChunkLen() are
// per-instance accessors (track this encryptor's own nonceBits,
// NOT the process-wide itb.headerSize).
//
// ubyte[] cbuf;
// for (size_t i = 0; i < plaintext.length; i += chunkSize)
// {
//     auto end = i + chunkSize > plaintext.length ? plaintext.length : i + chunkSize;
//     cbuf ~= enc.encryptAuth(plaintext[i .. end]).dup;
// }
// auto encrypted = cbuf;

// Send encrypted payload + state blob; the destructor releases
// the handle + zeroes key material at scope end. enc.close() is
// the explicit zeroing path that surfaces release-time errors.


// Receiver

// Receive `wire` payload + state blob
// auto wire = ...;
// auto blob = ...;

itb.setMaxWorkers(8);  // limit to 8 CPU cores (default: 0 = all CPUs)

// Optional: peek at the blob's metadata before constructing a
// matching encryptor. Useful when the receiver multiplexes blobs
// of different shapes (different primitive / mode / MAC choices).
auto cfg = peekConfig(blob);
writefln("peek: primitive=%s, keyBits=%d, mode=%d, mac=%s",
    cfg.primitive, cfg.keyBits, cfg.mode, cfg.macName);

auto dec = Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);

// dec.importState(blob) below automatically restores the full
// per-instance configuration (nonceBits, barrierFill, bitSoup,
// lockSoup, and the dedicated lockSeed material when sender's
// setLockSeed(1) was active). The set*() lines below are kept
// for documentation — they show the knobs available for explicit
// pre-Import override. barrierFill is asymmetric: a receiver-set
// value > 1 takes priority over the blob's barrierFill (the
// receiver's heavier CSPRNG margin is preserved across Import).
dec.setNonceBits(512);
dec.setBarrierFill(4);
dec.setBitSoup(1);
dec.setLockSoup(1);
// dec.setLockSeed(1);   // optional — Import below restores the dedicated
                         // lockSeed slot from the blob's lock_seed:true.

// Restore PRF keys, seed components, MAC key, and the per-instance
// configuration overrides (nonceBits / barrierFill / bitSoup /
// lockSoup / lockSeed) from the saved blob.
dec.importState(blob);

// Strip the per-stream nonce, recover the inner ITB ciphertext.
auto recovered = unwrapInPlace(Cipher.aes128Ctr, outerKey, wire);

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered). Mismatch
// surfaces as ITBError(Status.MACFailure), not a corrupted
// plaintext.
import std.string : assumeUTF;
try
{
    auto plaintextOut = dec.decryptAuth(recovered);
    writefln("decrypted: %s", assumeUTF(plaintextOut));
}
catch (ITBError e)
{
    if (e.statusCode == Status.MACFailure)
        writefln("MAC verification failed — tampered or wrong key");
    else
        throw e;
}
```

### Per-encryptor thread-unsafety contract

Each `Encryptor` is single-thread by construction. Cipher methods
(`encrypt` / `decrypt` / `encryptAuth` / `decryptAuth`) write into
the per-instance output-buffer cache and are not safe to invoke
concurrently against the same encryptor. Per-instance setters
(`setNonceBits` / `setBarrierFill` / `setBitSoup` / `setLockSoup`
/ `setLockSeed` / `setChunkSize`) and persistence (`exportState`
/ `importState`) likewise require external synchronisation when
invoked against the same encryptor from multiple threads.
Distinct `Encryptor` values, each owned by one thread, run
independently against the libitb worker pool — share by
serialising or by giving each thread its own `Encryptor`.

### Slice-return contract on cipher methods

Every cipher method (`enc.encrypt` / `enc.decrypt` / `enc.encryptAuth`
/ `enc.decryptAuth`) returns a slice over the per-encryptor output
cache. The cache survives between calls and is overwritten on the
next cipher call:

```d
auto ct1 = enc.encrypt(p1);
auto ct2 = enc.encrypt(p2);
// At this point ct1's contents have been overwritten — the slice
// header is still valid but the bytes underneath are now ct2's.
```

Call `.dup` to detach an owned copy whose lifetime needs to outlast
the next cipher call:

```d
auto ct1 = enc.encrypt(p1).dup;   // own bytes — survives the next call
auto ct2 = enc.encrypt(p2);
// ct1 still holds the original ciphertext.
```

The cache is wiped on grow and on `enc.close()` / destruction, so
residual ciphertext / plaintext does not linger in heap memory
beyond the next cipher call.

## Quick Start — Mixed primitives (Different PRF per seed slot)

`Encryptor.newMixed` and `Encryptor.newMixed3` accept per-slot
primitive names — the noise / data / start (and optional dedicated
lockSeed) seed slots can use different PRF primitives within the
same native hash width. The mix-and-match-PRF freedom of the
lower-level path, surfaced through the high-level `Encryptor`
without forcing the caller off the Easy Mode constructor. The
state blob carries per-slot primitives + per-slot PRF keys; the
receiver constructs a matching encryptor with the same arguments
and calls `importState` to restore.

```d
// Sender

import itb;
import std.stdio : writefln;

// Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
// Every name must share the same native hash width — mixing widths
// throws ITBError at construction time.
// Triple Ouroboros mirror — Encryptor.newMixed3 takes seven
// per-slot names (noise + 3 data + 3 start) plus the optional
// primL lockSeed.
auto enc = Encryptor.newMixed(
    "blake3",         // primN: noiseSeed:  BLAKE3
    "blake2s",        // primD: dataSeed:   BLAKE2s
    "areion256",      // primS: startSeed:  Areion-SoEM-256
    "blake2b256",     // primL: dedicated lockSeed (null for no lockSeed slot)
    1024,             // keyBits
    "hmac-blake3");   // macName

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

// Per-instance configuration applies as for Encryptor(...).
enc.setNonceBits(512);
enc.setBarrierFill(4);
// BitSoup + LockSoup are auto-coupled on the on-direction by
// primL above; explicit calls below are unnecessary but
// harmless if added.
// enc.setBitSoup(1);
// enc.setLockSoup(1);

// Per-slot introspection — primitive() returns "mixed" literal,
// primitiveAt(slot) returns each slot's name, isMixed() is the
// typed predicate. Slot ordering is canonical: 0 = noiseSeed,
// 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple
// grows the middle range to 7 slots + lockSeed.
writefln("mixed=%s primitive=%s", enc.isMixed, enc.primitive);
foreach (i; 0 .. 4)
    writefln("  slot %d: %s", i, enc.primitiveAt(i));

auto blob = enc.exportState();
writefln("state blob: %d bytes", blob.length);

auto plaintext = cast(const(ubyte)[]) "mixed-primitive Easy Mode payload";

auto encrypted = enc.encryptAuth(plaintext).dup;
writefln("encrypted: %d bytes", encrypted.length);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = wrapInPlace(Cipher.aes128Ctr, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;


// Receiver

// Receive `wire` payload + state blob
// auto wire = ...;
// auto blob = ...;

// Receiver constructs a matching mixed encryptor — every per-slot
// primitive name plus keyBits and macName must agree with the
// sender. importState validates each per-slot primitive against
// the receiver's bound spec; mismatches throw
// ITBEasyMismatchError with the "primitive" field tag.
auto dec = Encryptor.newMixed(
    "blake3", "blake2s", "areion256",
    "blake2b256", 1024, "hmac-blake3");

dec.importState(blob);

auto recovered = unwrapInPlace(Cipher.aes128Ctr, outerKey, wire);
import std.string : assumeUTF;
auto decrypted = dec.decryptAuth(recovered);
writefln("decrypted: %s", assumeUTF(decrypted));
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×keyBits)) takes seven
seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) on the low-level path, all wrapped behind a single
`Encryptor` call when `mode = 3` is passed to the constructor.

```d
import itb;

// mode=3 selects Triple Ouroboros. All other constructor arguments
// behave identically to the Single (mode=1) case shown above.
auto enc = Encryptor("areion512", 2048, "hmac-blake3", 3);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

auto plaintext = cast(const(ubyte)[]) "Triple Ouroboros payload";
auto encrypted = enc.encryptAuth(plaintext).dup;

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = wrapInPlace(Cipher.aes128Ctr, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;

auto recovered = unwrapInPlace(Cipher.aes128Ctr, outerKey, wire);
auto decrypted = enc.decryptAuth(recovered);
assert(decrypted == plaintext);
```

The seven-seed split is internal to the encryptor; the on-wire
ciphertext format is identical in shape to Single Ouroboros — only
the internal payload split / interleave differs. Mixed-primitive
Triple is reachable via `Encryptor.newMixed3`.

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path uses explicit `Seed` handles for the
noise / data / start trio plus an optional dedicated `Seed` wired
in through `Seed.attachLockSeed`. Useful when the caller needs
full control over per-slot keying (e.g. PRF material stored in an
HSM) or when slotting into the existing Go `itb.Encrypt` /
`itb.Decrypt` call surface from a D client. The high-level
`Encryptor` above wraps this same path with one constructor call.

```d
// Sender

import itb;
import std.stdio : writefln;

// Optional: global configuration (all process-wide, atomic)
itb.setMaxWorkers(8);     // limit to 8 CPU cores (default: 0 = all CPUs)
itb.setNonceBits(512);    // 512-bit nonce (default: 128-bit)
itb.setBarrierFill(4);    // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)

itb.setBitSoup(1);        // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                          // automatically enabled for Single Ouroboros if
                          // itb.setLockSoup(1) is enabled or vice versa

itb.setLockSoup(1);       // optional Insane Interlocked Mode: per-chunk PRF-keyed
                          // bit-permutation overlay on top of bit-soup;
                          // automatically enabled for Single Ouroboros if
                          // itb.setBitSoup(1) is enabled or vice versa

// Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
// pre-keys its primitive once at construction; the C ABI / FFI
// layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
// absorb dispatch through Seed.BatchHash — no manual batched-arm
// attachment is required on the D side.
auto ns = Seed("areion512", 2048);   // random noise CSPRNG seeds + hash key generated
auto ds = Seed("areion512", 2048);   // random data  CSPRNG seeds + hash key generated
auto ss = Seed("areion512", 2048);   // random start CSPRNG seeds + hash key generated

// Optional: dedicated lockSeed for the bit-permutation derivation
// channel. Separates that PRF's keying material from the noiseSeed-
// driven noise-injection channel without changing the public
// encrypt / decrypt signatures. The bit-permutation overlay must
// be engaged (itb.setBitSoup(1) or itb.setLockSoup(1) — both
// already on above) before the first encrypt; the build-PRF guard
// panics on encrypt-time when an attach is present without either
// flag.
auto ls = Seed("areion512", 2048);   // random lock CSPRNG seeds + hash key generated
ns.attachLockSeed(ls);

// HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag. Real code should
// pull the key bytes from a CSPRNG (e.g. /dev/urandom via
// std.file.read); the zero key here is for example purposes only.
ubyte[32] macKey = 0;
auto mac = MAC("hmac-blake3", macKey[]);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

auto plaintext = cast(const(ubyte)[]) "any text or binary data - including 0x00 bytes";

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
auto encrypted = encryptAuth(ns, ds, ss, mac, plaintext).dup;
writefln("encrypted: %d bytes", encrypted.length);

// Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
auto nonce = wrapInPlace(Cipher.aes128Ctr, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;
writefln("wire: %d bytes", wire.length);

// Cross-process persistence: itb.Blob512 packs every seed's hash
// key + components, the optional dedicated lockSeed, and the MAC
// key + name into one JSON blob alongside the captured process-
// wide globals. BlobOpt.LockSeed / BlobOpt.MAC opt the
// corresponding sections in.
auto blob = Blob512();
blob.setKey(BlobSlot.N, ns.hashKey);
blob.setComponents(BlobSlot.N, ns.components);
blob.setKey(BlobSlot.D, ds.hashKey);
blob.setComponents(BlobSlot.D, ds.components);
blob.setKey(BlobSlot.S, ss.hashKey);
blob.setComponents(BlobSlot.S, ss.components);
blob.setKey(BlobSlot.L, ls.hashKey);
blob.setComponents(BlobSlot.L, ls.components);
blob.setMACKey(macKey[]);
blob.setMACName("hmac-blake3");
auto blobBytes = blob.exportToBytes(BlobOpt.LockSeed | BlobOpt.MAC);
writefln("persistence blob: %d bytes", blobBytes.length);

// Send encrypted payload + blobBytes; the seed, MAC, and blob
// destructors release at scope end.


// Receiver

itb.setMaxWorkers(8);   // deployment knob — not serialised by Blob512

// Receive `wire` payload + blobBytes
// auto wire = ...;
// auto blobBytes = ...;
// auto outerKey = ...;   // agreed out-of-band with the sender

// Blob512.importFromBytes restores per-slot hash keys + components
// AND applies the captured globals (nonceBits / barrierFill /
// bitSoup / lockSoup) via the process-wide setters.
auto restored = Blob512();
restored.importFromBytes(blobBytes);

auto ns2 = Seed.fromComponents(
    "areion512",
    restored.getComponents(BlobSlot.N),
    restored.getKey(BlobSlot.N));
auto ds2 = Seed.fromComponents(
    "areion512",
    restored.getComponents(BlobSlot.D),
    restored.getKey(BlobSlot.D));
auto ss2 = Seed.fromComponents(
    "areion512",
    restored.getComponents(BlobSlot.S),
    restored.getKey(BlobSlot.S));
auto ls2 = Seed.fromComponents(
    "areion512",
    restored.getComponents(BlobSlot.L),
    restored.getKey(BlobSlot.L));
ns2.attachLockSeed(ls2);

auto macName2 = restored.getMACName();
auto macKey2 = restored.getMACKey();
auto mac2 = MAC(macName2, macKey2);

import std.string : assumeUTF;
// Strip the per-stream nonce, recover the inner ITB ciphertext.
auto recovered = unwrapInPlace(Cipher.aes128Ctr, outerKey, wire);
// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered).
auto decrypted = decryptAuth(ns2, ds2, ss2, mac2, recovered);
writefln("decrypted: %s", assumeUTF(decrypted));
```

## Streams — chunked I/O over delegate-driven readers / writers

`StreamEncryptor` / `StreamDecryptor` (and the seven-seed
counterparts `StreamEncryptor3` / `StreamDecryptor3`) wrap the
Single Message Encrypt / Decrypt API behind a chunked I/O surface. ITB
ciphertexts cap at ~64 MB plaintext per chunk; streaming larger
payloads slices the input into chunks at the binding layer,
encrypts each chunk through the regular FFI path, and concatenates
the results. Memory peak is bounded by `chunkSize` (default
`DEFAULT_CHUNK_SIZE` = 16 MiB) regardless of the total payload
length.

The stream wrappers take `void delegate(const(ubyte)[])` writer
delegates that receive each emitted chunk; the convenience free
functions `encryptStream` / `decryptStream` (and Triple variants)
additionally take a `size_t delegate(ubyte[])` reader delegate
that fills its buffer argument with the next slice of input bytes
and returns the number of bytes read (zero on EOF).

```d
import itb;

auto n = Seed("blake3", 1024);
auto d = Seed("blake3", 1024);
auto s = Seed("blake3", 1024);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
auto outerKey = wrapperGenerateKey(Cipher.aes128Ctr);
// auto outerKey = wrapperDeriveKey(Cipher.aes128Ctr, master);

// Encrypt: writer delegate receives each ITB chunk; the wrap-stream
// writer XORs each chunk through one keystream session into `wire`.
// close() flushes the trailing partial chunk; the destructor
// best-effort-flushes on scope exit.
ubyte[] wire;
{
    // Format-deniability ITB masking via outer-cipher wrapper (AES-128-CTR) ~0% overhead (Recommended in every case).
    auto ww = WrapStreamWriter(Cipher.aes128Ctr, outerKey);
    scope(exit) ww.close();
    wire ~= ww.nonce;
    auto enc = StreamEncryptor(n, d, s,
        (const(ubyte)[] chunk) { wire ~= ww.update(chunk); },
        1 << 16);
    enc.write(cast(const(ubyte)[]) "chunk one");
    enc.write(cast(const(ubyte)[]) "chunk two");
    enc.close();
}

// Decrypt: strip the leading nonce, unwrap the body, feed the
// recovered inner ITB ciphertext to StreamDecryptor (which buffers
// partial chunks until complete). close() throws when leftover
// bytes do not form a complete chunk.
ubyte[] psink;
{
    size_t nlen = nonceSize(Cipher.aes128Ctr);
    auto ur = UnwrapStreamReader(Cipher.aes128Ctr, outerKey, wire[0 .. nlen]);
    scope(exit) ur.close();
    auto ciphertext = ur.update(wire[nlen .. $]);
    auto dec = StreamDecryptor(n, d, s,
        (const(ubyte)[] pt) { psink ~= pt; });
    dec.feed(ciphertext);
    dec.close();
}
assert(psink == cast(const(ubyte)[]) "chunk onechunk two");
```

For driving an encrypt or decrypt straight off a reader / writer
delegate pair, the convenience wrappers `encryptStream` /
`decryptStream` (plus `encryptStreamTriple` / `decryptStreamTriple`)
loop until EOF internally:

```d
import itb;

auto n = Seed("blake3", 1024);
auto d = Seed("blake3", 1024);
auto s = Seed("blake3", 1024);

auto plaintext = new ubyte[5 * 1024 * 1024];
plaintext[] = 0xAB;

ubyte[] ciphertext;
size_t pcursor = 0;
encryptStream(n, d, s,
    (ubyte[] buf) {
        size_t take = buf.length > plaintext.length - pcursor
            ? plaintext.length - pcursor : buf.length;
        buf[0 .. take] = plaintext[pcursor .. pcursor + take];
        pcursor += take;
        return take;
    },
    (const(ubyte)[] chunk) { ciphertext ~= chunk; },
    1 << 20);

ubyte[] recovered;
size_t ccursor = 0;
decryptStream(n, d, s,
    (ubyte[] buf) {
        size_t take = buf.length > ciphertext.length - ccursor
            ? ciphertext.length - ccursor : buf.length;
        buf[0 .. take] = ciphertext[ccursor .. ccursor + take];
        ccursor += take;
        return take;
    },
    (const(ubyte)[] pt) { recovered ~= pt; },
    1 << 16);
assert(recovered == plaintext);
```

Switching `itb.setNonceBits` mid-stream produces a chunk header
layout the paired decryptor (which snapshots `itb.headerSize` at
construction) cannot parse — the nonce size must be stable for the
lifetime of one stream pair.

### Seed-lifetime contract on streams

The stream constructors store raw pointers to the supplied `Seed`
values. The caller MUST keep all three (or seven, for Triple) seeds
alive for the entire stream lifetime — until the destructor or
`close()` returns. Letting any seed go out of scope before then is
undefined behaviour (use-after-free in the FFI call). The stream
takes the seeds, not an `Encryptor`; the seeds themselves are the
keying-material handles.

Practical pattern: declare the seeds in the same scope as the
stream, with the seeds declared first so they outlive the stream's
destructor (D destroys local values in reverse declaration order).
The `Seed` type is non-copyable, so accidentally moving a seed away
under the stream is a compile error rather than a runtime fault.

## Native Blob — low-level state persistence

`Blob128` / `Blob256` / `Blob512` wrap the libitb Native Blob C
ABI: a width-specific container that packs the low-level encryptor
material (per-seed hash key + components + optional dedicated
lockSeed + optional MAC key + name) plus the captured process-wide
configuration into one self-describing JSON blob. Used on the
lower-level encrypt / decrypt path where each seed slot may carry
a different primitive — the high-level `Encryptor.exportState`
wraps a narrower one-primitive-per-encryptor surface that uses the
same wire format under the hood.

```d
import itb;

// Sender side — pack a Single-Ouroboros + Areion-SoEM-512 + MAC
// state blob.
auto ns = Seed("areion512", 2048);
auto ds = Seed("areion512", 2048);
auto ss = Seed("areion512", 2048);

ubyte[32] macKey = 0;
auto blob = Blob512();
blob.setKey(BlobSlot.N, ns.hashKey);
blob.setComponents(BlobSlot.N, ns.components);
blob.setKey(BlobSlot.D, ds.hashKey);
blob.setComponents(BlobSlot.D, ds.components);
blob.setKey(BlobSlot.S, ss.hashKey);
blob.setComponents(BlobSlot.S, ss.components);
blob.setMACKey(macKey[]);
blob.setMACName("hmac-blake3");
auto blobBytes = blob.exportToBytes(BlobOpt.MAC);   // MAC opted in, lockseed off

// Receiver side — round-trip back to working seed material.
auto restored = Blob512();
restored.importFromBytes(blobBytes);

auto ns2 = Seed.fromComponents(
    "areion512",
    restored.getComponents(BlobSlot.N),
    restored.getKey(BlobSlot.N));
// ... wire ds, ss the same way; rebuild MAC; decryptAuth ...
```

The blob is mode-discriminated: `Blob512.exportToBytes` packs
Single material, `Blob512.exportTriple` packs Triple material; the
matching `Blob512.importFromBytes` / `Blob512.importTriple`
receivers reject the wrong importer with
`ITBBlobModeMismatchError`.

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry. Listed below in the
binding-side canonical PRF-only ordering — `Areion-SoEM-256`,
`Areion-SoEM-512`, `BLAKE2b-256`, `BLAKE2b-512`, `BLAKE2s`,
`BLAKE3`, `AES-CMAC`, `SipHash-2-4`, `ChaCha20` — the FFI names
are `areion256`, `areion512`, `blake2b256`, `blake2b512`,
`blake2s`, `blake3`, `aescmac`, `siphash24`, `chacha20`. Triple
Ouroboros (3× security) takes seven seeds (one shared `noiseSeed`
plus three `dataSeed` and three `startSeed`) via `encryptTriple` /
`decryptTriple` and the authenticated counterparts
`encryptAuthTriple` / `decryptAuthTriple`. Streaming counterparts:
`StreamEncryptor3` / `StreamDecryptor3` / `encryptStreamTriple` /
`decryptStreamTriple`.

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths throws `ITBError` with
`Status.SeedWidthMix`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values surface as
`ITBError` with `Status.BadInput` rather than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `setMaxWorkers(n)` | non-negative int | 0 (auto) |
| `setNonceBits(n)` | 128, 256, 512 | 128 |
| `setBarrierFill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `setBitSoup(mode)` | 0 (off), non-zero (on) | 0 |
| `setLockSoup(mode)` | 0 (off), non-zero (on) | 0 |

Read-only constants: `itb.maxKeyBits()`, `itb.channels()`,
`itb.headerSize()`, `itb.version_()` (the trailing underscore
avoids the `version` keyword clash).

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `itb.parseChunkLen(header)` inspects
the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb.headerSize()` returns the active header
byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

MAC names available via `itb.listMACs()`: `kmac256`, `hmac-sha256`,
`hmac-blake3`. Hash names via `itb.listHashes()`.

## Concurrency

The libitb shared library exposes process-wide configuration
through a small set of atomics (`setNonceBits`, `setBarrierFill`,
`setBitSoup`, `setLockSoup`, `setMaxWorkers`). Multiple threads
calling these setters concurrently without external coordination
will race for the final value visible to subsequent encrypt /
decrypt calls — serialise the mutators behind a `core.sync.mutex`
(or set them once at startup before spawning workers) when
multiple D threads need to touch them.

Per-encryptor configuration via `Encryptor.setNonceBits` /
`Encryptor.setBarrierFill` / `Encryptor.setBitSoup` /
`Encryptor.setLockSoup` mutates only that handle's Config copy and
is safe to call from the owning thread without affecting other
`Encryptor` instances. The cipher methods (`Encryptor.encrypt` /
`Encryptor.decrypt` / `Encryptor.encryptAuth` /
`Encryptor.decryptAuth`) write into the per-instance output-buffer
cache; sharing one `Encryptor` across threads requires external
synchronisation. Distinct `Encryptor` handles, each owned by one
thread, run independently against the libitb worker pool.

By contrast, the low-level cipher free functions (`encrypt` /
`decrypt` / `encryptAuth` / `decryptAuth` plus the Triple
counterparts) allocate output per call and are **thread-safe** under
concurrent invocation on the same Seed handles — libitb's worker
pool dispatches them independently. Two exceptions: `Seed.attachLockSeed`
mutates the noise Seed and must not race against an in-flight cipher
call on it, and the process-wide setters above stay process-global.

The wrapper types (`Seed`, `MAC`, `Encryptor`, `Blob128` /
`Blob256` / `Blob512`, `StreamEncryptor` / `StreamDecryptor` and
their Triple counterparts) are plain `struct` values — stack
allocated, non-copyable via `@disable this(this)`, with
deterministic `~this()` destructors. They live outside the D
garbage collector by construction, so the §11.j `keepAlive`
discipline that JIT- and GC-managed bindings require (the .NET
`GC.KeepAlive` trap, the V8 `FinalizationRegistry` trap) is N/A
here — the FFI handle pointer is owned by the struct's stack slot
for the entire scope and the destructor at scope exit handles
release.

## Error model

Every failure surfaces as `ITBError` (or one of the four typed
subclasses) with a `statusCode` field and a `detail` string:

```d
import itb;
import std.stdio : writefln;

ubyte[32] keybuf = 0;
try
{
    auto bad = MAC("nonsense", keybuf[]);
}
catch (ITBError e)
{
    // e.statusCode == Status.BadMAC
    writefln("code=%d msg=%s", e.statusCode, e.msg);
}
```

The typed-exception hierarchy:

- `ITBError` — base class; carries `statusCode` + `detail`.
- `ITBEasyMismatchError` — Easy Mode `importState` rejected a
  field; the offending JSON field name is on `.field`.
- `ITBBlobModeMismatchError` — Blob receiver rejected a
  Single-vs-Triple wire mismatch.
- `ITBBlobMalformedError` — Blob payload failed structural checks.
- `ITBBlobVersionTooNewError` — Blob version field higher than
  this libitb build supports.

Status codes are documented in `cmd/cshared/internal/capi/errors.go`
and re-exported as the named `Status` enum in `itb.status` (e.g.
`Status.MACFailure`, `Status.EasyMismatch`, `Status.SeedWidthMix`).
The `Encryptor.importState` path additionally folds the offending
JSON field name into the thrown exception's `.field` member; the
field is also retrievable via the module-level
`lastMismatchField()` accessor.

**Note:** empty plaintext / ciphertext is rejected by libitb itself
with `ITBError` carrying `statusCode == Status.EncryptFailed`
("itb: empty data") on every cipher entry point. Pass at least one
byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `Status.OK` | Success — the only non-failure return value |
| 1 | `Status.BadHash` | Unknown hash primitive name |
| 2 | `Status.BadKeyBits` | ITB key width invalid for the chosen primitive |
| 3 | `Status.BadHandle` | FFI handle invalid or already freed |
| 4 | `Status.BadInput` | Generic shape / range / domain violation on a call argument |
| 5 | `Status.BufferTooSmall` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `Status.EncryptFailed` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `Status.DecryptFailed` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `Status.SeedWidthMix` | Seeds passed to one call do not share the same native hash width |
| 9 | `Status.BadMAC` | Unknown MAC name or key-length violates the primitive's `minKeyBytes` |
| 10 | `Status.MACFailure` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `Status.EasyClosed` | Easy Mode encryptor call after `close()` |
| 12 | `Status.EasyMalformed` | Easy Mode `importState` blob fails JSON parse / structural check |
| 13 | `Status.EasyVersionTooNew` | Easy Mode blob version field higher than this build supports |
| 14 | `Status.EasyUnknownPrimitive` | Easy Mode blob references a primitive this build does not know |
| 15 | `Status.EasyUnknownMAC` | Easy Mode blob references a MAC this build does not know |
| 16 | `Status.EasyBadKeyBits` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `Status.EasyMismatch` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name on `ITBEasyMismatchError.field` |
| 18 | `Status.EasyLockSeedAfterEncrypt` | `setLockSeed(1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `Status.BlobModeMismatch` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `Status.BlobMalformed` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `Status.BlobVersionTooNew` | Native Blob version field higher than this libitb build supports |
| 22 | `Status.BlobTooManyOpts` | Native Blob export opts mask carries unsupported bits |
| 23 | `Status.StreamTruncated` | Streaming AEAD transcript truncated before the terminator chunk; raised as `ITBStreamTruncatedError` |
| 24 | `Status.StreamAfterFinal` | Streaming AEAD transcript carries chunk bytes after the terminator; raised as `ITBStreamAfterFinalError` |
| 99 | `Status.Internal` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **D 2.x with three supported compilers.** `dmd` is the reference
  compiler; `ldc2` is the LLVM-backed release compiler used for the
  bench arm; `gdc` (shipped via Arch's `gcc-d`) is optional. The
  source uses `@safe` / `@nogc` / `pure` annotations where the FFI
  substrate permits.
- **`dub` build manager.** The package's `dub.json` declares
  `targetType = "library"` plus `bench` and `eitb` sub-packages.
- **Single library.** All consumer-visible declarations live under
  `src/`; the FFI substrate (`itb.sys`) is kept separate so audits
  can read it independently.
- **libitb.so required at runtime.** The library links against
  `dist/<os>-<arch>/libitb.<ext>` — the shared library must be built
  first and reachable through the loader's search path (compile-time
  `-L` plus runtime `RPATH` or `LD_LIBRARY_PATH`).
- **No external runtime deps beyond Phobos + libitb.so.** The
  binding uses only D's standard library; no third-party runtime
  dependencies are pulled in.
- **Frozen C ABI.** The `ITB_*` exports declared in `itb.sys` (synced
  from `dist/<os>-<arch>/libitb.h`) are the contract; the binding
  does not extend or reshape them.
- **No `dlopen`.** Symbols are bound at link time. Consumers wanting
  runtime FFI loading can wrap this binding's `itb.sys` layer in
  their own `core.sys.posix.dlfcn` shim.

## API Overview

Every public symbol re-exports through the top-level `itb` module
(`import itb;`). Sub-modules (`itb.seed`, `itb.streams`,
`itb.wrapper`, ...) are reachable directly when finer-grained imports
are preferred.

### Library metadata (`itb.registry`)

| Symbol | Purpose |
|---|---|
| `string version_()` | Library version `"<major>.<minor>.<patch>"` |
| `int maxKeyBits()` | Max supported ITB key width in bits |
| `int channels()` | Number of native channel slots |
| `int headerSize()` | Current chunk header size in bytes |
| `size_t parseChunkLen(const(ubyte)[] header)` | Parse chunk header, return total on-wire chunk length |
| `HashInfo[] listHashes()` / `MACInfo[] listMACs()` | Catalogue accessors |

### Process-wide configuration (`itb.registry`)

| Symbol | Purpose |
|---|---|
| `void setBitSoup(int mode)` / `int getBitSoup()` | Bit Soup mode toggle |
| `void setLockSoup(int mode)` / `int getLockSoup()` | Lock Soup mode toggle |
| `void setMaxWorkers(int n)` / `int getMaxWorkers()` | Worker pool cap |
| `void setNonceBits(int n)` / `int getNonceBits()` | Nonce width (128 / 256 / 512) |
| `void setBarrierFill(int n)` / `int getBarrierFill()` | Barrier-fill factor |
| `long setMemoryLimit(long limit)` | Go runtime heap soft limit in bytes; pass negative to query only |
| `int setGcPercent(int pct)` | Go GC trigger percentage; pass negative to query only |

### Seeds and MAC

| Symbol | Purpose |
|---|---|
| `Seed(string hashName, int keyBits)` | CSPRNG-fresh seed |
| `seed.width / hashName / hashKey / components / attachLockSeed(lockSeed)` | Introspection + lock-seed attachment |
| `MAC(string macName, const(ubyte)[] key)` | Construct MAC handle |

### Low-level cipher (`itb.cipher`)

| Symbol | Purpose |
|---|---|
| `ubyte[] encrypt(noise, data, start, pt)` / `decrypt(...)` | Single Message |
| `encryptAuth(noise, data, start, mac, pt)` / `decryptAuth(...)` | MAC-authenticated counterparts |
| `encryptTriple(noise, d1, d2, d3, s1, s2, s3, pt)` / `decryptTriple(...)` | Triple Ouroboros |
| `encryptAuthTriple(...)` / `decryptAuthTriple(...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor (`itb.encryptor`)

| Symbol | Purpose |
|---|---|
| `Encryptor(string primitive, int keyBits, string mac = null, string mode = "single")` | Single-primitive constructor |
| `Encryptor.mixed(primitives, keyBits, mac)` / `Encryptor.mixed3(primitives, keyBits, mac)` | Mixed-primitive Single / Triple |
| `enc.encrypt(pt) / decrypt(ct) / encryptAuth(pt) / decryptAuth(ct)` | Cipher entry points |
| `enc.setNonceBits / setBarrierFill / setBitSoup / setLockSoup / setLockSeed / setChunkSize` | Per-instance setters |
| `enc.primitive / macName / keyBits / mode / nonceBits / headerSize / hasPRFKeys / isMixed / seedCount` | Accessors |
| `enc.prfKey(slot) / macKey() / seedComponents(slot)` | Key-material accessors |
| `enc.exportState() / importState(blob)` | State-blob persistence |
| `EasyConfig peekConfig(const(ubyte)[] blob)` / `string lastMismatchField()` | Pre-import discriminator + mismatch-field accessor |
| `enc.close()` | Release encryptor |

### Streaming AEAD (`itb.streams`)

| Symbol | Purpose |
|---|---|
| `StreamEncryptor / StreamDecryptor / StreamEncryptor3 / StreamDecryptor3` | Push-style Low-Level streamers |
| `StreamEncryptorAuth / StreamDecryptorAuth / StreamEncryptorAuth3 / StreamDecryptorAuth3` | Push-style Streaming AEAD streamers |
| `encryptStream / decryptStream / encryptStreamTriple / decryptStreamTriple` | Free-function bridges (Low-Level No MAC) |
| `encryptStreamAuth / decryptStreamAuth / encryptStreamAuthTriple / decryptStreamAuthTriple` | Free-function bridges (Streaming AEAD) |
| `DEFAULT_CHUNK_SIZE` | Default streaming chunk size in bytes |

### Native Blob (`itb.blob`)

| Symbol | Purpose |
|---|---|
| `Blob128 / Blob256 / Blob512` | Width-specific Native Blob handles |
| `blob.setKey / setComponents / setMacKey / setMacName(...)` | Field setters |
| `blob.getKey / getComponents / getMacKey / getMacName(...)` | Field getters |
| `blob.exportState(opts) / exportStateTriple(opts) / importState(payload) / importStateTriple(payload)` | Serialisation |
| `BlobSlot.N / D / S / L / D1 / D2 / D3 / S1 / S2 / S3` | Slot enum |
| `BlobOpt.None / LockSeed / Mac` / `slotFromName(string)` | Export opt-in flags + name → slot helper |

### Wrapper (`itb.wrapper`)

| Symbol | Purpose |
|---|---|
| `Cipher.aes128ctr / chacha20 / siphash24` | Cipher enum |
| `CIPHER_NAMES` | Canonical name list |
| `string ffiName(Cipher c)` / `Cipher cipherFromName(string s)` | Enum ↔ string converters |
| `size_t keySize(Cipher c)` / `size_t nonceSize(Cipher c)` | Cipher dimension accessors |
| `ubyte[] wrapperGenerateKey(Cipher c)` | CSPRNG-fresh wrapper key |
| `ubyte[] wrap(Cipher c, const(ubyte)[] key, const(ubyte)[] blob)` / `ubyte[] unwrap(...)` | Single Message Wrap / Unwrap |
| `ubyte[] wrapInPlace(Cipher c, const(ubyte)[] key, ubyte[] buf)` / `ubyte[] unwrapInPlace(...)` | In-place Wrap / Unwrap |
| `WrapStreamWriter / UnwrapStreamReader` | Streaming wrap writer / unwrap reader |
| `WrapperError / WrapperInvalidCipherError / WrapperInvalidKeyError / WrapperInvalidNonceError / WrapperHandleClosedError` | Typed exceptions |

### Error model (`itb.errors`)

| Symbol | Purpose |
|---|---|
| `ITBError` | Base exception class; `.statusCode` carries the numeric status |
| `ITBEasyMismatchError / ITBBlobModeMismatchError / ITBBlobMalformedError / ITBBlobVersionTooNewError` | Typed subclasses for cold-path discriminators |
| `ITBStreamTruncatedError / ITBStreamAfterFinalError` | Streaming AEAD transcript-shape exceptions |
| `Status` (enum, `itb.status`) | Status-code surface |
