/// Easy Mode Single-Ouroboros benchmarks for the D binding.
///
/// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for
/// PRF-grade primitives, locked at 1024-bit ITB key width and
/// 16 MiB CSPRNG-filled payload. One mixed-primitive variant
/// (`Encryptor.newMixed` + dedicated lockSeed) covers the
/// Easy Mode Mixed surface alongside the single-primitive grid.
///
/// Run with:
///
/// ---
/// dub build :single --compiler=dmd --build=release
/// ./bench/bin/itb-bench-single
///
/// ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./bench/bin/itb-bench-single
/// ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-single
///
/// ITB_BENCH_FILTER=blake3_encrypt ./bench/bin/itb-bench-single
/// ---
///
/// The harness emits one Go-bench-style line per case (name, iters,
/// ns/op, MB/s). See `bench.common` for the supported environment
/// variables and the convergence policy.
module bench.bench_single;

import std.format : format;
import std.stdio : writeln;

import itb : Encryptor, setMaxWorkers, setNonceBits;

import bench.common :
    BenchCase,
    BenchFn,
    PAYLOAD_16MB,
    PRIMITIVES_CANONICAL,
    envFilter,
    envLockBatch,
    envLockSeed,
    envMinSeconds,
    envNonceBits,
    measureAndPrint,
    randomBytes;

// Mixed-primitive composition used by the Mixed Single bench cases.
// noise / data / start cycle through the BLAKE family while
// Areion takes the dedicated lockSeed slot - every name
// resolves to a 256-bit native hash width so the Encryptor.newMixed
// width-check passes.
private enum string MIXED_NOISE = "blake3";
private enum string MIXED_DATA = "blake2s";
private enum string MIXED_START = "blake2b256";
private enum string MIXED_LOCK = "areion256";

private enum int KEY_BITS = 1024;
private enum string MAC_NAME = "hmac-blake3";
private enum size_t PAYLOAD_BYTES = PAYLOAD_16MB;

// Heap-resident registry of bench encryptors so each closure can
// reach its Encryptor through a stable pointer. Encryptors are
// non-copyable in D (`@disable this(this)`) so the closure must
// reference them rather than capture by value.
private struct EncBox { Encryptor enc; }

private EncBox*[] _encryptorRegistry;

/// Apply the dedicated lockSeed slot when `ITB_LOCKSEED` is set. Easy
/// Mode auto-couples BitSoup + LockSoup as a side effect, so no
/// separate calls are issued.
private void applyLockSeedIfRequested(Encryptor* enc) @trusted
{
    if (envLockSeed())
        enc.setLockSeed(1);
}

/// Apply the Lock Batch performance mode when `ITB_LOCKBATCH` is set.
/// Inert unless Lock Soup is engaged via `ITB_LOCKSEED`.
private void applyLockBatchIfRequested(Encryptor* enc) @trusted
{
    if (envLockBatch())
        enc.setLockBatch(1);
}

/// Construct a single-primitive 1024-bit Single-Ouroboros encryptor
/// with HMAC-BLAKE3 authentication. Stored on the heap-resident
/// registry so the closure can reach it through a stable pointer.
private EncBox* buildSingle(string primitive) @trusted
{
    auto box = new EncBox;
    box.enc = Encryptor(primitive, KEY_BITS, MAC_NAME, 1);
    applyLockSeedIfRequested(&box.enc);
    applyLockBatchIfRequested(&box.enc);
    _encryptorRegistry ~= box;
    return box;
}

/// Construct a mixed-primitive Single-Ouroboros encryptor matching
/// the README Quick Start composition (BLAKE3 noise / BLAKE2s data /
/// BLAKE2b-256 start). The dedicated lockSeed slot
/// is allocated only when `ITB_LOCKSEED` is set, so the no-LockSeed
/// bench arm measures the plain mixed-primitive cost without the
/// BitSoup + LockSoup auto-couple. The four primitive names share
/// the 256-bit native hash width.
private EncBox* buildMixedSingle() @trusted
{
    // When `primL` is set, newMixed auto-couples BitSoup + LockSoup
    // on construction; an extra setLockSeed call would be a
    // redundant no-op against the already-active lockSeed slot.
    // When `primL` is null the encryptor stays in plain mixed mode.
    string primL = envLockSeed() ? MIXED_LOCK : null;
    auto box = new EncBox;
    box.enc = Encryptor.newMixed(
        MIXED_NOISE, MIXED_DATA, MIXED_START,
        primL, KEY_BITS, MAC_NAME);
    _encryptorRegistry ~= box;
    return box;
}

/// Build a plain-Encrypt bench case. Encryptor + payload are
/// constructed once outside the measured loop; only the encrypt call
/// is timed.
private BenchCase makeEncryptCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encrypt(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build a plain-Decrypt bench case. Pre-encrypts a single
/// ciphertext outside the measured loop; only the decrypt call is
/// timed.
private BenchCase makeDecryptCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    auto ciphertext = box.enc.encrypt(payload).dup;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.decrypt(ciphertext);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build an authenticated-Encrypt bench case (MAC tag attached).
private BenchCase makeEncryptAuthCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encryptAuth(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build an authenticated-Decrypt bench case (MAC tag verified on
/// the way back).
private BenchCase makeDecryptAuthCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    auto ciphertext = box.enc.encryptAuth(payload).dup;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.decryptAuth(ciphertext);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// One lazy factory entry: case name + a delegate that builds the
/// BenchCase on demand. Factories are called one at a time just
/// before measurement so peak RSS is bounded to roughly one case.
private alias CaseFactory = BenchCase delegate() @trusted;
private struct LazyEntry { string name; CaseFactory factory; }

// ────────────────────────────────────────────────────────────────────
// Per-primitive factory helpers.
//
// D closures capture variables by reference (heap-allocated when the
// closure escapes the stack). In a `foreach` loop the compiler reuses
// the same heap cell for the same variable name across all iterations,
// so every closure ends up referencing the last iteration's value.
// Wrapping each closure in a function that receives `string` by value
// forces a fresh copy per call-site, giving each returned delegate its
// own binding.
// ────────────────────────────────────────────────────────────────────

private LazyEntry singleEncFac(string n, string p) @trusted
{ return LazyEntry(n, () @trusted { return makeEncryptCase(n, buildSingle(p)); }); }

private LazyEntry singleDecFac(string n, string p) @trusted
{ return LazyEntry(n, () @trusted { return makeDecryptCase(n, buildSingle(p)); }); }

private LazyEntry singleEncAuthFac(string n, string p) @trusted
{ return LazyEntry(n, () @trusted { return makeEncryptAuthCase(n, buildSingle(p)); }); }

private LazyEntry singleDecAuthFac(string n, string p) @trusted
{ return LazyEntry(n, () @trusted { return makeDecryptAuthCase(n, buildSingle(p)); }); }

/// Assemble the full lazy factory list: 9 single-primitive entries ×
/// 4 ops plus 1 mixed entry × 4 ops = 40 message cases, plus 8
/// streaming cases appended at the end. Each factory builds one
/// BenchCase on demand.
private LazyEntry[] buildLazyFactories() @trusted
{
    LazyEntry[] facs;
    facs.reserve(48);
    foreach (prim; PRIMITIVES_CANONICAL)
    {
        string p = prim;
        string bp = format("bench_single_%s_%dbit", p, KEY_BITS);
        string en  = format("%s_encrypt_16mb", bp);
        string dn  = format("%s_decrypt_16mb", bp);
        string ean = format("%s_encrypt_auth_16mb", bp);
        string dan = format("%s_decrypt_auth_16mb", bp);
        facs ~= singleEncFac(en,   p);
        facs ~= singleDecFac(dn,   p);
        facs ~= singleEncAuthFac(ean, p);
        facs ~= singleDecAuthFac(dan, p);
    }
    string bm  = format("bench_single_mixed_%dbit", KEY_BITS);
    string men  = format("%s_encrypt_16mb", bm);
    string mdn  = format("%s_decrypt_16mb", bm);
    string mean = format("%s_encrypt_auth_16mb", bm);
    string mdan = format("%s_decrypt_auth_16mb", bm);
    facs ~= LazyEntry(men,  () @trusted { return makeEncryptCase(men,  buildMixedSingle()); });
    facs ~= LazyEntry(mdn,  () @trusted { return makeDecryptCase(mdn,  buildMixedSingle()); });
    facs ~= LazyEntry(mean, () @trusted { return makeEncryptAuthCase(mean, buildMixedSingle()); });
    facs ~= LazyEntry(mdan, () @trusted { return makeDecryptAuthCase(mdan, buildMixedSingle()); });
    appendStreamLazySingle(facs);
    return facs;
}

void main() @trusted
{
    import std.algorithm : filter;
    import std.array : array;

    int nonceBits = envNonceBits(128);
    setMaxWorkers(0);
    setNonceBits(nonceBits);

    writeln(format(
        "# easy_single primitives=%d key_bits=%d mac=%s nonce_bits=%d lockseed=%s workers=auto",
        PRIMITIVES_CANONICAL.length,
        KEY_BITS,
        MAC_NAME,
        nonceBits,
        envLockSeed() ? "on" : "off"));

    auto facs = buildLazyFactories();
    string flt = envFilter();
    double minSeconds = envMinSeconds();

    import std.stdio : stderr;
    LazyEntry[] selected;
    if (flt is null)
        selected = facs;
    else
        foreach (ref e; facs)
            if (e.name.length >= flt.length)
            {
                // simple substring scan
                bool found = false;
                foreach (i; 0 .. e.name.length - flt.length + 1)
                    if (e.name[i .. i + flt.length] == flt) { found = true; break; }
                if (found)
                    selected ~= e;
            }

    if (selected.length == 0)
    {
        import std.stdio : stderr;
        string[] names;
        foreach (ref e; facs) names ~= e.name;
        stderr.writefln(
            "no bench cases match filter %s; available: %s",
            flt is null ? "<unset>" : flt, names);
        return;
    }

    writeln(format("# benchmarks=%d payload_bytes=%d min_seconds=%g",
        selected.length, PAYLOAD_BYTES, minSeconds));
    foreach (ref e; selected)
    {
        auto c = e.factory();
        measureAndPrint(c, minSeconds);
    }
}

// ────────────────────────────────────────────────────────────────────
// Streaming benchmarks (Single Ouroboros).
//
// Eight cases exercising the full Single-Ouroboros streaming matrix
// at 64 MiB total payload / 16 MiB chunk size under areion512 + 1024
// bit ITB key + hmac-blake3 MAC:
//
//     | Mode      | Op      | Variant   |
//     |-----------|---------|-----------|
//     | Easy      | Encrypt | AEAD IO   |
//     | Easy      | Encrypt | UserLoop  |
//     | Easy      | Decrypt | AEAD IO   |
//     | Easy      | Decrypt | UserLoop  |
//     | Low-Level | Encrypt | AEAD IO   |
//     | Low-Level | Encrypt | UserLoop  |
//     | Low-Level | Decrypt | AEAD IO   |
//     | Low-Level | Decrypt | UserLoop  |
//
// AEAD IO  — Streaming AEAD over reader / writer delegates. Easy:
//            Encryptor.encryptStreamAuth / decryptStreamAuth. Low-
//            Level: itb.streams.encryptStreamAuth / decryptStreamAuth
//            free functions over (noise, data, start, mac).
//
// UserLoop — plain Streaming via caller-side per-chunk loop; framing
//            convention is a 4-byte big-endian ciphertext-length
//            prefix preceding each chunk's ciphertext bytes (matching
//            the canonical pattern in tmp/itb_examples/dlang/main.d).
//            Easy uses Encryptor.encrypt / decrypt; Low-Level uses
//            the itb.cipher.encrypt / decrypt free functions.
//
// Setup discipline: 64 MiB CSPRNG fill, Encryptor / Seed / MAC
// construction, and (for Decrypt cases) the pre-encryption all run
// outside the timer. Each measured iteration walks fresh reader /
// writer delegate state over the prepared inputs and tears them
// down.
// ────────────────────────────────────────────────────────────────────

import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import std.exception : enforce;

import itb.cipher : encrypt, decrypt;
import itb.mac : MAC;
import itb.seed : Seed;
import itb.streams :
    encryptStreamAuth,
    decryptStreamAuth;

private enum string STREAM_PRIMITIVE = "areion512";
private enum size_t STREAM_TOTAL_BYTES = 64UL << 20;
private enum size_t STREAM_CHUNK_BYTES = 16UL << 20;

// Fixed 32-byte MAC key matches the 32-byte hmac-blake3 key length
// codified. Value contents are immaterial for throughput measurement;
//the MAC executes in O(MAC-key-length) per absorb regardless of byte distribution.
private static immutable ubyte[32] STREAM_MAC_KEY = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

// Heap-resident Low-Level Single Ouroboros bench state. Holds three
// non-copyable Seeds plus one non-copyable MAC behind a stable
// pointer so closures can reference the handles without moving the
// underlying structs. Mirrors the `EncBox` pattern (D struct + closure
// non-copyable workaround).
private struct StreamLowSingleBox
{
    Seed noise;
    Seed data;
    Seed start;
    MAC  mac;
}

private StreamLowSingleBox*[] _streamSingleRegistry;

private StreamLowSingleBox* buildStreamSingleLow() @trusted
{
    auto box = new StreamLowSingleBox;
    box.noise = Seed(STREAM_PRIMITIVE, KEY_BITS);
    box.data  = Seed(STREAM_PRIMITIVE, KEY_BITS);
    box.start = Seed(STREAM_PRIMITIVE, KEY_BITS);
    box.mac   = MAC(MAC_NAME, STREAM_MAC_KEY[]);
    _streamSingleRegistry ~= box;
    return box;
}

private EncBox* buildStreamSingleEasy() @trusted
{
    auto box = new EncBox;
    box.enc = Encryptor(STREAM_PRIMITIVE, KEY_BITS, MAC_NAME, 1);
    applyLockSeedIfRequested(&box.enc);
    applyLockBatchIfRequested(&box.enc);
    _encryptorRegistry ~= box;
    return box;
}

/// Frames a single chunk of ciphertext under the UserLoop convention:
/// 4-byte big-endian ciphertext-length prefix followed by the
/// ciphertext bytes.
private void frameChunk(ref ubyte[] sink, const(ubyte)[] ct) @trusted
{
    ubyte[4] hdr = nativeToBigEndian!uint(cast(uint) ct.length);
    sink ~= hdr[];
    sink ~= ct;
}

/// Easy AEAD IO encrypt: per iter, walks the prepared payload via
/// `Encryptor.encryptStreamAuth` over fresh delegate state.
private BenchCase makeEasyStreamEncryptAeadIoCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    EncBox* box = buildStreamSingleEasy();
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            size_t pos = 0;
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            size_t reader(ubyte[] buf) @trusted
            {
                if (pos >= payload.length)
                    return 0;
                size_t take = (payload.length - pos) < buf.length
                    ? (payload.length - pos)
                    : buf.length;
                buf[0 .. take] = payload[pos .. pos + take];
                pos += take;
                return take;
            }
            void writer(const(ubyte)[] d) @trusted { sink ~= d; }
            box.enc.encryptStreamAuth(&reader, &writer, STREAM_CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Easy AEAD IO decrypt: pre-encrypts once, then per iter decrypts
/// the stored transcript through `Encryptor.decryptStreamAuth`.
private BenchCase makeEasyStreamDecryptAeadIoCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    EncBox* box = buildStreamSingleEasy();
    ubyte[] transcript;
    transcript.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    {
        size_t pos = 0;
        size_t reader(ubyte[] buf) @trusted
        {
            if (pos >= payload.length) return 0;
            size_t take = (payload.length - pos) < buf.length
                ? (payload.length - pos) : buf.length;
            buf[0 .. take] = payload[pos .. pos + take];
            pos += take;
            return take;
        }
        void writer(const(ubyte)[] d) @trusted { transcript ~= d; }
        box.enc.encryptStreamAuth(&reader, &writer, STREAM_CHUNK_BYTES);
    }
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            size_t pos = 0;
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES);
            size_t reader(ubyte[] buf) @trusted
            {
                if (pos >= transcript.length) return 0;
                size_t take = (transcript.length - pos) < buf.length
                    ? (transcript.length - pos) : buf.length;
                buf[0 .. take] = transcript[pos .. pos + take];
                pos += take;
                return take;
            }
            void writer(const(ubyte)[] d) @trusted { sink ~= d; }
            box.enc.decryptStreamAuth(&reader, &writer, STREAM_CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Easy UserLoop encrypt: per iter, walks the plaintext in 16 MiB
/// chunks and emits 4-byte BE-length-prefixed ciphertexts via
/// `Encryptor.encrypt`.
private BenchCase makeEasyStreamEncryptUserLoopCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    EncBox* box = buildStreamSingleEasy();
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            size_t off = 0;
            while (off < payload.length)
            {
                size_t end = off + STREAM_CHUNK_BYTES;
                if (end > payload.length) end = payload.length;
                auto ct = box.enc.encrypt(payload[off .. end]);
                frameChunk(sink, ct);
                off = end;
            }
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Easy UserLoop decrypt: pre-frames the transcript once, then per
/// iter parses the framing and calls `Encryptor.decrypt` per chunk.
private BenchCase makeEasyStreamDecryptUserLoopCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    EncBox* box = buildStreamSingleEasy();
    ubyte[] transcript;
    transcript.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    {
        size_t off = 0;
        while (off < payload.length)
        {
            size_t end = off + STREAM_CHUNK_BYTES;
            if (end > payload.length) end = payload.length;
            auto ct = box.enc.encrypt(payload[off .. end]);
            frameChunk(transcript, ct.dup);
            off = end;
        }
    }
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES);
            size_t pos = 0;
            while (pos + 4 <= transcript.length)
            {
                ubyte[4] hdr = transcript[pos .. pos + 4][0 .. 4];
                uint n = bigEndianToNative!uint(hdr);
                pos += 4;
                enforce(pos + n <= transcript.length,
                    "easy UserLoop decrypt: short ciphertext read");
                auto pt = box.enc.decrypt(transcript[pos .. pos + n]);
                sink ~= pt;
                pos += n;
            }
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Low-Level AEAD IO encrypt: per iter, runs
/// `itb.streams.encryptStreamAuth` over the (noise, data, start, mac)
/// handles + fresh delegate state.
private BenchCase makeLowLevelStreamEncryptAeadIoCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    StreamLowSingleBox* box = buildStreamSingleLow();
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            size_t pos = 0;
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            size_t reader(ubyte[] buf) @trusted
            {
                if (pos >= payload.length) return 0;
                size_t take = (payload.length - pos) < buf.length
                    ? (payload.length - pos) : buf.length;
                buf[0 .. take] = payload[pos .. pos + take];
                pos += take;
                return take;
            }
            void writer(const(ubyte)[] d) @trusted { sink ~= d; }
            encryptStreamAuth(box.noise, box.data, box.start, box.mac,
                &reader, &writer, STREAM_CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Low-Level AEAD IO decrypt: pre-encrypts once with the same seeds /
/// MAC, then per iter walks the transcript through
/// `itb.streams.decryptStreamAuth`.
private BenchCase makeLowLevelStreamDecryptAeadIoCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    StreamLowSingleBox* box = buildStreamSingleLow();
    ubyte[] transcript;
    transcript.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    {
        size_t pos = 0;
        size_t reader(ubyte[] buf) @trusted
        {
            if (pos >= payload.length) return 0;
            size_t take = (payload.length - pos) < buf.length
                ? (payload.length - pos) : buf.length;
            buf[0 .. take] = payload[pos .. pos + take];
            pos += take;
            return take;
        }
        void writer(const(ubyte)[] d) @trusted { transcript ~= d; }
        encryptStreamAuth(box.noise, box.data, box.start, box.mac,
            &reader, &writer, STREAM_CHUNK_BYTES);
    }
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            size_t pos = 0;
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES);
            size_t reader(ubyte[] buf) @trusted
            {
                if (pos >= transcript.length) return 0;
                size_t take = (transcript.length - pos) < buf.length
                    ? (transcript.length - pos) : buf.length;
                buf[0 .. take] = transcript[pos .. pos + take];
                pos += take;
                return take;
            }
            void writer(const(ubyte)[] d) @trusted { sink ~= d; }
            decryptStreamAuth(box.noise, box.data, box.start, box.mac,
                &reader, &writer, STREAM_CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Low-Level UserLoop encrypt: per iter, walks the plaintext in
/// 16 MiB chunks and frames each ciphertext via `itb.cipher.encrypt`.
private BenchCase makeLowLevelStreamEncryptUserLoopCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    StreamLowSingleBox* box = buildStreamSingleLow();
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
            size_t off = 0;
            while (off < payload.length)
            {
                size_t end = off + STREAM_CHUNK_BYTES;
                if (end > payload.length) end = payload.length;
                auto ct = encrypt(box.noise, box.data, box.start,
                    payload[off .. end]);
                frameChunk(sink, ct);
                off = end;
            }
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Low-Level UserLoop decrypt: pre-frames the transcript once, then
/// per iter walks the framing and calls `itb.cipher.decrypt` per
/// chunk.
private BenchCase makeLowLevelStreamDecryptUserLoopCase(string name) @trusted
{
    auto payload = randomBytes(STREAM_TOTAL_BYTES);
    StreamLowSingleBox* box = buildStreamSingleLow();
    ubyte[] transcript;
    transcript.reserve(STREAM_TOTAL_BYTES + (STREAM_TOTAL_BYTES >> 3));
    {
        size_t off = 0;
        while (off < payload.length)
        {
            size_t end = off + STREAM_CHUNK_BYTES;
            if (end > payload.length) end = payload.length;
            auto ct = encrypt(box.noise, box.data, box.start,
                payload[off .. end]);
            frameChunk(transcript, ct);
            off = end;
        }
    }
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] sink;
            sink.reserve(STREAM_TOTAL_BYTES);
            size_t pos = 0;
            while (pos + 4 <= transcript.length)
            {
                ubyte[4] hdr = transcript[pos .. pos + 4][0 .. 4];
                uint n = bigEndianToNative!uint(hdr);
                pos += 4;
                enforce(pos + n <= transcript.length,
                    "low-level UserLoop decrypt: short ciphertext read");
                auto pt = decrypt(box.noise, box.data, box.start,
                    transcript[pos .. pos + n]);
                sink ~= pt;
                pos += n;
            }
        }
    };
    return BenchCase(name, run, STREAM_TOTAL_BYTES);
}

/// Appends the eight Single-Ouroboros streaming lazy factory entries to
/// the running factory list. Naming convention:
///
///     bench_single_stream_<primitive>_<bits>bit_64mb_<mode>_<op>_<variant>
///
/// where `mode ∈ {easy, lowlevel}`, `op ∈ {encrypt, decrypt}`,
/// `variant ∈ {aead_io, userloop}`. Order is mode-major /
/// variant-minor / op-minor for filter-friendly grouping.
private void appendStreamLazySingle(ref LazyEntry[] facs) @trusted
{
    string base = format("bench_single_stream_%s_%dbit_64mb",
        STREAM_PRIMITIVE, KEY_BITS);
    string n0 = format("%s_easy_encrypt_aead_io", base);
    string n1 = format("%s_easy_decrypt_aead_io", base);
    string n2 = format("%s_easy_encrypt_userloop", base);
    string n3 = format("%s_easy_decrypt_userloop", base);
    string n4 = format("%s_lowlevel_encrypt_aead_io", base);
    string n5 = format("%s_lowlevel_decrypt_aead_io", base);
    string n6 = format("%s_lowlevel_encrypt_userloop", base);
    string n7 = format("%s_lowlevel_decrypt_userloop", base);
    facs ~= LazyEntry(n0, () @trusted { return makeEasyStreamEncryptAeadIoCase(n0); });
    facs ~= LazyEntry(n1, () @trusted { return makeEasyStreamDecryptAeadIoCase(n1); });
    facs ~= LazyEntry(n2, () @trusted { return makeEasyStreamEncryptUserLoopCase(n2); });
    facs ~= LazyEntry(n3, () @trusted { return makeEasyStreamDecryptUserLoopCase(n3); });
    facs ~= LazyEntry(n4, () @trusted { return makeLowLevelStreamEncryptAeadIoCase(n4); });
    facs ~= LazyEntry(n5, () @trusted { return makeLowLevelStreamDecryptAeadIoCase(n5); });
    facs ~= LazyEntry(n6, () @trusted { return makeLowLevelStreamEncryptUserLoopCase(n6); });
    facs ~= LazyEntry(n7, () @trusted { return makeLowLevelStreamDecryptUserLoopCase(n7); });
}
