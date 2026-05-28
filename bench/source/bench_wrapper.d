/// Format-deniability wrapper benchmarks for the D binding.
///
/// Mirrors `wrapper/bench_test.go` on the Go-native side and
/// `bindings/{python,rust,csharp,nodejs}/.../bench_wrapper*` on the
/// peer-binding side. Eighteen wrapper only round-trip cases (16 MiB
/// random blob through `wrap` / `wrapInPlace` per outer cipher) plus
/// 288 full-ITB cases split across:
///
///   * Message Single Ouroboros — 4 modes × every cipher × 2 directions.
///   * Message Triple Ouroboros — 4 modes × every cipher × 2 directions.
///   * Streaming Single Ouroboros — 4 modes × every cipher × 2 directions.
///   * Streaming Triple Ouroboros — 4 modes × every cipher × 2 directions.
///
/// Total: 18 + 288 = **306 sub-benches** when run end-to-end.
///
/// Streaming sub-benches do NOT include `noaead-*-io` cells. The D
/// binding's Non-AEAD streaming surface is User-Driven Loop only —
/// there is no `OutputRange` / `InputRange` adapter pair for the
/// Non-AEAD case. The Streaming AEAD path (Easy + Low-Level)
/// covers the IO-Driven delegate / reader / writer surface; the
/// Non-AEAD streaming column is the User-Driven Loop variant.
///
/// Run with:
///
/// ---
/// dub build :wrapper --compiler=dmd --build=release
/// ./bench/bin/itb-bench-wrapper
///
/// ITB_BENCH_FILTER=bench_wrapper_only \
///     ./bench/bin/itb-bench-wrapper
///
/// ITB_BENCH_FILTER=bench_msg_triple \
///     ./bench/bin/itb-bench-wrapper
/// ---
///
/// Naming discipline: streaming = "Streaming
/// AEAD" / "Streaming Easy" / "Streaming Low-Level"; modes = "Easy" /
/// "Low-Level" / "MAC Authenticated" / "No MAC" / "Single Ouroboros" /
/// "Triple Ouroboros"; outer cipher arms = AES-128-CTR / ChaCha20 /
/// SipHash-CTR.
module bench.bench_wrapper;

import std.bitmanip : nativeToLittleEndian, littleEndianToNative;
import std.format : format;
import std.stdio : writeln;

import itb;
import itb.cipher : encrypt, decrypt, encryptAuth, decryptAuth,
    encryptTriple, decryptTriple, encryptAuthTriple, decryptAuthTriple;
import itb.mac : MAC;
import itb.seed : Seed;
import itb.streams :
    encryptStreamAuth, decryptStreamAuth,
    encryptStreamAuthTriple, decryptStreamAuthTriple;
import itb.wrapper :
    Cipher, CIPHER_NAMES, ffiName,
    keySize, nonceSize, wrapperGenerateKey,
    wrap, unwrap, wrapInPlace, unwrapInPlace,
    WrapStreamWriter, UnwrapStreamReader;

import bench.common :
    BenchCase, BenchFn,
    randomBytes,
    measureAndPrint, envFilter, envMinSeconds;

private enum string PRIMITIVE = "areion512";
private enum int KEY_BITS = 1024;
private enum string MAC_NAME = "hmac-blake3";

// 16 MiB single-message payload, 64 MiB streaming payload, 16 MiB
// chunk size — matches every peer binding's wrapper-bench surface.
private enum size_t MSG_BYTES    = 16UL << 20;
private enum size_t STREAM_BYTES = 64UL << 20;
private enum size_t CHUNK_BYTES  = 16UL << 20;

// Fixed 32-byte MAC key — bench harness discipline; value contents
// are immaterial for throughput measurement.
private static immutable ubyte[32] MAC_KEY = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];

// ────────────────────────────────────────────────────────────────────
// Heap-resident registries — closures capture pointers rather than
// non-copyable struct values. Mirrors the EncBox pattern in
// bench_single / bench_triple.
// ────────────────────────────────────────────────────────────────────

private struct EncBox { Encryptor enc; }
private struct SeedBox
{
    Seed noise;
    Seed data;
    Seed start;
    MAC  mac;
}
private struct Seed3Box
{
    Seed noise;
    Seed data1, data2, data3;
    Seed start1, start2, start3;
    MAC  mac;
}

private EncBox*[] _encRegistry;
private SeedBox*[] _seedRegistry;
private Seed3Box*[] _seed3Registry;

private EncBox* makeEncryptor(int mode, bool authMac) @trusted
{
    auto box = new EncBox;
    box.enc = Encryptor(PRIMITIVE, KEY_BITS, authMac ? MAC_NAME : null, mode);
    _encRegistry ~= box;
    return box;
}

private SeedBox* makeSeed1(bool authMac) @trusted
{
    auto box = new SeedBox;
    box.noise = Seed(PRIMITIVE, KEY_BITS);
    box.data  = Seed(PRIMITIVE, KEY_BITS);
    box.start = Seed(PRIMITIVE, KEY_BITS);
    if (authMac)
        box.mac = MAC(MAC_NAME, MAC_KEY[]);
    _seedRegistry ~= box;
    return box;
}

private Seed3Box* makeSeed3(bool authMac) @trusted
{
    auto box = new Seed3Box;
    box.noise = Seed(PRIMITIVE, KEY_BITS);
    box.data1 = Seed(PRIMITIVE, KEY_BITS);
    box.data2 = Seed(PRIMITIVE, KEY_BITS);
    box.data3 = Seed(PRIMITIVE, KEY_BITS);
    box.start1 = Seed(PRIMITIVE, KEY_BITS);
    box.start2 = Seed(PRIMITIVE, KEY_BITS);
    box.start3 = Seed(PRIMITIVE, KEY_BITS);
    if (authMac)
        box.mac = MAC(MAC_NAME, MAC_KEY[]);
    _seed3Registry ~= box;
    return box;
}

// ────────────────────────────────────────────────────────────────────
// Wrapper Only round-trip (16 MiB random blob, no ITB call).
//
// Three outer ciphers × two surfaces (`wrap` allocating + `wrapInPlace`
// no output-buffer alloc) = 6 sub-benches. Round-trip = encrypt + decrypt timed
// together because the keystream cipher is symmetric (same XOR pass
// reverses).
// ────────────────────────────────────────────────────────────────────

private BenchCase makeWrapperOnlyAlloc(string name, Cipher cipher) @trusted
{
    auto blob = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wrap(cipher, key, blob);
            cast(void) unwrap(cipher, key, wire);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeWrapperOnlyInPlace(string name, Cipher cipher) @trusted
{
    auto plaintext = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    immutable size_t nlen = nonceSize(cipher);
    // Pre-encrypt plaintext into wire once (untimed) so the timed loop
    // alternates UnwrapInPlace → WrapInPlace on the same buffer with no
    // per-iteration memcpy. Mirrors the Go-native pattern at
    // wrapper/bench_test.go::BenchmarkWrapperOnlyInPlace.
    auto wire = new ubyte[](nlen + plaintext.length);
    wire[nlen .. nlen + plaintext.length] = plaintext[];
    auto nonceSetup = wrapInPlace(cipher, key, wire[nlen .. $]);
    wire[0 .. nlen] = nonceSetup[];
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            cast(void) unwrapInPlace(cipher, key, wire);
            auto newNonce = wrapInPlace(cipher, key, wire[nlen .. $]);
            wire[0 .. nlen] = newNonce[];
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

// ────────────────────────────────────────────────────────────────────
// Single-message ITB + wrapper sub-benches.
//
// 4 modes × every cipher × 2 directions, per Ouroboros. The
// modes are:
//
//   * Easy No MAC                -> Encryptor.encrypt / decrypt
//   * Easy MAC Authenticated     -> Encryptor.encryptAuth / decryptAuth
//   * Low-Level No MAC           -> itb.cipher.encrypt / decrypt
//   * Low-Level MAC Authenticated-> itb.cipher.encryptAuth / decryptAuth
// ────────────────────────────────────────────────────────────────────

// --- Encrypt direction ---------------------------------------------

private BenchCase makeMsgEasyNoMACEncSingle(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(1, false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = box.enc.encrypt(pt).dup;
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgEasyAuthEncSingle(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(1, true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = box.enc.encryptAuth(pt).dup;
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowNoMACEncSingle(string name, Cipher cipher) @trusted
{
    auto box = makeSeed1(false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = encrypt(box.noise, box.data, box.start, pt);
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowAuthEncSingle(string name, Cipher cipher) @trusted
{
    auto box = makeSeed1(true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = encryptAuth(box.noise, box.data, box.start, box.mac, pt);
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

// --- Decrypt direction ---------------------------------------------

private BenchCase makeMsgEasyNoMACDecSingle(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(1, false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = box.enc.encrypt(pt).dup;
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) box.enc.decrypt(recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgEasyAuthDecSingle(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(1, true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = box.enc.encryptAuth(pt).dup;
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) box.enc.decryptAuth(recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowNoMACDecSingle(string name, Cipher cipher) @trusted
{
    auto box = makeSeed1(false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = encrypt(box.noise, box.data, box.start, pt);
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) decrypt(box.noise, box.data, box.start, recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowAuthDecSingle(string name, Cipher cipher) @trusted
{
    auto box = makeSeed1(true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = encryptAuth(box.noise, box.data, box.start, box.mac, pt);
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) decryptAuth(box.noise, box.data, box.start, box.mac, recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

// ────────────────────────────────────────────────────────────────────
// Triple Ouroboros message variants — 7-seed Triple wrapped against
// 4 modes × every cipher × 2 directions.
// ────────────────────────────────────────────────────────────────────

private BenchCase makeMsgEasyNoMACEncTriple(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(3, false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = box.enc.encrypt(pt).dup;
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgEasyAuthEncTriple(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(3, true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = box.enc.encryptAuth(pt).dup;
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowNoMACEncTriple(string name, Cipher cipher) @trusted
{
    auto box = makeSeed3(false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = encryptTriple(box.noise,
                box.data1, box.data2, box.data3,
                box.start1, box.start2, box.start3, pt);
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowAuthEncTriple(string name, Cipher cipher) @trusted
{
    auto box = makeSeed3(true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto blob = encryptAuthTriple(box.noise,
                box.data1, box.data2, box.data3,
                box.start1, box.start2, box.start3, box.mac, pt);
            cast(void) wrapInPlace(cipher, key, blob);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgEasyNoMACDecTriple(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(3, false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = box.enc.encrypt(pt).dup;
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) box.enc.decrypt(recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgEasyAuthDecTriple(string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(3, true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = box.enc.encryptAuth(pt).dup;
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) box.enc.decryptAuth(recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowNoMACDecTriple(string name, Cipher cipher) @trusted
{
    auto box = makeSeed3(false);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = encryptTriple(box.noise,
        box.data1, box.data2, box.data3,
        box.start1, box.start2, box.start3, pt);
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) decryptTriple(box.noise,
                box.data1, box.data2, box.data3,
                box.start1, box.start2, box.start3, recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

private BenchCase makeMsgLowAuthDecTriple(string name, Cipher cipher) @trusted
{
    auto box = makeSeed3(true);
    auto pt = randomBytes(MSG_BYTES);
    auto key = wrapperGenerateKey(cipher);
    auto blob = encryptAuthTriple(box.noise,
        box.data1, box.data2, box.data3,
        box.start1, box.start2, box.start3, box.mac, pt);
    auto nonce = wrapInPlace(cipher, key, blob);
    ubyte[] wirePristine;
    wirePristine ~= nonce;
    wirePristine ~= blob;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            auto recovered = unwrapInPlace(cipher, key, wire);
            cast(void) decryptAuthTriple(box.noise,
                box.data1, box.data2, box.data3,
                box.start1, box.start2, box.start3, box.mac, recovered);
        }
    };
    return BenchCase(name, run, MSG_BYTES);
}

// ────────────────────────────────────────────────────────────────────
// Streaming sub-benches.
//
// Per-Ouroboros: 4 modes × every cipher × 2 directions.
// The four streaming modes:
//
//   * Streaming AEAD Easy   IO-Driven (Encryptor.encryptStreamAuth /
//                            decryptStreamAuth + WrapStreamWriter /
//                            UnwrapStreamReader).
//   * Streaming AEAD Low-Level IO-Driven (free function
//                            encryptStreamAuth / decryptStreamAuth +
//                            WrapStreamWriter / UnwrapStreamReader).
//   * Streaming Easy        No MAC, User-Driven Loop (Encryptor.encrypt
//                            per chunk + u32_LE_len framing through
//                            WrapStreamWriter).
//   * Streaming Low-Level   No MAC, User-Driven Loop (free-function
//                            encrypt per chunk + u32_LE_len framing).
//
// `noaead-*-io` cells are absent — the D Non-AEAD streaming surface
// is User-Driven Loop only.
// ────────────────────────────────────────────────────────────────────

// --- Streaming AEAD Easy IO-Driven (encrypt) -----------------------

private BenchCase makeStreamAeadEasyEnc(int mode, string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(mode, true);
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] wireBuf;
            auto ww = WrapStreamWriter(cipher, key);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;
            size_t readOff = 0;
            size_t reader(ubyte[] buf) @trusted
            {
                if (readOff >= payload.length) return 0;
                size_t take = (payload.length - readOff < buf.length)
                              ? payload.length - readOff : buf.length;
                buf[0 .. take] = payload[readOff .. readOff + take];
                readOff += take;
                return take;
            }
            void writer(const(ubyte)[] chunk) @trusted
            {
                wireBuf ~= ww.update(chunk);
            }
            box.enc.encryptStreamAuth(&reader, &writer, CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

private BenchCase makeStreamAeadEasyDec(int mode, string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(mode, true);
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);

    // Pre-compute the wrapped wire once outside the timer.
    ubyte[] wirePristine;
    {
        auto ww = WrapStreamWriter(cipher, key);
        scope(exit) ww.close();
        wirePristine ~= ww.nonce;
        size_t readOff = 0;
        size_t reader(ubyte[] buf) @trusted
        {
            if (readOff >= payload.length) return 0;
            size_t take = (payload.length - readOff < buf.length)
                          ? payload.length - readOff : buf.length;
            buf[0 .. take] = payload[readOff .. readOff + take];
            readOff += take;
            return take;
        }
        void writer(const(ubyte)[] chunk) @trusted
        {
            wirePristine ~= ww.update(chunk);
        }
        box.enc.encryptStreamAuth(&reader, &writer, CHUNK_BYTES);
    }

    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            size_t nlen = nonceSize(cipher);
            auto ur = UnwrapStreamReader(cipher, key, wire[0 .. nlen]);
            scope(exit) ur.close();
            auto decryptedAccum = ur.update(wire[nlen .. $]);
            size_t readOff = 0;
            size_t reader(ubyte[] buf) @trusted
            {
                if (readOff >= decryptedAccum.length) return 0;
                size_t take = (decryptedAccum.length - readOff < buf.length)
                              ? decryptedAccum.length - readOff : buf.length;
                buf[0 .. take] = decryptedAccum[readOff .. readOff + take];
                readOff += take;
                return take;
            }
            void writer(const(ubyte)[] chunk) @trusted { /* sink */ }
            box.enc.decryptStreamAuth(&reader, &writer, CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

// --- Streaming AEAD Low-Level IO-Driven ----------------------------

private void aeadLowEncryptToWire(SeedBox* box, Seed3Box* box3, bool triple,
    const(ubyte)[] payload, ref WrapStreamWriter ww, ref ubyte[] wireBuf,
    size_t chunkSize) @trusted
{
    size_t readOff = 0;
    size_t reader(ubyte[] buf) @trusted
    {
        if (readOff >= payload.length) return 0;
        size_t take = (payload.length - readOff < buf.length)
                      ? payload.length - readOff : buf.length;
        buf[0 .. take] = payload[readOff .. readOff + take];
        readOff += take;
        return take;
    }
    void writer(const(ubyte)[] chunk) @trusted
    {
        wireBuf ~= ww.update(chunk);
    }
    if (triple)
    {
        encryptStreamAuthTriple(box3.noise,
            box3.data1, box3.data2, box3.data3,
            box3.start1, box3.start2, box3.start3,
            box3.mac, &reader, &writer, chunkSize);
    }
    else
    {
        encryptStreamAuth(box.noise, box.data, box.start, box.mac,
            &reader, &writer, chunkSize);
    }
}

private BenchCase makeStreamAeadLowEnc(bool triple, string name, Cipher cipher) @trusted
{
    SeedBox* box1 = triple ? null : makeSeed1(true);
    Seed3Box* box3 = triple ? makeSeed3(true) : null;
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] wireBuf;
            auto ww = WrapStreamWriter(cipher, key);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;
            aeadLowEncryptToWire(box1, box3, triple, payload, ww, wireBuf, CHUNK_BYTES);
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

private BenchCase makeStreamAeadLowDec(bool triple, string name, Cipher cipher) @trusted
{
    SeedBox* box1 = triple ? null : makeSeed1(true);
    Seed3Box* box3 = triple ? makeSeed3(true) : null;
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);

    ubyte[] wirePristine;
    {
        auto ww = WrapStreamWriter(cipher, key);
        scope(exit) ww.close();
        wirePristine ~= ww.nonce;
        aeadLowEncryptToWire(box1, box3, triple, payload, ww, wirePristine, CHUNK_BYTES);
    }

    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            size_t nlen = nonceSize(cipher);
            auto ur = UnwrapStreamReader(cipher, key, wire[0 .. nlen]);
            scope(exit) ur.close();
            auto decryptedAccum = ur.update(wire[nlen .. $]);
            size_t readOff = 0;
            size_t reader(ubyte[] buf) @trusted
            {
                if (readOff >= decryptedAccum.length) return 0;
                size_t take = (decryptedAccum.length - readOff < buf.length)
                              ? decryptedAccum.length - readOff : buf.length;
                buf[0 .. take] = decryptedAccum[readOff .. readOff + take];
                readOff += take;
                return take;
            }
            void writer(const(ubyte)[] chunk) @trusted { /* sink */ }
            if (triple)
            {
                decryptStreamAuthTriple(box3.noise,
                    box3.data1, box3.data2, box3.data3,
                    box3.start1, box3.start2, box3.start3,
                    box3.mac, &reader, &writer, CHUNK_BYTES);
            }
            else
            {
                decryptStreamAuth(box1.noise, box1.data, box1.start, box1.mac,
                    &reader, &writer, CHUNK_BYTES);
            }
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

// --- Streaming No MAC User-Driven Loop (Easy) ----------------------

private BenchCase makeStreamUserloopEasyEnc(int mode, string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(mode, false);
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] wireBuf;
            auto ww = WrapStreamWriter(cipher, key);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;
            size_t off = 0;
            while (off < payload.length)
            {
                size_t take = (payload.length - off < CHUNK_BYTES)
                              ? payload.length - off : CHUNK_BYTES;
                auto ct = box.enc.encrypt(payload[off .. off + take]).dup;
                ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
                wireBuf ~= ww.update(lenBytes[]);
                wireBuf ~= ww.update(ct);
                off += take;
            }
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

private BenchCase makeStreamUserloopEasyDec(int mode, string name, Cipher cipher) @trusted
{
    auto box = makeEncryptor(mode, false);
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);

    ubyte[] wirePristine;
    {
        auto ww = WrapStreamWriter(cipher, key);
        scope(exit) ww.close();
        wirePristine ~= ww.nonce;
        size_t off = 0;
        while (off < payload.length)
        {
            size_t take = (payload.length - off < CHUNK_BYTES)
                          ? payload.length - off : CHUNK_BYTES;
            auto ct = box.enc.encrypt(payload[off .. off + take]).dup;
            ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
            wirePristine ~= ww.update(lenBytes[]);
            wirePristine ~= ww.update(ct);
            off += take;
        }
    }

    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            size_t nlen = nonceSize(cipher);
            auto ur = UnwrapStreamReader(cipher, key, wire[0 .. nlen]);
            scope(exit) ur.close();
            auto decryptedAll = ur.update(wire[nlen .. $]);
            size_t pos = 0;
            while (pos < decryptedAll.length)
            {
                ubyte[4] lenBytes = decryptedAll[pos .. pos + 4][0 .. 4];
                uint clen = littleEndianToNative!uint(lenBytes);
                pos += 4;
                cast(void) box.enc.decrypt(decryptedAll[pos .. pos + clen]);
                pos += clen;
            }
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

// --- Streaming No MAC User-Driven Loop (Low-Level) -----------------

private BenchCase makeStreamUserloopLowEnc(bool triple, string name, Cipher cipher) @trusted
{
    SeedBox* box1 = triple ? null : makeSeed1(false);
    Seed3Box* box3 = triple ? makeSeed3(false) : null;
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            ubyte[] wireBuf;
            auto ww = WrapStreamWriter(cipher, key);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;
            size_t off = 0;
            while (off < payload.length)
            {
                size_t take = (payload.length - off < CHUNK_BYTES)
                              ? payload.length - off : CHUNK_BYTES;
                ubyte[] ct;
                if (triple)
                {
                    ct = encryptTriple(box3.noise,
                        box3.data1, box3.data2, box3.data3,
                        box3.start1, box3.start2, box3.start3,
                        payload[off .. off + take]);
                }
                else
                {
                    ct = encrypt(box1.noise, box1.data, box1.start,
                        payload[off .. off + take]);
                }
                ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
                wireBuf ~= ww.update(lenBytes[]);
                wireBuf ~= ww.update(ct);
                off += take;
            }
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

private BenchCase makeStreamUserloopLowDec(bool triple, string name, Cipher cipher) @trusted
{
    SeedBox* box1 = triple ? null : makeSeed1(false);
    Seed3Box* box3 = triple ? makeSeed3(false) : null;
    auto payload = randomBytes(STREAM_BYTES);
    auto key = wrapperGenerateKey(cipher);

    ubyte[] wirePristine;
    {
        auto ww = WrapStreamWriter(cipher, key);
        scope(exit) ww.close();
        wirePristine ~= ww.nonce;
        size_t off = 0;
        while (off < payload.length)
        {
            size_t take = (payload.length - off < CHUNK_BYTES)
                          ? payload.length - off : CHUNK_BYTES;
            ubyte[] ct;
            if (triple)
            {
                ct = encryptTriple(box3.noise,
                    box3.data1, box3.data2, box3.data3,
                    box3.start1, box3.start2, box3.start3,
                    payload[off .. off + take]);
            }
            else
            {
                ct = encrypt(box1.noise, box1.data, box1.start,
                    payload[off .. off + take]);
            }
            ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
            wirePristine ~= ww.update(lenBytes[]);
            wirePristine ~= ww.update(ct);
            off += take;
        }
    }

    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
        {
            auto wire = wirePristine.dup;
            size_t nlen = nonceSize(cipher);
            auto ur = UnwrapStreamReader(cipher, key, wire[0 .. nlen]);
            scope(exit) ur.close();
            auto decryptedAll = ur.update(wire[nlen .. $]);
            size_t pos = 0;
            while (pos < decryptedAll.length)
            {
                ubyte[4] lenBytes = decryptedAll[pos .. pos + 4][0 .. 4];
                uint clen = littleEndianToNative!uint(lenBytes);
                pos += 4;
                if (triple)
                {
                    cast(void) decryptTriple(box3.noise,
                        box3.data1, box3.data2, box3.data3,
                        box3.start1, box3.start2, box3.start3,
                        decryptedAll[pos .. pos + clen]);
                }
                else
                {
                    cast(void) decrypt(box1.noise, box1.data, box1.start,
                        decryptedAll[pos .. pos + clen]);
                }
                pos += clen;
            }
        }
    };
    return BenchCase(name, run, STREAM_BYTES);
}

// ────────────────────────────────────────────────────────────────────
// Case-list assembly.
// ────────────────────────────────────────────────────────────────────

private void appendWrapperOnly(ref BenchCase[] cases) @trusted
{
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        cases ~= makeWrapperOnlyAlloc(
            format("bench_wrapper_only_alloc_%s_16mb", cn), cipher);
        cases ~= makeWrapperOnlyInPlace(
            format("bench_wrapper_only_inplace_%s_16mb", cn), cipher);
    }
}

private void appendMessageSingle(ref BenchCase[] cases) @trusted
{
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        cases ~= makeMsgEasyNoMACEncSingle(
            format("bench_msg_single_easy_nomac_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyNoMACDecSingle(
            format("bench_msg_single_easy_nomac_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyAuthEncSingle(
            format("bench_msg_single_easy_auth_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyAuthDecSingle(
            format("bench_msg_single_easy_auth_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgLowNoMACEncSingle(
            format("bench_msg_single_low_nomac_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgLowNoMACDecSingle(
            format("bench_msg_single_low_nomac_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgLowAuthEncSingle(
            format("bench_msg_single_low_auth_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgLowAuthDecSingle(
            format("bench_msg_single_low_auth_%s_decrypt_16mb", cn), cipher);
    }
}

private void appendMessageTriple(ref BenchCase[] cases) @trusted
{
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        cases ~= makeMsgEasyNoMACEncTriple(
            format("bench_msg_triple_easy_nomac_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyNoMACDecTriple(
            format("bench_msg_triple_easy_nomac_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyAuthEncTriple(
            format("bench_msg_triple_easy_auth_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgEasyAuthDecTriple(
            format("bench_msg_triple_easy_auth_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgLowNoMACEncTriple(
            format("bench_msg_triple_low_nomac_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgLowNoMACDecTriple(
            format("bench_msg_triple_low_nomac_%s_decrypt_16mb", cn), cipher);
        cases ~= makeMsgLowAuthEncTriple(
            format("bench_msg_triple_low_auth_%s_encrypt_16mb", cn), cipher);
        cases ~= makeMsgLowAuthDecTriple(
            format("bench_msg_triple_low_auth_%s_decrypt_16mb", cn), cipher);
    }
}

private void appendStreamSingle(ref BenchCase[] cases) @trusted
{
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        cases ~= makeStreamAeadEasyEnc(1,
            format("bench_stream_single_aead_easy_io_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadEasyDec(1,
            format("bench_stream_single_aead_easy_io_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadLowEnc(false,
            format("bench_stream_single_aead_low_io_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadLowDec(false,
            format("bench_stream_single_aead_low_io_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopEasyEnc(1,
            format("bench_stream_single_easy_userloop_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopEasyDec(1,
            format("bench_stream_single_easy_userloop_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopLowEnc(false,
            format("bench_stream_single_low_userloop_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopLowDec(false,
            format("bench_stream_single_low_userloop_%s_decrypt_64mb", cn), cipher);
    }
}

private void appendStreamTriple(ref BenchCase[] cases) @trusted
{
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        cases ~= makeStreamAeadEasyEnc(3,
            format("bench_stream_triple_aead_easy_io_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadEasyDec(3,
            format("bench_stream_triple_aead_easy_io_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadLowEnc(true,
            format("bench_stream_triple_aead_low_io_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamAeadLowDec(true,
            format("bench_stream_triple_aead_low_io_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopEasyEnc(3,
            format("bench_stream_triple_easy_userloop_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopEasyDec(3,
            format("bench_stream_triple_easy_userloop_%s_decrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopLowEnc(true,
            format("bench_stream_triple_low_userloop_%s_encrypt_64mb", cn), cipher);
        cases ~= makeStreamUserloopLowDec(true,
            format("bench_stream_triple_low_userloop_%s_decrypt_64mb", cn), cipher);
    }
}

// ────────────────────────────────────────────────────────────────────
// Lazy factory list.
//
// Each entry is a (name, factory) pair.  The factory is a zero-arg
// delegate that allocates the payload + context and returns exactly
// one BenchCase.  Building the list is O(1) in memory; each factory
// is called immediately before timing and the resulting BenchCase is
// discarded after the measurement, bounding peak RSS to roughly one
// case at a time.
// ────────────────────────────────────────────────────────────────────

private alias CaseFac = BenchCase delegate() @trusted;

private struct LazyCase
{
    string  name;
    CaseFac factory;
}

// ────────────────────────────────────────────────────────────────────
// Per-cipher factory helpers.
//
// D closures capture variables by reference (heap-allocated when the
// closure escapes the stack). In a `foreach` loop the compiler reuses
// the same heap cell for the same variable name across all iterations,
// so every closure ends up referencing the last iteration's value.
// Wrapping each closure in a function that receives `Cipher` by value
// forces a fresh copy per call-site, giving each returned delegate its
// own binding.
// ────────────────────────────────────────────────────────────────────

private LazyCase wrapOnlyAllocFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeWrapperOnlyAlloc(n, c)); }

private LazyCase wrapOnlyInPlaceFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeWrapperOnlyInPlace(n, c)); }

private LazyCase msgEasyNoMACEncSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyNoMACEncSingle(n, c)); }

private LazyCase msgEasyNoMACDecSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyNoMACDecSingle(n, c)); }

private LazyCase msgEasyAuthEncSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyAuthEncSingle(n, c)); }

private LazyCase msgEasyAuthDecSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyAuthDecSingle(n, c)); }

private LazyCase msgLowNoMACEncSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowNoMACEncSingle(n, c)); }

private LazyCase msgLowNoMACDecSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowNoMACDecSingle(n, c)); }

private LazyCase msgLowAuthEncSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowAuthEncSingle(n, c)); }

private LazyCase msgLowAuthDecSingleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowAuthDecSingle(n, c)); }

private LazyCase msgEasyNoMACEncTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyNoMACEncTriple(n, c)); }

private LazyCase msgEasyNoMACDecTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyNoMACDecTriple(n, c)); }

private LazyCase msgEasyAuthEncTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyAuthEncTriple(n, c)); }

private LazyCase msgEasyAuthDecTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgEasyAuthDecTriple(n, c)); }

private LazyCase msgLowNoMACEncTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowNoMACEncTriple(n, c)); }

private LazyCase msgLowNoMACDecTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowNoMACDecTriple(n, c)); }

private LazyCase msgLowAuthEncTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowAuthEncTriple(n, c)); }

private LazyCase msgLowAuthDecTripleFac(string n, Cipher c) @trusted
{ return LazyCase(n, () => makeMsgLowAuthDecTriple(n, c)); }

private LazyCase streamAeadEasyEncFac(int mode, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamAeadEasyEnc(mode, n, c)); }

private LazyCase streamAeadEasyDecFac(int mode, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamAeadEasyDec(mode, n, c)); }

private LazyCase streamAeadLowEncFac(bool triple, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamAeadLowEnc(triple, n, c)); }

private LazyCase streamAeadLowDecFac(bool triple, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamAeadLowDec(triple, n, c)); }

private LazyCase streamUserloopEasyEncFac(int mode, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamUserloopEasyEnc(mode, n, c)); }

private LazyCase streamUserloopEasyDecFac(int mode, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamUserloopEasyDec(mode, n, c)); }

private LazyCase streamUserloopLowEncFac(bool triple, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamUserloopLowEnc(triple, n, c)); }

private LazyCase streamUserloopLowDecFac(bool triple, string n, Cipher c) @trusted
{ return LazyCase(n, () => makeStreamUserloopLowDec(triple, n, c)); }

private LazyCase[] buildLazyFactories() @trusted
{
    LazyCase[] facs;
    facs.reserve(306);

    // Wrapper Only — 2 per cipher across every cipher in the palette.
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        facs ~= wrapOnlyAllocFac(
            format("bench_wrapper_only_alloc_%s_16mb", cn), cipher);
        facs ~= wrapOnlyInPlaceFac(
            format("bench_wrapper_only_inplace_%s_16mb", cn), cipher);
    }

    // Message Single — 4 modes × every cipher × 2 dirs.
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        facs ~= msgEasyNoMACEncSingleFac(
            format("bench_msg_single_easy_nomac_%s_encrypt_16mb", cn), cipher);
        facs ~= msgEasyNoMACDecSingleFac(
            format("bench_msg_single_easy_nomac_%s_decrypt_16mb", cn), cipher);
        facs ~= msgEasyAuthEncSingleFac(
            format("bench_msg_single_easy_auth_%s_encrypt_16mb", cn), cipher);
        facs ~= msgEasyAuthDecSingleFac(
            format("bench_msg_single_easy_auth_%s_decrypt_16mb", cn), cipher);
        facs ~= msgLowNoMACEncSingleFac(
            format("bench_msg_single_low_nomac_%s_encrypt_16mb", cn), cipher);
        facs ~= msgLowNoMACDecSingleFac(
            format("bench_msg_single_low_nomac_%s_decrypt_16mb", cn), cipher);
        facs ~= msgLowAuthEncSingleFac(
            format("bench_msg_single_low_auth_%s_encrypt_16mb", cn), cipher);
        facs ~= msgLowAuthDecSingleFac(
            format("bench_msg_single_low_auth_%s_decrypt_16mb", cn), cipher);
    }

    // Message Triple — 4 modes × every cipher × 2 dirs.
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        facs ~= msgEasyNoMACEncTripleFac(
            format("bench_msg_triple_easy_nomac_%s_encrypt_16mb", cn), cipher);
        facs ~= msgEasyNoMACDecTripleFac(
            format("bench_msg_triple_easy_nomac_%s_decrypt_16mb", cn), cipher);
        facs ~= msgEasyAuthEncTripleFac(
            format("bench_msg_triple_easy_auth_%s_encrypt_16mb", cn), cipher);
        facs ~= msgEasyAuthDecTripleFac(
            format("bench_msg_triple_easy_auth_%s_decrypt_16mb", cn), cipher);
        facs ~= msgLowNoMACEncTripleFac(
            format("bench_msg_triple_low_nomac_%s_encrypt_16mb", cn), cipher);
        facs ~= msgLowNoMACDecTripleFac(
            format("bench_msg_triple_low_nomac_%s_decrypt_16mb", cn), cipher);
        facs ~= msgLowAuthEncTripleFac(
            format("bench_msg_triple_low_auth_%s_encrypt_16mb", cn), cipher);
        facs ~= msgLowAuthDecTripleFac(
            format("bench_msg_triple_low_auth_%s_decrypt_16mb", cn), cipher);
    }

    // Streaming Single — 4 modes × every cipher × 2 dirs.
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        facs ~= streamAeadEasyEncFac(1,
            format("bench_stream_single_aead_easy_io_%s_encrypt_64mb", cn), cipher);
        facs ~= streamAeadEasyDecFac(1,
            format("bench_stream_single_aead_easy_io_%s_decrypt_64mb", cn), cipher);
        facs ~= streamAeadLowEncFac(false,
            format("bench_stream_single_aead_low_io_%s_encrypt_64mb", cn), cipher);
        facs ~= streamAeadLowDecFac(false,
            format("bench_stream_single_aead_low_io_%s_decrypt_64mb", cn), cipher);
        facs ~= streamUserloopEasyEncFac(1,
            format("bench_stream_single_easy_userloop_%s_encrypt_64mb", cn), cipher);
        facs ~= streamUserloopEasyDecFac(1,
            format("bench_stream_single_easy_userloop_%s_decrypt_64mb", cn), cipher);
        facs ~= streamUserloopLowEncFac(false,
            format("bench_stream_single_low_userloop_%s_encrypt_64mb", cn), cipher);
        facs ~= streamUserloopLowDecFac(false,
            format("bench_stream_single_low_userloop_%s_decrypt_64mb", cn), cipher);
    }

    // Streaming Triple — 4 modes × every cipher × 2 dirs.
    foreach (cipher; CIPHER_NAMES)
    {
        string cn = ffiName(cipher);
        facs ~= streamAeadEasyEncFac(3,
            format("bench_stream_triple_aead_easy_io_%s_encrypt_64mb", cn), cipher);
        facs ~= streamAeadEasyDecFac(3,
            format("bench_stream_triple_aead_easy_io_%s_decrypt_64mb", cn), cipher);
        facs ~= streamAeadLowEncFac(true,
            format("bench_stream_triple_aead_low_io_%s_encrypt_64mb", cn), cipher);
        facs ~= streamAeadLowDecFac(true,
            format("bench_stream_triple_aead_low_io_%s_decrypt_64mb", cn), cipher);
        facs ~= streamUserloopEasyEncFac(3,
            format("bench_stream_triple_easy_userloop_%s_encrypt_64mb", cn), cipher);
        facs ~= streamUserloopEasyDecFac(3,
            format("bench_stream_triple_easy_userloop_%s_decrypt_64mb", cn), cipher);
        facs ~= streamUserloopLowEncFac(true,
            format("bench_stream_triple_low_userloop_%s_encrypt_64mb", cn), cipher);
        facs ~= streamUserloopLowDecFac(true,
            format("bench_stream_triple_low_userloop_%s_decrypt_64mb", cn), cipher);
    }

    return facs;
}

void main() @trusted
{
    setMaxWorkers(0);
    setNonceBits(128);

    auto facs = buildLazyFactories();

    writeln(format(
        "# wrapper bench primitive=%s key_bits=%d mac=%s msg_bytes=%d stream_bytes=%d cases=%d",
        PRIMITIVE, KEY_BITS, MAC_NAME, MSG_BYTES, STREAM_BYTES, facs.length));

    // Filter + header line.
    string flt = envFilter();
    double minSeconds = envMinSeconds();

    string[] allNames;
    allNames.length = facs.length;
    foreach (i, ref lc; facs)
        allNames[i] = lc.name;

    LazyCase[] selected;
    if (flt is null)
        selected = facs;
    else
        foreach (ref lc; facs)
            if (lc.name.length >= flt.length)
            {
                import std.algorithm : canFind;
                if (lc.name.canFind(flt))
                    selected ~= lc;
            }

    if (selected.length == 0)
    {
        import std.stdio : stderr;
        stderr.writefln("no bench cases match filter %s; available: %s",
            flt is null ? "<unset>" : flt, allNames);
        return;
    }

    writeln(format("# benchmarks=%d min_seconds=%g", selected.length, minSeconds));

    // Lazy loop: build one case, measure it, drop it.
    foreach (ref lc; selected)
    {
        auto bc = lc.factory();
        measureAndPrint(bc, minSeconds);
    }
}
