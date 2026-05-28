// End-to-end D binding tests for the high-level itb.Encryptor surface.
//
// Mirrors bindings/rust/tests/test_easy_roundtrip.rs one-to-one:
// lifecycle (close / drop / handle invalidation), structural validation
// (bad primitive / MAC / keyBits / mode), full-matrix round-trips for
// both Single and Triple Ouroboros, and per-instance configuration
// setters that mutate only the local Config copy without touching
// libitb's process-global state.
//
// No tests are skipped from the Rust source — every Rust case maps
// cleanly onto the D surface.

import std.exception : collectException;
import std.random : Random, uniform;
import std.stdio : writefln;

import itb;

private struct HashRow { string name; int width; }

private static immutable HashRow[] CANONICAL_HASHES = [
    HashRow("areion256", 256),
    HashRow("areion512", 512),
    HashRow("blake2b256", 256),
    HashRow("blake2b512", 512),
    HashRow("blake2s", 256),
    HashRow("blake3", 256),
    HashRow("aescmac", 128),
    HashRow("siphash24", 128),
    HashRow("chacha20", 256),
];

private int[] keyBitsFor(int width)
{
    int[] out_;
    foreach (kb; [512, 1024, 2048])
        if (kb % width == 0)
            out_ ~= kb;
    return out_;
}

private Random rng;
static this() { rng = Random(0xF00DCAFEU); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

// ─── Lifecycle ─────────────────────────────────────────────────────

void testNewAndFree()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    assert(enc.handle() != 0);
    assert(enc.primitive() == "blake3");
    assert(enc.keyBits() == 1024);
    assert(enc.mode() == 1);
    assert(enc.macName() == "kmac256");
    enc.close();
}

void testDropReleasesHandle()
{
    // D analogue of the Rust drop / Python context-manager test — the
    // destructor calls ITB_Easy_Free when the encryptor leaves scope.
    {
        auto enc = Encryptor("areion256", 1024, "kmac256", 1);
        assert(enc.handle() != 0);
    } // destructor here; libitb-side handle released
}

void testCloseThenMethodRaises()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.close();
    auto err = collectException!ITBError(
        enc.encrypt(cast(const(ubyte)[]) "after close"));
    assert(err !is null, "encrypt after close must throw");
    assert(err.statusCode == Status.EasyClosed,
        "expected EasyClosed, got status code on encrypt-after-close");
}

void testDefaults()
{
    // null primitive / 0 keyBits / null mac select libitb's defaults
    // (areion512 / 1024) plus the binding-side mac override to
    // hmac-blake3 (the lightest-overhead MAC the Easy Mode surface
    // ships with).
    auto enc = Encryptor(null, 0, null, 1);
    assert(enc.primitive() == "areion512");
    assert(enc.keyBits() == 1024);
    assert(enc.mode() == 1);
    assert(enc.macName() == "hmac-blake3");
}

void testBadPrimitive()
{
    auto err = collectException!ITBError(
        Encryptor("nonsense-hash", 1024, "kmac256", 1));
    assert(err !is null, "bad primitive must throw");
}

void testBadMac()
{
    auto err = collectException!ITBError(
        Encryptor("blake3", 1024, "nonsense-mac", 1));
    assert(err !is null, "bad mac must throw");
}

void testBadKeyBits()
{
    foreach (bits; [256, 511, 999, 2049])
    {
        auto err = collectException!ITBError(
            Encryptor("blake3", bits, "kmac256", 1));
        assert(err !is null, "key_bits must be rejected");
    }
}

void testBadMode()
{
    auto err = collectException!ITBError(
        Encryptor("blake3", 1024, "kmac256", 2));
    assert(err !is null, "mode=2 must be rejected");
    assert(err.statusCode == Status.BadInput,
        "bad mode must surface as Status.BadInput");
}

// ─── Roundtrip Single ──────────────────────────────────────────────

void testAllHashesAllWidthsSingle()
{
    auto plaintext = tokenBytes(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (kb; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, kb, "kmac256", 1);
            auto ct = enc.encrypt(plaintext).dup;
            assert(ct.length > plaintext.length,
                "ciphertext must be longer than plaintext");
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext, "single roundtrip mismatch");
        }
    }
}

void testAllHashesAllWidthsSingleAuth()
{
    auto plaintext = tokenBytes(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (kb; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, kb, "kmac256", 1);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext, "single auth roundtrip mismatch");
        }
    }
}

void testSliceInputRoundtrip()
{
    // D analogue of the Rust slice / Python bytearray + memoryview
    // tests — `const(ubyte)[]` is the canonical input shape.
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    ubyte[] payload = cast(ubyte[]) "hello bytearray".dup;
    auto ct = enc.encrypt(payload[]).dup;
    auto pt = enc.decrypt(ct[]).dup;
    assert(pt == payload, "slice-input roundtrip mismatch");
}

// ─── Roundtrip Triple ──────────────────────────────────────────────

void testAllHashesAllWidthsTriple()
{
    auto plaintext = tokenBytes(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (kb; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, kb, "kmac256", 3);
            auto ct = enc.encrypt(plaintext).dup;
            assert(ct.length > plaintext.length,
                "triple ciphertext must be longer than plaintext");
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext, "triple roundtrip mismatch");
        }
    }
}

void testAllHashesAllWidthsTripleAuth()
{
    auto plaintext = tokenBytes(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (kb; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, kb, "kmac256", 3);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext, "triple auth roundtrip mismatch");
        }
    }
}

void testSeedCountReflectsMode()
{
    auto enc1 = Encryptor("blake3", 1024, "kmac256", 1);
    assert(enc1.seedCount() == 3);
    auto enc3 = Encryptor("blake3", 1024, "kmac256", 3);
    assert(enc3.seedCount() == 7);
}

// ─── Per-instance configuration ───────────────────────────────────

void testSetBitSoup()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.setBitSoup(1);
    auto ct = enc.encrypt(cast(const(ubyte)[]) "bit-soup payload").dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == cast(const(ubyte)[]) "bit-soup payload",
        "bit-soup roundtrip mismatch");
}

void testSetLockSoupCouplesBitSoup()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.setLockSoup(1);
    auto ct = enc.encrypt(cast(const(ubyte)[]) "lock-soup payload").dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == cast(const(ubyte)[]) "lock-soup payload",
        "lock-soup roundtrip mismatch");
}

void testSetLockSeedGrowsSeedCount()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    assert(enc.seedCount() == 3);
    enc.setLockSeed(1);
    assert(enc.seedCount() == 4, "lockSeed must grow seedCount to 4");
    auto ct = enc.encrypt(cast(const(ubyte)[]) "lockseed payload").dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == cast(const(ubyte)[]) "lockseed payload",
        "lockSeed roundtrip mismatch");
}

void testSetLockSeedAfterEncryptRejected()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    cast(void) enc.encrypt(cast(const(ubyte)[]) "first").dup;
    auto err = collectException!ITBError(enc.setLockSeed(1));
    assert(err !is null, "setLockSeed after encrypt must throw");
    assert(err.statusCode == Status.EasyLockSeedAfterEncrypt,
        "expected EasyLockSeedAfterEncrypt status");
}

void testSetNonceBitsValidation()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    foreach (valid; [128, 256, 512])
        enc.setNonceBits(valid);
    foreach (bad; [0, 1, 192, 1024])
    {
        auto err = collectException!ITBError(enc.setNonceBits(bad));
        assert(err !is null, "bad nonce bits must throw");
        assert(err.statusCode == Status.BadInput,
            "bad nonce bits must surface as Status.BadInput");
    }
}

void testSetBarrierFillValidation()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    foreach (valid; [1, 2, 4, 8, 16, 32])
        enc.setBarrierFill(valid);
    foreach (bad; [0, 3, 5, 7, 64])
    {
        auto err = collectException!ITBError(enc.setBarrierFill(bad));
        assert(err !is null, "bad barrier fill must throw");
        assert(err.statusCode == Status.BadInput,
            "bad barrier fill must surface as Status.BadInput");
    }
}

void testSetChunkSizeAccepted()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.setChunkSize(1024);
    enc.setChunkSize(0);
}

void testTwoEncryptorsIsolated()
{
    // Setting LockSoup on one encryptor must not bleed into another;
    // per-instance Config snapshots are independent.
    auto a = Encryptor("blake3", 1024, "kmac256", 1);
    auto b = Encryptor("blake3", 1024, "kmac256", 1);
    a.setLockSoup(1);
    auto ctA = a.encrypt(cast(const(ubyte)[]) "a").dup;
    assert(a.decrypt(ctA).dup == cast(const(ubyte)[]) "a",
        "encryptor a self-roundtrip mismatch");
    auto ctB = b.encrypt(cast(const(ubyte)[]) "b").dup;
    assert(b.decrypt(ctB).dup == cast(const(ubyte)[]) "b",
        "encryptor b self-roundtrip mismatch");
}

void main()
{
    testNewAndFree();
    testDropReleasesHandle();
    testCloseThenMethodRaises();
    testDefaults();
    testBadPrimitive();
    testBadMac();
    testBadKeyBits();
    testBadMode();
    testAllHashesAllWidthsSingle();
    testAllHashesAllWidthsSingleAuth();
    testSliceInputRoundtrip();
    testAllHashesAllWidthsTriple();
    testAllHashesAllWidthsTripleAuth();
    testSeedCountReflectsMode();
    testSetBitSoup();
    testSetLockSoupCouplesBitSoup();
    testSetLockSeedGrowsSeedCount();
    testSetLockSeedAfterEncryptRejected();
    testSetNonceBitsValidation();
    testSetBarrierFillValidation();
    testSetChunkSizeAccepted();
    testTwoEncryptorsIsolated();
    writefln("test_easy_roundtrip: ALL OK");
}
