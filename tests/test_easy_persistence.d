// Cross-process persistence round-trip tests for the high-level
// itb.Encryptor surface.
//
// The exportState / importState / peekConfig triplet is the
// persistence surface required for any deployment where encrypt and
// decrypt run in different processes (network, storage, backup,
// microservices). Without the JSON-encoded blob captured at
// encrypt-side and re-supplied at decrypt-side, the encryptor state
// cannot be reconstructed and the ciphertext is unreadable.
//
// Mirrors bindings/rust/tests/test_easy_persistence.rs one-to-one.

import std.exception : collectException;
import std.stdio : writeln;

import itb;

private struct HashRow { string name; int width; }

private static immutable HashRow[] CANONICAL_HASHES = [
    HashRow("areion256", 256),
    HashRow("areion512", 512),
    HashRow("siphash24", 128),
    HashRow("aescmac", 128),
    HashRow("blake2b256", 256),
    HashRow("blake2b512", 512),
    HashRow("blake2s", 256),
    HashRow("blake3", 256),
    HashRow("chacha20", 256),
];

private size_t expectedPrfKeyLen(string name)
{
    switch (name)
    {
        case "areion256":  return 32;
        case "areion512":  return 64;
        case "siphash24":  return 0;
        case "aescmac":    return 16;
        case "blake2b256": return 32;
        case "blake2b512": return 64;
        case "blake2s":    return 32;
        case "blake3":     return 32;
        case "chacha20":   return 32;
        default: assert(false, "unknown hash " ~ name);
    }
}

private int[] keyBitsFor(int width)
{
    int[] out_;
    foreach (kb; [512, 1024, 2048])
        if (kb % width == 0)
            out_ ~= kb;
    return out_;
}

private ubyte[] canonicalPlaintextSingle()
{
    ubyte[] v = (cast(ubyte[]) "any binary data, including 0x00 bytes -- ".dup);
    foreach (i; 0 .. 256)
        v ~= cast(ubyte) i;
    return v;
}

private ubyte[] canonicalPlaintextTriple()
{
    ubyte[] v = (cast(ubyte[]) "triple-mode persistence payload ".dup);
    foreach (i; 0 .. 64)
        v ~= cast(ubyte) i;
    return v;
}

// ─── TestPersistenceRoundtrip ──────────────────────────────────────

void testRoundtripAllHashesSingle()
{
    auto plaintext = canonicalPlaintextSingle();
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBitsVal; keyBitsFor(h.width))
        {
            // Day 1 — random encryptor.
            ubyte[] blob;
            ubyte[] ct;
            {
                auto src = Encryptor(h.name, keyBitsVal, "kmac256", 1);
                blob = src.exportState().dup;
                ct = src.encryptAuth(plaintext).dup;
            }
            // Day 2 — restore from saved blob.
            auto dst = Encryptor(h.name, keyBitsVal, "kmac256", 1);
            dst.importState(blob);
            auto pt = dst.decryptAuth(ct).dup;
            assert(pt == plaintext,
                "Single persistence roundtrip mismatch for " ~ h.name);
        }
    }
}

void testRoundtripAllHashesTriple()
{
    auto plaintext = canonicalPlaintextTriple();
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBitsVal; keyBitsFor(h.width))
        {
            ubyte[] blob;
            ubyte[] ct;
            {
                auto src = Encryptor(h.name, keyBitsVal, "kmac256", 3);
                blob = src.exportState().dup;
                ct = src.encryptAuth(plaintext).dup;
            }
            auto dst = Encryptor(h.name, keyBitsVal, "kmac256", 3);
            dst.importState(blob);
            auto pt = dst.decryptAuth(ct).dup;
            assert(pt == plaintext,
                "Triple persistence roundtrip mismatch for " ~ h.name);
        }
    }
}

void testRoundtripWithLockSeed()
{
    // Activating LockSeed grows the encryptor to 4 (Single) or 8
    // (Triple) seed slots; the exported blob carries the dedicated
    // lockSeed material via the lock_seed:true field, and importState
    // on a fresh encryptor restores the seed slot AND auto-couples
    // LockSoup + BitSoup overlays.
    ubyte[] plaintext = (cast(ubyte[]) "lockseed payload ".dup);
    foreach (i; 0 .. 32)
        plaintext ~= cast(ubyte) i;

    static immutable int[2][2] modes = [[1, 4], [3, 8]];
    foreach (pair; modes)
    {
        int mode = pair[0];
        int expectedCount = pair[1];

        ubyte[] blob;
        ubyte[] ct;
        {
            auto src = Encryptor("blake3", 1024, "kmac256", mode);
            src.setLockSeed(1);
            assert(src.seedCount() == expectedCount,
                "lockSeed seedCount sender mismatch");
            blob = src.exportState().dup;
            ct = src.encryptAuth(plaintext).dup;
        }
        auto dst = Encryptor("blake3", 1024, "kmac256", mode);
        assert(dst.seedCount() == expectedCount - 1,
            "fresh encryptor pre-import seedCount mismatch");
        dst.importState(blob);
        assert(dst.seedCount() == expectedCount,
            "post-import seedCount mismatch");
        auto pt = dst.decryptAuth(ct).dup;
        assert(pt == plaintext, "lockSeed persistence roundtrip mismatch");
    }
}

void testRoundtripWithFullConfig()
{
    // Per-instance configuration knobs (NonceBits, BarrierFill,
    // BitSoup, LockSoup) round-trip through the state blob along
    // with the seed material — no manual mirror set*() calls
    // required on the receiver.
    ubyte[] plaintext = (cast(ubyte[]) "full-config persistence ".dup);
    foreach (i; 0 .. 64)
        plaintext ~= cast(ubyte) i;

    ubyte[] blob;
    ubyte[] ct;
    {
        auto src = Encryptor("blake3", 1024, "kmac256", 1);
        src.setNonceBits(512);
        src.setBarrierFill(4);
        src.setBitSoup(1);
        src.setLockSoup(1);
        blob = src.exportState().dup;
        ct = src.encryptAuth(plaintext).dup;
    }
    // Receiver — fresh encryptor without any mirror set*() calls.
    auto dst = Encryptor("blake3", 1024, "kmac256", 1);
    assert(dst.nonceBits() == 128, "default before Import");
    dst.importState(blob);
    assert(dst.nonceBits() == 512, "restored from blob");
    assert(dst.easyHeaderSize() == 68, "follows nonceBits");

    auto pt = dst.decryptAuth(ct).dup;
    assert(pt == plaintext, "full-config decrypt mismatch");
}

void testRoundtripBarrierFillReceiverPriority()
{
    // BarrierFill is asymmetric — the receiver does not need the
    // same margin as the sender. When the receiver explicitly
    // installs a non-default BarrierFill before Import, that choice
    // takes priority over the blob's barrier_fill.
    auto plaintext = cast(const(ubyte)[]) "barrier-fill priority";

    ubyte[] blob;
    ubyte[] ct;
    {
        auto src = Encryptor("blake3", 1024, "kmac256", 1);
        src.setBarrierFill(4);
        blob = src.exportState().dup;
        ct = src.encryptAuth(plaintext).dup;
    }

    // Receiver pre-sets BarrierFill=8; Import must NOT downgrade it
    // to the blob's 4.
    {
        auto dst = Encryptor("blake3", 1024, "kmac256", 1);
        dst.setBarrierFill(8);
        dst.importState(blob);
        auto pt = dst.decryptAuth(ct).dup;
        assert(pt == plaintext, "barrier-fill 8 receiver decrypt mismatch");
    }

    // A receiver that did NOT pre-set BarrierFill picks up the blob
    // value transparently.
    {
        auto dst2 = Encryptor("blake3", 1024, "kmac256", 1);
        dst2.importState(blob);
        auto pt2 = dst2.decryptAuth(ct).dup;
        assert(pt2 == plaintext, "barrier-fill default receiver mismatch");
    }
}

// ─── TestPeekConfig ────────────────────────────────────────────────

void testPeekRecoversMetadata()
{
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBitsVal; keyBitsFor(h.width))
        {
            foreach (mode; [1, 3])
            {
                foreach (mac; ["kmac256", "hmac-sha256", "hmac-blake3"])
                {
                    ubyte[] blob;
                    {
                        auto enc = Encryptor(h.name, keyBitsVal, mac, mode);
                        blob = enc.exportState().dup;
                    }
                    auto cfg = peekConfig(blob);
                    assert(cfg.primitive == h.name,
                        "peek primitive mismatch");
                    assert(cfg.keyBits == keyBitsVal,
                        "peek keyBits mismatch");
                    assert(cfg.mode == mode,
                        "peek mode mismatch");
                    assert(cfg.macName == mac,
                        "peek mac mismatch");
                }
            }
        }
    }
}

void testPeekMalformedBlob()
{
    static immutable ubyte[][] blobs = [
        cast(immutable(ubyte)[]) "not json",
        cast(immutable(ubyte)[]) "",
        cast(immutable(ubyte)[]) "{}",
        cast(immutable(ubyte)[]) `{"v":1}`,
    ];
    foreach (b; blobs)
    {
        auto err = collectException!ITBError(peekConfig(b));
        assert(err !is null, "peek on malformed blob must throw");
        assert(err.statusCode == Status.EasyMalformed,
            "expected Status.EasyMalformed for malformed peek");
    }
}

void testPeekTooNewVersion()
{
    // Hand-craft a blob with v=99; PeekConfig must reject rather
    // than silently parsing. The peek path conflates "too-new
    // version" with the broader malformed-shape bucket and surfaces
    // Status.EasyMalformed for either; the dedicated
    // Status.EasyVersionTooNew is reserved for the Import path
    // (covered by testImportTooNewVersion in this file).
    auto blob = cast(const(ubyte)[]) `{"v":99,"kind":"itb-easy"}`;
    auto err = collectException!ITBError(peekConfig(blob));
    assert(err !is null, "peek too-new must throw");
    assert(err.statusCode == Status.EasyMalformed,
        "expected Status.EasyMalformed for peek v=99");
}

// ─── TestImportMismatch ────────────────────────────────────────────

private ubyte[] makeBaselineBlob()
{
    auto src = Encryptor("blake3", 1024, "kmac256", 1);
    return src.exportState().dup;
}

void testImportMismatchPrimitive()
{
    auto blob = makeBaselineBlob();
    auto dst = Encryptor("blake2s", 1024, "kmac256", 1);
    auto err = collectException!ITBEasyMismatchError(dst.importState(blob));
    assert(err !is null, "primitive mismatch must throw EasyMismatchError");
    assert(err.statusCode == Status.EasyMismatch);
    assert(err.field == "primitive",
        "expected mismatch field=primitive, got " ~ err.field);
}

void testImportMismatchKeyBits()
{
    auto blob = makeBaselineBlob();
    auto dst = Encryptor("blake3", 2048, "kmac256", 1);
    auto err = collectException!ITBEasyMismatchError(dst.importState(blob));
    assert(err !is null, "keyBits mismatch must throw EasyMismatchError");
    assert(err.statusCode == Status.EasyMismatch);
    assert(err.field == "key_bits",
        "expected mismatch field=key_bits, got " ~ err.field);
}

void testImportMismatchMode()
{
    auto blob = makeBaselineBlob();
    auto dst = Encryptor("blake3", 1024, "kmac256", 3);
    auto err = collectException!ITBEasyMismatchError(dst.importState(blob));
    assert(err !is null, "mode mismatch must throw EasyMismatchError");
    assert(err.statusCode == Status.EasyMismatch);
    assert(err.field == "mode",
        "expected mismatch field=mode, got " ~ err.field);
}

void testImportMismatchMac()
{
    auto blob = makeBaselineBlob();
    auto dst = Encryptor("blake3", 1024, "hmac-sha256", 1);
    auto err = collectException!ITBEasyMismatchError(dst.importState(blob));
    assert(err !is null, "mac mismatch must throw EasyMismatchError");
    assert(err.statusCode == Status.EasyMismatch);
    assert(err.field == "mac",
        "expected mismatch field=mac, got " ~ err.field);
}

// ─── TestImportMalformed ───────────────────────────────────────────

void testImportMalformedJson()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto err = collectException!ITBError(
        enc.importState(cast(const(ubyte)[]) "this is not json"));
    assert(err !is null, "malformed JSON import must throw");
    assert(err.statusCode == Status.EasyMalformed,
        "expected Status.EasyMalformed");
}

void testImportTooNewVersion()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto blob = cast(const(ubyte)[]) `{"v":99,"kind":"itb-easy"}`;
    auto err = collectException!ITBError(enc.importState(blob));
    assert(err !is null, "v=99 import must throw");
    assert(err.statusCode == Status.EasyVersionTooNew,
        "expected Status.EasyVersionTooNew");
}

void testImportWrongKind()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto blob = cast(const(ubyte)[]) `{"v":1,"kind":"not-itb-easy"}`;
    auto err = collectException!ITBError(enc.importState(blob));
    assert(err !is null, "wrong kind import must throw");
    assert(err.statusCode == Status.EasyMalformed,
        "expected Status.EasyMalformed for wrong kind");
}

// ─── TestMaterialGetters ───────────────────────────────────────────

void testPrfKeyLengthsPerPrimitive()
{
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBitsVal; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, keyBitsVal, "kmac256", 1);
            if (h.name == "siphash24")
            {
                assert(!enc.hasPRFKeys(),
                    "siphash24 must report hasPRFKeys=false");
                auto err = collectException!ITBError(enc.prfKey(0));
                assert(err !is null, "siphash24 prfKey must throw");
            }
            else
            {
                assert(enc.hasPRFKeys(),
                    "primitive must report hasPRFKeys=true");
                auto count = enc.seedCount();
                foreach (slot; 0 .. count)
                {
                    auto key = enc.prfKey(slot);
                    assert(key.length == expectedPrfKeyLen(h.name),
                        "PRF key length mismatch for " ~ h.name);
                }
            }
        }
    }
}

void testSeedComponentsLengthsPerKeyBits()
{
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBitsVal; keyBitsFor(h.width))
        {
            auto enc = Encryptor(h.name, keyBitsVal, "kmac256", 1);
            auto count = enc.seedCount();
            foreach (slot; 0 .. count)
            {
                auto comps = enc.seedComponents(slot);
                assert(cast(int) comps.length * 64 == keyBitsVal,
                    "seed components length mismatch");
            }
        }
    }
}

void testMacKeyPresent()
{
    foreach (mac; ["kmac256", "hmac-sha256", "hmac-blake3"])
    {
        auto enc = Encryptor("blake3", 1024, mac, 1);
        auto k = enc.macKey();
        assert(k.length > 0, "macKey must be non-empty");
    }
}

void testSeedComponentsOutOfRange()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    assert(enc.seedCount() == 3);
    auto err = collectException!ITBError(enc.seedComponents(3));
    assert(err !is null, "slot=3 must throw");
    assert(err.statusCode == Status.BadInput,
        "expected Status.BadInput for slot=3");
    auto err2 = collectException!ITBError(enc.seedComponents(-1));
    assert(err2 !is null, "slot=-1 must throw");
    assert(err2.statusCode == Status.BadInput,
        "expected Status.BadInput for slot=-1");
}

void main()
{
    testRoundtripAllHashesSingle();
    testRoundtripAllHashesTriple();
    testRoundtripWithLockSeed();
    testRoundtripWithFullConfig();
    testRoundtripBarrierFillReceiverPriority();
    testPeekRecoversMetadata();
    testPeekMalformedBlob();
    testPeekTooNewVersion();
    testImportMismatchPrimitive();
    testImportMismatchKeyBits();
    testImportMismatchMode();
    testImportMismatchMac();
    testImportMalformedJson();
    testImportTooNewVersion();
    testImportWrongKind();
    testPrfKeyLengthsPerPrimitive();
    testSeedComponentsLengthsPerKeyBits();
    testMacKeyPresent();
    testSeedComponentsOutOfRange();
    writeln("test_easy_persistence: ALL OK");
}
