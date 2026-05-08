// Mixed-mode Encryptor (per-slot PRF primitive selection) tests.
//
// Round-trip on Single + Triple under Encryptor.newMixed /
// Encryptor.newMixed3; optional dedicated lockSeed under its own
// primitive; state-blob exportState / importState; mixed-width
// rejection through the cgo boundary; per-slot introspection
// accessors (primitiveAt, isMixed).
//
// Mirrors bindings/rust/tests/test_easy_mixed.rs one-to-one.

import std.array : replicate;
import std.exception : collectException;
import std.random : Random, uniform;
import std.stdio : writeln;

import itb;

private Random rng;
static this() { rng = Random(0xFEEDFACEU); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

// ─── TestMixedSingle ──────────────────────────────────────────────

void testMixedSingleBasicRoundtrip()
{
    auto enc = Encryptor.newMixed("blake3", "blake2s", "areion256",
                                   null, 1024, "kmac256");
    assert(enc.isMixed());
    assert(enc.primitive() == "mixed");
    assert(enc.primitiveAt(0) == "blake3");
    assert(enc.primitiveAt(1) == "blake2s");
    assert(enc.primitiveAt(2) == "areion256");

    auto plaintext = cast(const(ubyte)[]) "d mixed Single roundtrip payload";
    auto ct = enc.encrypt(plaintext).dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == plaintext, "mixed Single roundtrip mismatch");
}

void testMixedSingleWithDedicatedLockseed()
{
    auto enc = Encryptor.newMixed("blake3", "blake2s", "blake3",
                                   "areion256", 1024, "kmac256");
    assert(enc.primitiveAt(3) == "areion256");
    auto plaintext = cast(const(ubyte)[]) "d mixed Single + dedicated lockSeed payload";
    auto ct = enc.encryptAuth(plaintext).dup;
    auto pt = enc.decryptAuth(ct).dup;
    assert(pt == plaintext, "mixed Single + lockSeed roundtrip mismatch");
}

void testMixedSingleAescmacSiphash128bit()
{
    // SipHash-2-4 in one slot + AES-CMAC in others — 128-bit width
    // with mixed key shapes (siphash24 carries no fixed key bytes,
    // aescmac carries 16). Exercises the per-slot empty / non-empty
    // PRF-key validation in exportState / importState.
    auto enc = Encryptor.newMixed("aescmac", "siphash24", "aescmac",
                                   null, 512, "hmac-sha256");
    auto plaintext = cast(const(ubyte)[]) "d mixed 128-bit aescmac+siphash24 mix";
    auto ct = enc.encrypt(plaintext).dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == plaintext, "mixed 128-bit roundtrip mismatch");
}

// ─── TestMixedTriple ──────────────────────────────────────────────

void testMixedTripleBasicRoundtrip()
{
    auto enc = Encryptor.newMixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        null, 1024, "kmac256");
    static immutable string[] wants = [
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
    ];
    foreach (i, w; wants)
    {
        assert(enc.primitiveAt(cast(int) i) == w,
            "primitive mismatch at slot");
    }
    auto plaintext = cast(const(ubyte)[]) "d mixed Triple roundtrip payload";
    auto ct = enc.encrypt(plaintext).dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == plaintext, "mixed Triple roundtrip mismatch");
}

void testMixedTripleWithDedicatedLockseed()
{
    auto enc = Encryptor.newMixed3(
        "blake3", "blake2s", "blake3", "blake2s",
        "blake3", "blake2s", "blake3",
        "areion256", 1024, "kmac256");
    assert(enc.primitiveAt(7) == "areion256");
    auto plaintext = cast(ubyte[]) replicate(
        cast(string) "d mixed Triple + lockSeed payload", 16);
    auto ct = enc.encryptAuth(plaintext).dup;
    auto pt = enc.decryptAuth(ct).dup;
    assert(pt == plaintext, "mixed Triple + lockSeed roundtrip mismatch");
}

// ─── TestMixedExportImport ────────────────────────────────────────

void testMixedSingleExportImport()
{
    auto plaintext = tokenBytes(2048);
    ubyte[] ct;
    ubyte[] blob;
    {
        auto sender = Encryptor.newMixed("blake3", "blake2s", "areion256",
                                          null, 1024, "kmac256");
        ct = sender.encryptAuth(plaintext).dup;
        blob = sender.exportState().dup;
        assert(blob.length > 0, "exported blob must not be empty");
    }
    auto receiver = Encryptor.newMixed("blake3", "blake2s", "areion256",
                                        null, 1024, "kmac256");
    receiver.importState(blob);
    auto pt = receiver.decryptAuth(ct).dup;
    assert(pt == plaintext, "mixed Single import decrypt mismatch");
}

void testMixedTripleExportImportWithLockseed()
{
    auto plaintext = cast(ubyte[]) replicate(
        cast(string) "d mixed Triple + lockSeed Export/Import", 16);
    ubyte[] ct;
    ubyte[] blob;
    {
        auto sender = Encryptor.newMixed3(
            "areion256", "blake3", "blake2s", "chacha20",
            "blake2b256", "blake3", "blake2s",
            "areion256", 1024, "kmac256");
        ct = sender.encryptAuth(plaintext).dup;
        blob = sender.exportState().dup;
    }
    auto receiver = Encryptor.newMixed3(
        "areion256", "blake3", "blake2s", "chacha20",
        "blake2b256", "blake3", "blake2s",
        "areion256", 1024, "kmac256");
    receiver.importState(blob);
    auto pt = receiver.decryptAuth(ct).dup;
    assert(pt == plaintext, "mixed Triple + lockSeed import mismatch");
}

void testMixedShapeMismatch()
{
    // Mixed blob landing on a single-primitive receiver must be
    // rejected as a primitive mismatch.
    ubyte[] mixedBlob;
    {
        auto mixedSender = Encryptor.newMixed(
            "blake3", "blake2s", "blake3",
            null, 1024, "kmac256");
        mixedBlob = mixedSender.exportState().dup;
    }
    auto singleRecv = Encryptor("blake3", 1024, "kmac256", 1);
    auto err = collectException!ITBError(singleRecv.importState(mixedBlob));
    assert(err !is null, "mixed-vs-single import must throw");
}

// ─── TestMixedRejection ───────────────────────────────────────────

void testRejectMixedWidth()
{
    // Mixing a 256-bit primitive with a 512-bit primitive surfaces as
    // an error (panic-to-Status path on the Go side).
    auto err = collectException!ITBError(
        Encryptor.newMixed(
            "blake3",     // 256-bit
            "areion512",  // 512-bit ← width mismatch
            "blake3",
            null, 1024, "kmac256"));
    assert(err !is null, "mixed-width must throw");
}

void testRejectUnknownPrimitive()
{
    auto err = collectException!ITBError(
        Encryptor.newMixed(
            "no-such-primitive",
            "blake3", "blake3",
            null, 1024, "kmac256"));
    assert(err !is null, "unknown primitive must throw");
}

// ─── TestMixedNonMixed ────────────────────────────────────────────

void testDefaultConstructorIsNotMixed()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    assert(!enc.isMixed());
    foreach (i; 0 .. 3)
        assert(enc.primitiveAt(i) == "blake3",
            "non-mixed primitiveAt mismatch");
}

void main()
{
    testMixedSingleBasicRoundtrip();
    testMixedSingleWithDedicatedLockseed();
    testMixedSingleAescmacSiphash128bit();
    testMixedTripleBasicRoundtrip();
    testMixedTripleWithDedicatedLockseed();
    testMixedSingleExportImport();
    testMixedTripleExportImportWithLockseed();
    testMixedShapeMismatch();
    testRejectMixedWidth();
    testRejectUnknownPrimitive();
    testDefaultConstructorIsNotMixed();
    writeln("test_easy_mixed: ALL OK");
}
