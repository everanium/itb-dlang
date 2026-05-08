// End-to-end Encryptor tests for authenticated encryption.
//
// Same matrix (3 MACs × 3 hash widths × {Single, Triple} round trip
// plus tamper rejection) applied to the high-level itb.Encryptor
// surface. Cross-MAC structural rejection rides through the
// exportState / importState path, where a receiver constructed with
// the wrong MAC primitive surfaces Status.EasyMismatch with
// lastMismatchField() == "mac". Same-primitive different-key MAC
// failure verifies that two independently constructed encryptors with
// their own random MAC material collide on Status.MACFailure rather
// than a corrupted plaintext.
//
// Mirrors bindings/rust/tests/test_easy_auth.rs one-to-one.

import std.algorithm : min;
import std.exception : collectException;
import std.random : Random, uniform;
import std.stdio : writeln;

import itb;

private static immutable string[] CANONICAL_MACS =
    ["kmac256", "hmac-sha256", "hmac-blake3"];
private static immutable string[] HASH_BY_WIDTH =
    ["siphash24", "blake3", "blake2b512"];

private Random rng;
static this() { rng = Random(0xCAFEBABEU); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

void testAllMACsAllWidthsSingle()
{
    auto plaintext = tokenBytes(4096);
    foreach (macName; CANONICAL_MACS)
    {
        foreach (hashName; HASH_BY_WIDTH)
        {
            auto enc = Encryptor(hashName, 1024, macName, 1);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext, "auth Single roundtrip mismatch");

            // Tamper: flip 256 bytes past the dynamic header.
            auto tampered = ct.dup;
            auto h = enc.easyHeaderSize();
            auto end = min(h + 256, tampered.length);
            foreach (i; h .. end)
                tampered[i] ^= 0x01;
            auto err = collectException!ITBError(enc.decryptAuth(tampered));
            assert(err !is null, "tampered ciphertext must throw");
            assert(err.statusCode == Status.MACFailure,
                "expected Status.MACFailure on tampered ciphertext");
        }
    }
}

void testAllMACsAllWidthsTriple()
{
    auto plaintext = tokenBytes(4096);
    foreach (macName; CANONICAL_MACS)
    {
        foreach (hashName; HASH_BY_WIDTH)
        {
            auto enc = Encryptor(hashName, 1024, macName, 3);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext, "auth Triple roundtrip mismatch");

            auto tampered = ct.dup;
            auto h = enc.easyHeaderSize();
            auto end = min(h + 256, tampered.length);
            foreach (i; h .. end)
                tampered[i] ^= 0x01;
            auto err = collectException!ITBError(enc.decryptAuth(tampered));
            assert(err !is null, "tampered ciphertext must throw");
            assert(err.statusCode == Status.MACFailure,
                "expected Status.MACFailure on tampered ciphertext");
        }
    }
}

void testCrossMACRejectionDifferentPrimitive()
{
    // Sender uses kmac256; receiver uses hmac-sha256 — Import must
    // reject on field=mac.
    ubyte[] blob;
    {
        auto src = Encryptor("blake3", 1024, "kmac256", 1);
        blob = src.exportState().dup;
    }
    auto dst = Encryptor("blake3", 1024, "hmac-sha256", 1);
    auto err = collectException!ITBEasyMismatchError(dst.importState(blob));
    assert(err !is null, "cross-MAC import must throw EasyMismatchError");
    assert(err.statusCode == Status.EasyMismatch,
        "expected Status.EasyMismatch");
    assert(err.field == "mac", "expected mismatch field=mac, got " ~ err.field);
}

void testSamePrimitiveDifferentKeyMacFailure()
{
    auto plaintext = cast(const(ubyte)[]) "authenticated payload";
    auto enc1 = Encryptor("blake3", 1024, "hmac-sha256", 1);
    auto enc2 = Encryptor("blake3", 1024, "hmac-sha256", 1);
    // Day 1: encrypt with enc1's seeds and MAC key.
    auto ct = enc1.encryptAuth(plaintext).dup;
    // Day 2: enc2 has its own (different) seed/MAC keys.
    auto err = collectException!ITBError(enc2.decryptAuth(ct));
    assert(err !is null, "different-key decrypt must throw");
    assert(err.statusCode == Status.MACFailure,
        "expected Status.MACFailure on different-key auth");
}

void main()
{
    testAllMACsAllWidthsSingle();
    testAllMACsAllWidthsTriple();
    testCrossMACRejectionDifferentPrimitive();
    testSamePrimitiveDifferentKeyMacFailure();
    writeln("test_easy_auth: ALL OK");
}
