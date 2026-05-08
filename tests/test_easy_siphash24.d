// SipHash-2-4-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/test_siphash24.py
// applied to the high-level itb.Encryptor surface. SipHash ships only
// at -128 and is the unique primitive with no fixed PRF key —
// Encryptor.hasPRFKeys is false, Encryptor.prfKey surfaces
// Status.BadInput. The persistence path therefore exports / imports
// without prf_keys carried in the JSON blob; the seed components alone
// reconstruct the SipHash keying material.
//
// Encryptor.setNonceBits is per-instance and does not touch
// process-global state, so these tests do not need a serial-lock.

import std.algorithm : min;
import std.random : Random, uniform;
import std.stdio : writefln;

import itb;

private struct HashRow { string name; int width; }

private static immutable HashRow[] SIPHASH_HASHES = [
    HashRow("siphash24", 128),
];

private static immutable int[] NONCE_SIZES = [128, 256, 512];
private static immutable string[] MAC_NAMES = ["kmac256", "hmac-sha256", "hmac-blake3"];

private Random rng;
static this() { rng = Random(0xC0FFEE); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

private int[] keyBitsFor(int width)
{
    int[] out_;
    foreach (kb; [512, 1024, 2048])
        if (kb % width == 0)
            out_ ~= kb;
    return out_;
}

void testNoPrfKeys()
{
    // SipHash is the lone primitive with hasPRFKeys == false; the PRF
    // key getter rejects indexed access with Status.BadInput.
    auto enc = Encryptor("siphash24", 1024, "kmac256", 1);
    assert(!enc.hasPRFKeys(), "siphash24 must report hasPRFKeys=false");
    bool gotBadInput = false;
    try
    {
        cast(void) enc.prfKey(0);
    }
    catch (ITBError e)
    {
        assert(e.statusCode == Status.BadInput,
            "expected BadInput, got " ~ e.message);
        gotBadInput = true;
    }
    assert(gotBadInput, "prfKey(0) on siphash24 must throw");
}

void testRoundtripAcrossNonceSizes()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (h; SIPHASH_HASHES)
        {
            auto enc = Encryptor(h.name, 1024, "kmac256", 1);
            enc.setNonceBits(n);
            auto ct = enc.encrypt(plaintext).dup;
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext, "roundtrip mismatch");
        }
    }
}

void testTripleRoundtripAcrossNonceSizes()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (h; SIPHASH_HASHES)
        {
            auto enc = Encryptor(h.name, 1024, "kmac256", 3);
            enc.setNonceBits(n);
            auto ct = enc.encrypt(plaintext).dup;
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext, "triple roundtrip mismatch");
        }
    }
}

void testAuthAcrossNonceSizes()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            foreach (h; SIPHASH_HASHES)
            {
                auto enc = Encryptor(h.name, 1024, macName, 1);
                enc.setNonceBits(n);
                auto ct = enc.encryptAuth(plaintext).dup;
                auto pt = enc.decryptAuth(ct).dup;
                assert(pt == plaintext, "auth roundtrip mismatch");

                auto tampered = ct.dup;
                auto hsz = enc.easyHeaderSize();
                auto end = min(hsz + 256, tampered.length);
                foreach (i; hsz .. end)
                    tampered[i] ^= 0x01;
                bool gotMacFailure = false;
                try
                {
                    cast(void) enc.decryptAuth(tampered);
                }
                catch (ITBError e)
                {
                    assert(e.statusCode == Status.MACFailure,
                        "expected MACFailure, got " ~ e.message);
                    gotMacFailure = true;
                }
                assert(gotMacFailure, "tampered auth ciphertext must throw");
            }
        }
    }
}

void testTripleAuthAcrossNonceSizes()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            foreach (h; SIPHASH_HASHES)
            {
                auto enc = Encryptor(h.name, 1024, macName, 3);
                enc.setNonceBits(n);
                auto ct = enc.encryptAuth(plaintext).dup;
                auto pt = enc.decryptAuth(ct).dup;
                assert(pt == plaintext, "triple auth roundtrip mismatch");

                auto tampered = ct.dup;
                auto hsz = enc.easyHeaderSize();
                auto end = min(hsz + 256, tampered.length);
                foreach (i; hsz .. end)
                    tampered[i] ^= 0x01;
                bool gotMacFailure = false;
                try
                {
                    cast(void) enc.decryptAuth(tampered);
                }
                catch (ITBError e)
                {
                    assert(e.statusCode == Status.MACFailure);
                    gotMacFailure = true;
                }
                assert(gotMacFailure, "tampered triple auth must throw");
            }
        }
    }
}

void testPersistenceAcrossNonceSizes()
{
    // Persistence sweep without prf_keys: SipHash's seed components
    // alone reconstruct the keying material. The exported blob omits
    // prf_keys, and importState on a fresh encryptor restores the
    // seeds without consulting them.
    auto plaintext = (cast(ubyte[]) "persistence payload ".dup) ~ tokenBytes(1024);

    foreach (h; SIPHASH_HASHES)
    {
        foreach (keyBits; keyBitsFor(h.width))
        {
            foreach (n; NONCE_SIZES)
            {
                ubyte[] blob;
                ubyte[] ciphertext;
                {
                    auto src = Encryptor(h.name, keyBits, "kmac256", 1);
                    src.setNonceBits(n);
                    assert(!src.hasPRFKeys(),
                        "siphash24 must report hasPRFKeys=false");
                    assert(cast(int) src.seedComponents(0).length * 64 == keyBits,
                        "seedComponents length mismatch");
                    blob = src.exportState();
                    ciphertext = src.encrypt(plaintext).dup;
                    src.close();
                }

                auto dst = Encryptor(h.name, keyBits, "kmac256", 1);
                dst.setNonceBits(n);
                dst.importState(blob);
                auto pt = dst.decrypt(ciphertext).dup;
                assert(pt == plaintext, "persistence decrypt mismatch");
                dst.close();
            }
        }
    }
}

void testRoundtripSizes()
{
    foreach (h; SIPHASH_HASHES)
    {
        foreach (n; NONCE_SIZES)
        {
            foreach (sz; [1, 17, 4096, 65536, 1 << 20])
            {
                auto plaintext = tokenBytes(sz);
                auto enc = Encryptor(h.name, 1024, "kmac256", 1);
                enc.setNonceBits(n);
                auto ct = enc.encrypt(plaintext).dup;
                auto pt = enc.decrypt(ct).dup;
                assert(pt == plaintext, "roundtrip-sizes mismatch");
            }
        }
    }
}

void main()
{
    testNoPrfKeys();
    testRoundtripAcrossNonceSizes();
    testTripleRoundtripAcrossNonceSizes();
    testAuthAcrossNonceSizes();
    testTripleAuthAcrossNonceSizes();
    testPersistenceAcrossNonceSizes();
    testRoundtripSizes();
    writefln("test_easy_siphash24: ALL OK");
}
