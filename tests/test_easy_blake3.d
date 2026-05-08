// BLAKE3-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/test_blake3.py — same
// coverage shape (nonce-size sweep, single + triple roundtrip, single +
// triple auth with tamper rejection, persistence sweep, plaintext-size
// sweep) applied to the high-level itb.Encryptor surface instead of
// the lower-level Seed / encrypt / decrypt path.
//
// BLAKE3 ships at a single width (-256) — there is no -512 BLAKE3 in
// the registry — so this file iterates the single primitive across the
// same axes test_easy_blake2{b,s} cover.
//
// Persistence rides on Encryptor.exportState / Encryptor.importState
// (JSON blob, single round-trip). The blob captures the strictly larger
// encryptor state (PRF keys for every slot, MAC key, optional dedicated
// lockSeed material) so the day-2 decrypt path exercises the full
// restore.
//
// Encryptor.setNonceBits is per-instance and does not touch
// process-global state, so these tests do not need a serial-lock.

import std.algorithm : min;
import std.random : Random, uniform;
import std.stdio : writefln;

import itb;

private struct HashRow { string name; int width; }

private static immutable HashRow[] BLAKE3_HASHES = [
    HashRow("blake3", 256),
];

private size_t expectedKeyLen(string name)
{
    if (name == "blake3") return 32;
    assert(false, "unknown hash " ~ name);
}

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

void testRoundtripAcrossNonceSizes()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (h; BLAKE3_HASHES)
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
        foreach (h; BLAKE3_HASHES)
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
            foreach (h; BLAKE3_HASHES)
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
            foreach (h; BLAKE3_HASHES)
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
    auto plaintext = (cast(ubyte[]) "persistence payload ".dup) ~ tokenBytes(1024);

    foreach (h; BLAKE3_HASHES)
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
                    assert(src.prfKey(0).length == expectedKeyLen(h.name),
                        "prfKey length mismatch");
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
    foreach (h; BLAKE3_HASHES)
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
    testRoundtripAcrossNonceSizes();
    testTripleRoundtripAcrossNonceSizes();
    testAuthAcrossNonceSizes();
    testTripleAuthAcrossNonceSizes();
    testPersistenceAcrossNonceSizes();
    testRoundtripSizes();
    writefln("test_easy_blake3: ALL OK");
}
