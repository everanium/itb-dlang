// BLAKE3-focused D binding coverage.
//
// Mirrors bindings/rust/tests/test_blake3.rs one-to-one. BLAKE3 ships
// at a single width (-256). Each Rust `#[test] fn` becomes a `void
// test*()` here, called from `main()`; the per-test inner loops over
// (nonce, primitive, mac) are inlined directly via `foreach`.

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

private void restoreNonceBits(int orig)
{
    setNonceBits(orig);
}

void testRoundtripAcrossNonceSizes()
{
    int orig = getNonceBits();
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (h; BLAKE3_HASHES)
        {
            setNonceBits(n);
            auto s0 = Seed(h.name, 1024);
            auto s1 = Seed(h.name, 1024);
            auto s2 = Seed(h.name, 1024);
            auto ct = encrypt(s0, s1, s2, plaintext);
            auto pt = decrypt(s0, s1, s2, ct);
            assert(pt == plaintext, "roundtrip mismatch");
            auto hsz = headerSize();
            auto chunkLen = parseChunkLen(ct[0 .. hsz]);
            assert(chunkLen == ct.length, "parseChunkLen mismatch");
        }
    }
    restoreNonceBits(orig);
}

void testTripleRoundtripAcrossNonceSizes()
{
    int orig = getNonceBits();
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (h; BLAKE3_HASHES)
        {
            setNonceBits(n);
            auto n0 = Seed(h.name, 1024);
            auto d1 = Seed(h.name, 1024);
            auto d2 = Seed(h.name, 1024);
            auto d3 = Seed(h.name, 1024);
            auto t1 = Seed(h.name, 1024);
            auto t2 = Seed(h.name, 1024);
            auto t3 = Seed(h.name, 1024);
            auto ct = encryptTriple(n0, d1, d2, d3, t1, t2, t3, plaintext);
            auto pt = decryptTriple(n0, d1, d2, d3, t1, t2, t3, ct);
            assert(pt == plaintext, "triple roundtrip mismatch");
        }
    }
    restoreNonceBits(orig);
}

void testAuthAcrossNonceSizes()
{
    int orig = getNonceBits();
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            foreach (h; BLAKE3_HASHES)
            {
                setNonceBits(n);
                auto key = tokenBytes(32);
                auto mac = MAC(macName, key);
                auto s0 = Seed(h.name, 1024);
                auto s1 = Seed(h.name, 1024);
                auto s2 = Seed(h.name, 1024);
                auto ct = encryptAuth(s0, s1, s2, mac, plaintext);
                auto pt = decryptAuth(s0, s1, s2, mac, ct);
                assert(pt == plaintext, "auth roundtrip mismatch");

                auto tampered = ct.dup;
                auto hsz = headerSize();
                auto end = min(hsz + 256, tampered.length);
                foreach (i; hsz .. end)
                    tampered[i] ^= 0x01;
                bool gotMacFailure = false;
                try
                {
                    cast(void) decryptAuth(s0, s1, s2, mac, tampered);
                }
                catch (ITBError e)
                {
                    assert(e.statusCode == Status.MACFailure);
                    gotMacFailure = true;
                }
                assert(gotMacFailure, "tampered auth ciphertext must throw");
            }
        }
    }
    restoreNonceBits(orig);
}

void testTripleAuthAcrossNonceSizes()
{
    int orig = getNonceBits();
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            foreach (h; BLAKE3_HASHES)
            {
                setNonceBits(n);
                auto key = tokenBytes(32);
                auto mac = MAC(macName, key);
                auto n0 = Seed(h.name, 1024);
                auto d1 = Seed(h.name, 1024);
                auto d2 = Seed(h.name, 1024);
                auto d3 = Seed(h.name, 1024);
                auto t1 = Seed(h.name, 1024);
                auto t2 = Seed(h.name, 1024);
                auto t3 = Seed(h.name, 1024);
                auto ct = encryptAuthTriple(n0, d1, d2, d3, t1, t2, t3, mac, plaintext);
                auto pt = decryptAuthTriple(n0, d1, d2, d3, t1, t2, t3, mac, ct);
                assert(pt == plaintext, "triple auth roundtrip mismatch");

                auto tampered = ct.dup;
                auto hsz = headerSize();
                auto end = min(hsz + 256, tampered.length);
                foreach (i; hsz .. end)
                    tampered[i] ^= 0x01;
                bool gotMacFailure = false;
                try
                {
                    cast(void) decryptAuthTriple(n0, d1, d2, d3, t1, t2, t3, mac, tampered);
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
    restoreNonceBits(orig);
}

void testPersistenceAcrossNonceSizes()
{
    int orig = getNonceBits();
    auto plaintext = (cast(ubyte[]) "persistence payload ".dup) ~ tokenBytes(1024);

    foreach (h; BLAKE3_HASHES)
    {
        int[] validKeyBits;
        foreach (kb; [512, 1024, 2048])
            if (kb % h.width == 0)
                validKeyBits ~= kb;
        foreach (keyBits; validKeyBits)
        {
            foreach (n; NONCE_SIZES)
            {
                setNonceBits(n);

                ubyte[] ciphertext;
                ulong[] nsComps; ubyte[] nsKey;
                ulong[] dsComps; ubyte[] dsKey;
                ulong[] ssComps; ubyte[] ssKey;
                {
                    auto ns = Seed(h.name, keyBits);
                    auto ds = Seed(h.name, keyBits);
                    auto ss = Seed(h.name, keyBits);

                    nsComps = ns.components.dup;
                    nsKey = ns.hashKey.dup;
                    dsComps = ds.components.dup;
                    dsKey = ds.hashKey.dup;
                    ssComps = ss.components.dup;
                    ssKey = ss.hashKey.dup;

                    assert(nsKey.length == expectedKeyLen(h.name),
                        "hashKey length mismatch");
                    assert(cast(int) nsComps.length * 64 == keyBits,
                        "components length mismatch");

                    ciphertext = encrypt(ns, ds, ss, plaintext);
                }
                auto ns2 = Seed.fromComponents(h.name, nsComps, nsKey);
                auto ds2 = Seed.fromComponents(h.name, dsComps, dsKey);
                auto ss2 = Seed.fromComponents(h.name, ssComps, ssKey);
                auto decrypted = decrypt(ns2, ds2, ss2, ciphertext);
                assert(decrypted == plaintext, "persistence decrypt mismatch");
            }
        }
    }
    restoreNonceBits(orig);
}

void testRoundtripSizes()
{
    int orig = getNonceBits();
    foreach (h; BLAKE3_HASHES)
    {
        foreach (n; NONCE_SIZES)
        {
            foreach (sz; [1, 17, 4096, 65536, 1 << 20])
            {
                setNonceBits(n);
                auto plaintext = tokenBytes(sz);
                auto ns = Seed(h.name, 1024);
                auto ds = Seed(h.name, 1024);
                auto ss = Seed(h.name, 1024);
                auto ct = encrypt(ns, ds, ss, plaintext);
                auto pt = decrypt(ns, ds, ss, ct);
                assert(pt == plaintext, "roundtrip-sizes mismatch");
            }
        }
    }
    restoreNonceBits(orig);
}

void main()
{
    testRoundtripAcrossNonceSizes();
    testTripleRoundtripAcrossNonceSizes();
    testAuthAcrossNonceSizes();
    testTripleAuthAcrossNonceSizes();
    testPersistenceAcrossNonceSizes();
    testRoundtripSizes();
    writefln("test_blake3: ALL OK");
}
