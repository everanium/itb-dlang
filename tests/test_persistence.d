// Phase-5 mirror: cross-process persistence round-trip tests.
//
// Mirrors bindings/rust/tests/test_persistence.rs file-for-file.
//
// Exercises the Seed.components / Seed.hashKey / Seed.fromComponents
// surface across every primitive in the registry × the three ITB
// key-bit widths (512 / 1024 / 2048) that are valid for each native
// hash width.
//
// Without both `components` and `hashKey` captured at encrypt-side and
// re-supplied at decrypt-side, the seed state cannot be reconstructed
// and the ciphertext is unreadable.
import std.exception : collectException;
import std.range : iota;
import std.algorithm.iteration : map;
import std.array : array;
import std.stdio : writeln;
import itb;

struct CanonicalHash
{
    string name;
    int width;
}

immutable CanonicalHash[] CANONICAL_HASHES = [
    CanonicalHash("areion256", 256),
    CanonicalHash("areion512", 512),
    CanonicalHash("siphash24", 128),
    CanonicalHash("aescmac", 128),
    CanonicalHash("blake2b256", 256),
    CanonicalHash("blake2b512", 512),
    CanonicalHash("blake2s", 256),
    CanonicalHash("blake3", 256),
    CanonicalHash("chacha20", 256),
];

size_t expectedHashKeyLen(string name)
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
        default: assert(false, "unexpected primitive " ~ name);
    }
}

int[] keyBitsFor(int width)
{
    int[] out_;
    foreach (k; [512, 1024, 2048])
        if (k % width == 0)
            out_ ~= k;
    return out_;
}

ubyte[] buildPlaintext()
{
    auto p = cast(ubyte[]) "any binary data, including 0x00 bytes -- ".dup;
    foreach (i; 0 .. 256)
        p ~= cast(ubyte) i;
    return p;
}

void testRoundtripAllHashes()
{
    auto plaintext = buildPlaintext();

    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBits; keyBitsFor(h.width))
        {
            // Day 1 — random seeds.
            ulong[] nsComps, dsComps, ssComps;
            ubyte[] nsKey, dsKey, ssKey;
            ubyte[] ciphertext;
            {
                auto ns = Seed(h.name, keyBits);
                auto ds = Seed(h.name, keyBits);
                auto ss = Seed(h.name, keyBits);
                nsComps = ns.components();
                dsComps = ds.components();
                ssComps = ss.components();
                nsKey = ns.hashKey();
                dsKey = ds.hashKey();
                ssKey = ss.hashKey();

                assert(nsComps.length * 64 == cast(size_t) keyBits,
                    "components count mismatch for " ~ h.name);
                assert(nsKey.length == expectedHashKeyLen(h.name),
                    "hashKey length mismatch for " ~ h.name);

                ciphertext = encrypt(ns, ds, ss, plaintext);
            }

            // Day 2 — restore from saved material.
            auto ns2 = Seed.fromComponents(h.name, nsComps, nsKey);
            auto ds2 = Seed.fromComponents(h.name, dsComps, dsKey);
            auto ss2 = Seed.fromComponents(h.name, ssComps, ssKey);
            auto decrypted = decrypt(ns2, ds2, ss2, ciphertext);
            assert(decrypted == plaintext,
                "persistence roundtrip mismatch for " ~ h.name);

            // Restored seeds report the same components + key.
            assert(ns2.components() == nsComps,
                "restored components mismatch");
            assert(ns2.hashKey() == nsKey,
                "restored hashKey mismatch");
        }
    }
}

void testRandomKeyPath()
{
    // 512-bit zero components — sufficient for non-SipHash primitives.
    ulong[] components = new ulong[8];
    foreach (h; CANONICAL_HASHES)
    {
        auto seed = Seed.fromComponents(h.name, components, []);
        auto key = seed.hashKey();
        if (h.name == "siphash24")
            assert(key.length == 0, "siphash24 must report empty key");
        else
            assert(key.length == expectedHashKeyLen(h.name),
                "hashKey length mismatch for " ~ h.name);
    }
}

void testExplicitKeyPreserved()
{
    // BLAKE3 has a 32-byte symmetric key.
    ubyte[] explicit = iota(32).map!(i => cast(ubyte) i).array;
    ulong[] components;
    foreach (i; 0 .. 8)
        components ~= 0xCAFEBABE_DEADBEEFUL;
    auto seed = Seed.fromComponents("blake3", components, explicit);
    assert(seed.hashKey() == explicit,
        "explicit hashKey must round-trip exactly");
}

void testBadKeySize()
{
    // A non-empty hashKey whose length does not match the primitive's
    // expected length must surface a clean ITBError (no panic across
    // the FFI). Seven bytes is wrong for blake3 (expects 32).
    ulong[] components = new ulong[16];
    ubyte[7] badKey = 0;
    auto err = collectException!ITBError(
        Seed.fromComponents("blake3", components, badKey));
    assert(err !is null, "wrong-size hashKey must throw");
}

void testSiphashRejectsHashKey()
{
    // SipHash-2-4 takes no internal fixed key; passing one must be
    // rejected (not silently ignored).
    ulong[] components = new ulong[8];
    ubyte[16] nonempty = 0;
    auto err = collectException!ITBError(
        Seed.fromComponents("siphash24", components, nonempty));
    assert(err !is null, "siphash24 must reject non-empty hashKey");
}

void main()
{
    testRoundtripAllHashes();
    testRandomKeyPath();
    testExplicitKeyPreserved();
    testBadKeySize();
    testSiphashRejectsHashKey();
    writeln("test_persistence: ALL OK");
}
