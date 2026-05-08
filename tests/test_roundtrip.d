// Phase-3 + Phase-5 mirror: confirm Seed, MAC, and the low-level encrypt /
// decrypt entry points round-trip plaintext correctly. Covers Single,
// Triple, and Authenticated variants.
//
// Mirrors bindings/rust/tests/test_roundtrip.rs file-for-file.
//
// Compile recipe:
//   dmd -of=tests/build/test_roundtrip -I=src \
//       src/itb/package.d src/itb/sys.d src/itb/status.d \
//       src/itb/errors.d src/itb/registry.d src/itb/seed.d \
//       src/itb/mac.d src/itb/cipher.d src/itb/encryptor.d \
//       src/itb/blob.d src/itb/streams.d \
//       tests/test_roundtrip.d \
//       -L-L../../dist/linux-amd64 -L-litb \
//       '-L-rpath=$ORIGIN/../../dist/linux-amd64'
import std.exception : assertThrown, collectException;
import std.stdio : writefln, writeln;
import itb;

immutable ubyte[] PLAINTEXT =
    cast(immutable(ubyte)[]) "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

// Canonical primitive list shared with test_persistence.d / test_nonce_sizes.d.
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

ubyte[] pseudoPayload(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) ((i * 17 + 5) & 0xff);
    return buf;
}

void testSingleRoundtripBlake3()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto ct = encrypt(n, d, s, PLAINTEXT);
    assert(ct != PLAINTEXT, "ciphertext must differ from plaintext");
    auto pt = decrypt(n, d, s, ct);
    assert(pt == PLAINTEXT, "plaintext mismatch after Single roundtrip");
}

void testTripleRoundtripBlake3()
{
    auto n  = Seed("blake3", 1024);
    auto d1 = Seed("blake3", 1024);
    auto d2 = Seed("blake3", 1024);
    auto d3 = Seed("blake3", 1024);
    auto s1 = Seed("blake3", 1024);
    auto s2 = Seed("blake3", 1024);
    auto s3 = Seed("blake3", 1024);
    auto ct = encryptTriple(n, d1, d2, d3, s1, s2, s3, PLAINTEXT);
    auto pt = decryptTriple(n, d1, d2, d3, s1, s2, s3, ct);
    assert(pt == PLAINTEXT, "Triple roundtrip mismatch");
}

void testAuthRoundtripHmacSha256()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    ubyte[32] key = 0x42;
    auto mac = MAC("hmac-sha256", key[]);
    auto ct = encryptAuth(n, d, s, mac, PLAINTEXT);
    auto pt = decryptAuth(n, d, s, mac, ct);
    assert(pt == PLAINTEXT, "Auth Single roundtrip mismatch");
}

void testAuthTripleRoundtripKmac256()
{
    auto n  = Seed("blake3", 1024);
    auto d1 = Seed("blake3", 1024);
    auto d2 = Seed("blake3", 1024);
    auto d3 = Seed("blake3", 1024);
    auto s1 = Seed("blake3", 1024);
    auto s2 = Seed("blake3", 1024);
    auto s3 = Seed("blake3", 1024);
    ubyte[32] key = 0x21;
    auto mac = MAC("kmac256", key[]);
    auto ct = encryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, PLAINTEXT);
    auto pt = decryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, ct);
    assert(pt == PLAINTEXT, "Auth Triple roundtrip mismatch");
}

void testSeedComponentsRoundtrip()
{
    auto s  = Seed("blake3", 1024);
    auto comps = s.components();
    auto key   = s.hashKey();
    auto s2 = Seed.fromComponents("blake3", comps, key);
    assert(s.components() == s2.components(), "components mismatch after rebuild");
    assert(s.hashKey() == s2.hashKey(), "hashKey mismatch after rebuild");
}

void testAuthDecryptTamperedFailsWithMACFailure()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    ubyte[32] key = 0;
    auto mac = MAC("hmac-sha256", key[]);
    auto ct = encryptAuth(n, d, s, mac, PLAINTEXT);
    // Flip the last byte to tamper with the MAC tag.
    ct[$ - 1] ^= 0xff;
    auto err = collectException!ITBError(decryptAuth(n, d, s, mac, ct));
    assert(err !is null, "tampered ciphertext must surface ITBError");
    assert(err.statusCode == Status.MACFailure,
        "expected Status.MACFailure on tampered ciphertext");
}

void testSeedDropDoesNotPanic()
{
    foreach (i; 0 .. 32)
    {
        auto _s = Seed("blake3", 512);
    }
}

void testVersion()
{
    auto v = version_();
    assert(v.length > 0, "version must be non-empty");
    // Loose SemVer-shape sanity check: at least one '.' and digits.
    import std.algorithm.searching : canFind;
    import std.ascii : isDigit;
    assert(v.canFind('.'), "version must contain at least one '.'");
    assert(isDigit(v[0]), "version must start with a digit");
}

void testListHashes()
{
    auto got = listHashes();
    assert(got.length == CANONICAL_HASHES.length,
        "hash count mismatch");
    foreach (i, expected; CANONICAL_HASHES)
    {
        assert(got[i].name == expected.name,
            "hash[" ~ cast(string) [cast(char)('0' + i)] ~ "] name mismatch");
        assert(got[i].widthBits == expected.width,
            "hash width mismatch");
    }
}

void testConstants()
{
    assert(maxKeyBits() == 2048, "maxKeyBits must be 2048");
    assert(channels() == 8, "channels must be 8");
}

void testNewAndFree()
{
    auto s = Seed("blake3", 1024);
    assert(s.handle() != 0, "fresh Seed must hold a non-zero handle");
    assert(s.hashName() == "blake3");
    assert(s.width() == 256);
    // Destructor releases the handle at scope exit; no explicit `free`.
}

void testBadHash()
{
    auto err = collectException!ITBError(Seed("nonsense-hash", 1024));
    assert(err !is null, "Seed(nonsense) must throw");
    assert(err.statusCode == Status.BadHash,
        "expected Status.BadHash");
}

void testBadKeyBits()
{
    foreach (bits; [0, 256, 511, 2049])
    {
        auto err = collectException!ITBError(Seed("blake3", bits));
        assert(err !is null, "Seed bad bits must throw");
        assert(err.statusCode == Status.BadKeyBits,
            "expected Status.BadKeyBits");
    }
}

void testAllHashesAllWidthsSingle()
{
    auto plaintext = pseudoPayload(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBits; [512, 1024, 2048])
        {
            // Skip pairs where keyBits is not a multiple of width.
            if (keyBits % h.width != 0)
                continue;
            auto ns = Seed(h.name, keyBits);
            auto ds = Seed(h.name, keyBits);
            auto ss = Seed(h.name, keyBits);
            auto ct = encrypt(ns, ds, ss, plaintext);
            assert(ct.length > plaintext.length,
                "ciphertext must be longer than plaintext");
            auto pt = decrypt(ns, ds, ss, ct);
            assert(pt == plaintext,
                "Single roundtrip mismatch for " ~ h.name);
        }
    }
}

void testSeedWidthMismatch()
{
    auto ns = Seed("siphash24", 1024); // width 128
    auto ds = Seed("blake3", 1024);    // width 256
    auto ss = Seed("blake3", 1024);    // width 256
    auto err = collectException!ITBError(
        encrypt(ns, ds, ss, cast(const(ubyte)[]) "hello"));
    assert(err !is null, "width mix must throw");
    assert(err.statusCode == Status.SeedWidthMix,
        "expected Status.SeedWidthMix");
}

void testAllHashesAllWidthsTriple()
{
    auto plaintext = pseudoPayload(4096);
    foreach (h; CANONICAL_HASHES)
    {
        foreach (keyBits; [512, 1024, 2048])
        {
            if (keyBits % h.width != 0)
                continue;
            auto s0 = Seed(h.name, keyBits);
            auto s1 = Seed(h.name, keyBits);
            auto s2 = Seed(h.name, keyBits);
            auto s3 = Seed(h.name, keyBits);
            auto s4 = Seed(h.name, keyBits);
            auto s5 = Seed(h.name, keyBits);
            auto s6 = Seed(h.name, keyBits);
            auto ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);
            assert(ct.length > plaintext.length,
                "ciphertext must be longer than plaintext");
            auto pt = decryptTriple(s0, s1, s2, s3, s4, s5, s6, ct);
            assert(pt == plaintext,
                "Triple roundtrip mismatch for " ~ h.name);
        }
    }
}

void testTripleSeedWidthMismatch()
{
    auto odd = Seed("siphash24", 1024); // width 128
    auto r1  = Seed("blake3", 1024);    // width 256
    auto r2  = Seed("blake3", 1024);
    auto r3  = Seed("blake3", 1024);
    auto r4  = Seed("blake3", 1024);
    auto r5  = Seed("blake3", 1024);
    auto r6  = Seed("blake3", 1024);
    auto err = collectException!ITBError(
        encryptTriple(odd, r1, r2, r3, r4, r5, r6,
                      cast(const(ubyte)[]) "hello"));
    assert(err !is null, "width mix must throw");
    assert(err.statusCode == Status.SeedWidthMix,
        "expected Status.SeedWidthMix");
}

// Note: the `TestConfig` knob-mutation tests live in
// `test_config.d` — they mutate libitb's process-wide atomics
// (BitSoup / LockSoup / MaxWorkers / NonceBits / BarrierFill) and stay
// out of this file so the default-state roundtrip tests above remain
// race-free.

void main()
{
    testSingleRoundtripBlake3();
    testTripleRoundtripBlake3();
    testAuthRoundtripHmacSha256();
    testAuthTripleRoundtripKmac256();
    testSeedComponentsRoundtrip();
    testAuthDecryptTamperedFailsWithMACFailure();
    testSeedDropDoesNotPanic();
    testVersion();
    testListHashes();
    testConstants();
    testNewAndFree();
    testBadHash();
    testBadKeyBits();
    testAllHashesAllWidthsSingle();
    testSeedWidthMismatch();
    testAllHashesAllWidthsTriple();
    testTripleSeedWidthMismatch();
    writeln("test_roundtrip: ALL OK");
}
