// Phase-5 mirror: end-to-end tests for Authenticated Encryption.
//
// Mirrors bindings/rust/tests/test_auth.rs file-for-file: same matrix
// of 3 MACs × 3 hash widths × {Single, Triple} round-trip plus tamper
// rejection at the dynamic header offset and cross-MAC rejection.
import std.algorithm.comparison : min;
import std.exception : collectException;
import std.stdio : writeln;
import itb;

struct CanonicalMAC
{
    string name;
    int keySize;
    int tagSize;
    int minKeyBytes;
}

immutable CanonicalMAC[] CANONICAL_MACS = [
    CanonicalMAC("kmac256", 32, 32, 16),
    CanonicalMAC("hmac-sha256", 32, 32, 16),
    CanonicalMAC("hmac-blake3", 32, 32, 32),
];

// (hash, native width) representatives one per ITB key-width axis.
struct HashByWidth
{
    string name;
    int width;
}

immutable HashByWidth[] HASH_BY_WIDTH = [
    HashByWidth("siphash24", 128),
    HashByWidth("blake3", 256),
    HashByWidth("blake2b512", 512),
];

immutable ubyte[32] KEY_BYTES = 0x42;

ubyte[] pseudoPlaintext(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)(i & 0xff);
    return buf;
}

void testListMACs()
{
    auto got = listMACs();
    assert(got.length == CANONICAL_MACS.length, "MAC count mismatch");
    foreach (i, expected; CANONICAL_MACS)
    {
        assert(got[i].name == expected.name, "MAC name mismatch");
        assert(got[i].keySize == expected.keySize, "MAC keySize mismatch");
        assert(got[i].tagSize == expected.tagSize, "MAC tagSize mismatch");
        assert(got[i].minKeyBytes == expected.minKeyBytes,
            "MAC minKeyBytes mismatch");
    }
}

void testCreateAndFree()
{
    foreach (m; CANONICAL_MACS)
    {
        auto mac = MAC(m.name, KEY_BYTES);
        assert(mac.handle() != 0, "fresh MAC must hold non-zero handle");
        assert(mac.name() == m.name, "MAC name round-trip");
        // Destructor releases at scope exit.
    }
}

void testMACDropRelease()
{
    // Equivalent of the Python context-manager test: the destructor
    // must release the handle when the value goes out of scope.
    size_t h;
    {
        auto mac = MAC("hmac-sha256", KEY_BYTES);
        h = mac.handle();
        assert(h != 0);
    }
    // No assertion possible after drop, but a use-after-free in libitb
    // would surface as a test crash here.
}

void testBadName()
{
    auto err = collectException!ITBError(MAC("nonsense-mac", KEY_BYTES));
    assert(err !is null, "bad MAC name must throw");
    assert(err.statusCode == Status.BadMAC);
}

void testShortKey()
{
    foreach (m; CANONICAL_MACS)
    {
        auto shortKey = new ubyte[m.minKeyBytes - 1];
        shortKey[] = 0x11;
        auto err = collectException!ITBError(MAC(m.name, shortKey));
        assert(err !is null, "short MAC key must throw");
        assert(err.statusCode == Status.BadInput,
            "expected BadInput on short MAC key for " ~ m.name);
    }
}

void testAuthRoundtripAllMacsAllWidths()
{
    auto plaintext = pseudoPlaintext(4096);
    foreach (m; CANONICAL_MACS)
    {
        foreach (h; HASH_BY_WIDTH)
        {
            auto mac = MAC(m.name, KEY_BYTES);
            auto n = Seed(h.name, 1024);
            auto d = Seed(h.name, 1024);
            auto s = Seed(h.name, 1024);
            auto ct = encryptAuth(n, d, s, mac, plaintext);
            auto pt = decryptAuth(n, d, s, mac, ct);
            assert(pt == plaintext,
                "Auth Single roundtrip mismatch: " ~ m.name ~ "/" ~ h.name);

            // Tamper at the dynamic header offset.
            auto tampered = ct.dup;
            size_t hs = cast(size_t) headerSize();
            size_t upper = min(hs + 256, tampered.length);
            foreach (j; hs .. upper)
                tampered[j] ^= 0x01;
            auto err = collectException!ITBError(
                decryptAuth(n, d, s, mac, tampered));
            assert(err !is null, "tampered ciphertext must throw");
            assert(err.statusCode == Status.MACFailure,
                "expected Status.MACFailure on tampered ciphertext");
        }
    }
}

void testAuthTripleRoundtripAllMacsAllWidths()
{
    auto plaintext = pseudoPlaintext(4096);
    foreach (m; CANONICAL_MACS)
    {
        foreach (h; HASH_BY_WIDTH)
        {
            auto mac = MAC(m.name, KEY_BYTES);
            auto n  = Seed(h.name, 1024);
            auto d1 = Seed(h.name, 1024);
            auto d2 = Seed(h.name, 1024);
            auto d3 = Seed(h.name, 1024);
            auto s1 = Seed(h.name, 1024);
            auto s2 = Seed(h.name, 1024);
            auto s3 = Seed(h.name, 1024);
            auto ct = encryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, plaintext);
            auto pt = decryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, ct);
            assert(pt == plaintext,
                "Auth Triple roundtrip mismatch: " ~ m.name ~ "/" ~ h.name);

            auto tampered = ct.dup;
            size_t hs = cast(size_t) headerSize();
            size_t upper = min(hs + 256, tampered.length);
            foreach (j; hs .. upper)
                tampered[j] ^= 0x01;
            auto err = collectException!ITBError(
                decryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, tampered));
            assert(err !is null, "tampered Triple ciphertext must throw");
            assert(err.statusCode == Status.MACFailure);
        }
    }
}

void testCrossMACDifferentPrimitive()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto encMac = MAC("kmac256", KEY_BYTES);
    auto decMac = MAC("hmac-sha256", KEY_BYTES);
    auto ct = encryptAuth(n, d, s, encMac,
        cast(const(ubyte)[]) "authenticated payload");
    auto err = collectException!ITBError(decryptAuth(n, d, s, decMac, ct));
    assert(err !is null, "cross-MAC primitive must throw");
    assert(err.statusCode == Status.MACFailure);
}

void testCrossMACSamePrimitiveDifferentKey()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    ubyte[32] keyA = 0x01;
    ubyte[32] keyB = 0x02;
    auto encMac = MAC("hmac-sha256", keyA);
    auto decMac = MAC("hmac-sha256", keyB);
    auto ct = encryptAuth(n, d, s, encMac,
        cast(const(ubyte)[]) "authenticated payload");
    auto err = collectException!ITBError(decryptAuth(n, d, s, decMac, ct));
    assert(err !is null, "cross-MAC key must throw");
    assert(err.statusCode == Status.MACFailure);
}

void main()
{
    testListMACs();
    testCreateAndFree();
    testMACDropRelease();
    testBadName();
    testShortKey();
    testAuthRoundtripAllMacsAllWidths();
    testAuthTripleRoundtripAllMacsAllWidths();
    testCrossMACDifferentPrimitive();
    testCrossMACSamePrimitiveDifferentKey();
    writeln("test_auth: ALL OK");
}
