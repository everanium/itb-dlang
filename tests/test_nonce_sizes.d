// Phase-5 mirror: round-trip tests across all nonce-size configurations.
//
// Mirrors bindings/rust/tests/test_nonce_sizes.rs file-for-file.
//
// ITB exposes a runtime-configurable nonce size (setNonceBits) that
// takes one of {128, 256, 512}. The on-the-wire chunk header therefore
// varies between 20, 36, and 68 bytes; every consumer that walks
// ciphertext on the byte level (chunk parsers, tampering tests,
// streaming decoders) must use headerSize() rather than a hardcoded
// constant.
//
// Each test snapshots the original nonce setting on entry and restores
// it on exit so subsequent suites run unaffected. GLOBAL-STATE
// MUTATING — kept in this dedicated file so per-process isolation
// makes it safe.
import std.algorithm.comparison : min;
import std.exception : collectException;
import std.stdio : writeln;
import itb;

immutable int[] NONCE_SIZES = [128, 256, 512];
immutable string[] HASHES = ["siphash24", "blake3", "blake2b512"];
immutable string[] MAC_NAMES = ["kmac256", "hmac-sha256", "hmac-blake3"];
immutable ubyte[32] MAC_KEY = 0x73;

ubyte[] pseudoPlaintext(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)((i * 31 + 7) & 0xff);
    return buf;
}

void withNonceBits(int n, void delegate() body_)
{
    auto prev = getNonceBits();
    setNonceBits(n);
    body_();
    setNonceBits(prev);
}

void testDefaultIs20()
{
    auto prev = getNonceBits();
    setNonceBits(128);
    assert(headerSize() == 20, "headerSize() must be 20 at nonce=128");
    assert(getNonceBits() == 128, "getNonceBits roundtrip");
    setNonceBits(prev);
}

void testHeaderSizeDynamic()
{
    foreach (n; NONCE_SIZES)
    {
        withNonceBits(n, ()
        {
            assert(headerSize() == n / 8 + 4,
                "headerSize() must track active nonce");
        });
    }
}

void testEncryptDecryptAcrossNonceSizes()
{
    auto plaintext = pseudoPlaintext(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (hashName; HASHES)
        {
            withNonceBits(n, ()
            {
                auto ns = Seed(hashName, 1024);
                auto ds = Seed(hashName, 1024);
                auto ss = Seed(hashName, 1024);
                auto ct = encrypt(ns, ds, ss, plaintext);
                auto pt = decrypt(ns, ds, ss, ct);
                assert(pt == plaintext,
                    "Single roundtrip mismatch at nonce=" ~ hashName);
                size_t hs = cast(size_t) headerSize();
                auto chunkLen = parseChunkLen(ct[0 .. hs]);
                assert(chunkLen == ct.length,
                    "parseChunkLen must report full chunk length");
            });
        }
    }
}

void testTripleEncryptDecryptAcrossNonceSizes()
{
    auto plaintext = pseudoPlaintext(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (hashName; HASHES)
        {
            withNonceBits(n, ()
            {
                auto s0 = Seed(hashName, 1024);
                auto s1 = Seed(hashName, 1024);
                auto s2 = Seed(hashName, 1024);
                auto s3 = Seed(hashName, 1024);
                auto s4 = Seed(hashName, 1024);
                auto s5 = Seed(hashName, 1024);
                auto s6 = Seed(hashName, 1024);
                auto ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);
                auto pt = decryptTriple(s0, s1, s2, s3, s4, s5, s6, ct);
                assert(pt == plaintext, "Triple roundtrip mismatch");
            });
        }
    }
}

void testAuthAcrossNonceSizes()
{
    auto plaintext = pseudoPlaintext(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            withNonceBits(n, ()
            {
                auto mac = MAC(macName, MAC_KEY);
                auto ns = Seed("blake3", 1024);
                auto ds = Seed("blake3", 1024);
                auto ss = Seed("blake3", 1024);
                auto ct = encryptAuth(ns, ds, ss, mac, plaintext);
                auto pt = decryptAuth(ns, ds, ss, mac, ct);
                assert(pt == plaintext, "Auth roundtrip mismatch");

                auto tampered = ct.dup;
                size_t hs = cast(size_t) headerSize();
                size_t upper = min(hs + 256, tampered.length);
                foreach (j; hs .. upper)
                    tampered[j] ^= 0x01;
                auto err = collectException!ITBError(
                    decryptAuth(ns, ds, ss, mac, tampered));
                assert(err !is null, "tampered Auth must throw");
                assert(err.statusCode == Status.MACFailure);
            });
        }
    }
}

void testTripleAuthAcrossNonceSizes()
{
    auto plaintext = pseudoPlaintext(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MAC_NAMES)
        {
            withNonceBits(n, ()
            {
                auto mac = MAC(macName, MAC_KEY);
                auto s0 = Seed("blake3", 1024);
                auto s1 = Seed("blake3", 1024);
                auto s2 = Seed("blake3", 1024);
                auto s3 = Seed("blake3", 1024);
                auto s4 = Seed("blake3", 1024);
                auto s5 = Seed("blake3", 1024);
                auto s6 = Seed("blake3", 1024);
                auto ct = encryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, plaintext);
                auto pt = decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, ct);
                assert(pt == plaintext, "Triple Auth roundtrip mismatch");

                auto tampered = ct.dup;
                size_t hs = cast(size_t) headerSize();
                size_t upper = min(hs + 256, tampered.length);
                foreach (j; hs .. upper)
                    tampered[j] ^= 0x01;
                auto err = collectException!ITBError(
                    decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, tampered));
                assert(err !is null, "tampered Triple Auth must throw");
                assert(err.statusCode == Status.MACFailure);
            });
        }
    }
}

void main()
{
    testDefaultIs20();
    testHeaderSizeDynamic();
    testEncryptDecryptAcrossNonceSizes();
    testTripleEncryptDecryptAcrossNonceSizes();
    testAuthAcrossNonceSizes();
    testTripleAuthAcrossNonceSizes();
    writeln("test_nonce_sizes: ALL OK");
}
