// Round-trip tests across every per-instance nonce-size configuration.
//
// The Encryptor surface exposes nonce_bits as a per-instance setter
// (Encryptor.setNonceBits) rather than a process-wide config — each
// encryptor's easyHeaderSize and parseChunkLen track its own
// nonce_bits state without touching the process-wide setNonceBits /
// getNonceBits accessors. None of the tests in this file mutate
// process-global state.
//
// Mirrors bindings/rust/tests/test_easy_nonce_sizes.rs one-to-one.

import std.algorithm : min;
import std.exception : collectException;
import std.random : Random, uniform;
import std.stdio : writeln;

import itb;

private static immutable int[] NONCE_SIZES = [128, 256, 512];
private static immutable string[] HASHES =
    ["siphash24", "blake3", "blake2b512"];
private static immutable string[] MACS =
    ["kmac256", "hmac-sha256", "hmac-blake3"];

private Random rng;
static this() { rng = Random(0xA5A5A5A5U); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

void testHeaderSizeDefaultIs20()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    assert(enc.easyHeaderSize() == 20,
        "default header size must be 20");
    assert(enc.nonceBits() == 128,
        "default nonce bits must be 128");
}

void testHeaderSizeDynamic()
{
    foreach (n; NONCE_SIZES)
    {
        auto enc = Encryptor("blake3", 1024, "kmac256", 1);
        enc.setNonceBits(n);
        assert(enc.nonceBits() == n,
            "nonceBits round-trip mismatch");
        assert(enc.easyHeaderSize() == n / 8 + 4,
            "easyHeaderSize formula mismatch");
    }
}

void testEncryptDecryptAcrossNonceSizesSingle()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (hashName; HASHES)
        {
            auto enc = Encryptor(hashName, 1024, "kmac256", 1);
            enc.setNonceBits(n);
            auto ct = enc.encrypt(plaintext).dup;
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext,
                "Single nonce-size roundtrip mismatch");
            auto h = enc.easyHeaderSize();
            auto parsed = enc.parseChunkLen(ct[0 .. h]);
            assert(parsed == ct.length,
                "parseChunkLen mismatch");
        }
    }
}

void testEncryptDecryptAcrossNonceSizesTriple()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (hashName; HASHES)
        {
            auto enc = Encryptor(hashName, 1024, "kmac256", 3);
            enc.setNonceBits(n);
            auto ct = enc.encrypt(plaintext).dup;
            auto pt = enc.decrypt(ct).dup;
            assert(pt == plaintext,
                "Triple nonce-size roundtrip mismatch");
            auto h = enc.easyHeaderSize();
            auto parsed = enc.parseChunkLen(ct[0 .. h]);
            assert(parsed == ct.length,
                "parseChunkLen mismatch");
        }
    }
}

void testAuthAcrossNonceSizesSingle()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MACS)
        {
            auto enc = Encryptor("blake3", 1024, macName, 1);
            enc.setNonceBits(n);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext,
                "auth Single nonce-size roundtrip mismatch");
            auto tampered = ct.dup;
            auto h = enc.easyHeaderSize();
            auto end = min(h + 256, tampered.length);
            foreach (i; h .. end)
                tampered[i] ^= 0x01;
            auto err = collectException!ITBError(enc.decryptAuth(tampered));
            assert(err !is null, "tampered auth must throw");
            assert(err.statusCode == Status.MACFailure);
        }
    }
}

void testAuthAcrossNonceSizesTriple()
{
    auto plaintext = tokenBytes(1024);
    foreach (n; NONCE_SIZES)
    {
        foreach (macName; MACS)
        {
            auto enc = Encryptor("blake3", 1024, macName, 3);
            enc.setNonceBits(n);
            auto ct = enc.encryptAuth(plaintext).dup;
            auto pt = enc.decryptAuth(ct).dup;
            assert(pt == plaintext,
                "auth Triple nonce-size roundtrip mismatch");
            auto tampered = ct.dup;
            auto h = enc.easyHeaderSize();
            auto end = min(h + 256, tampered.length);
            foreach (i; h .. end)
                tampered[i] ^= 0x01;
            auto err = collectException!ITBError(enc.decryptAuth(tampered));
            assert(err !is null, "tampered auth must throw");
            assert(err.statusCode == Status.MACFailure);
        }
    }
}

void testTwoEncryptorsIndependentNonceBits()
{
    auto plaintext = cast(const(ubyte)[]) "isolation test";
    auto a = Encryptor("blake3", 1024, "kmac256", 1);
    auto b = Encryptor("blake3", 1024, "kmac256", 1);
    a.setNonceBits(512);
    assert(a.nonceBits() == 512);
    assert(a.easyHeaderSize() == 68);
    assert(b.nonceBits() == 128);
    assert(b.easyHeaderSize() == 20);
    auto ctA = a.encrypt(plaintext).dup;
    auto ptA = a.decrypt(ctA).dup;
    assert(ptA == plaintext, "encryptor A roundtrip mismatch");
    auto ctB = b.encrypt(plaintext).dup;
    auto ptB = b.decrypt(ctB).dup;
    assert(ptB == plaintext, "encryptor B roundtrip mismatch");
}

void main()
{
    testHeaderSizeDefaultIs20();
    testHeaderSizeDynamic();
    testEncryptDecryptAcrossNonceSizesSingle();
    testEncryptDecryptAcrossNonceSizesTriple();
    testAuthAcrossNonceSizesSingle();
    testAuthAcrossNonceSizesTriple();
    testTwoEncryptorsIndependentNonceBits();
    writeln("test_easy_nonce_sizes: ALL OK");
}
