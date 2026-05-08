// Streaming-style use of the high-level itb.Encryptor surface.
//
// Mirrors bindings/rust/tests/test_easy_streams.rs one-to-one.
//
// Streaming over the Encryptor surface lives entirely on the binding
// side (no separate StreamEncryptor / StreamDecryptor classes for the
// Easy API): the consumer slices the plaintext into chunks of the
// desired size and calls Encryptor.encrypt per chunk; the decrypt side
// walks the concatenated chunk stream by reading easyHeaderSize bytes,
// calling parseChunkLen, reading the remaining body, and feeding the
// full chunk to Encryptor.decrypt.
//
// Triple-Ouroboros (mode=3) and non-default nonce-bits configurations
// are covered explicitly so a regression in the per-instance
// easyHeaderSize / parseChunkLen path or in the seed plumbing surfaces
// here.

import std.algorithm.comparison : min;
import std.exception : collectException;
import std.random : Random, uniform;
import std.stdio : writefln;

import itb;

private enum size_t SMALL_CHUNK = 4096;

private Random rng;
static this() { rng = Random(0x12345678U); }

private ubyte[] tokenBytes(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte) uniform(0, 256, rng);
    return buf;
}

/// Encrypts `plaintext` chunk-by-chunk through `enc.encrypt` and
/// returns the concatenated ciphertext stream. Mirrors the Rust /
/// Python `_stream_encrypt` helper.
private ubyte[] streamEncrypt(ref Encryptor enc, const(ubyte)[] plaintext, size_t chunkSize)
{
    ubyte[] out_;
    size_t i = 0;
    while (i < plaintext.length)
    {
        size_t end = min(i + chunkSize, plaintext.length);
        auto ct = enc.encrypt(plaintext[i .. end]);
        out_ ~= ct;
        i = end;
    }
    return out_;
}

/// Drains the concatenated ciphertext stream chunk-by-chunk and
/// returns the recovered plaintext. Returns the trailing-bytes count
/// in `trailing` (0 on a clean stream); the caller asserts the
/// plausible-failure contract by checking `trailing > 0`.
private ubyte[] streamDecrypt(ref Encryptor enc, const(ubyte)[] ciphertext, out size_t trailing)
{
    ubyte[] out_;
    ubyte[] accumulator;
    size_t feedOff = 0;
    size_t headerSize = cast(size_t) enc.easyHeaderSize();

    while (feedOff < ciphertext.length)
    {
        size_t end = min(feedOff + SMALL_CHUNK, ciphertext.length);
        accumulator ~= ciphertext[feedOff .. end];
        feedOff = end;
        // Drain any complete chunks already in the accumulator.
        while (true)
        {
            if (accumulator.length < headerSize)
                break;
            size_t chunkLen = enc.parseChunkLen(accumulator[0 .. headerSize]);
            if (accumulator.length < chunkLen)
                break;
            auto pt = enc.decrypt(accumulator[0 .. chunkLen]).dup;
            out_ ~= pt;
            accumulator = accumulator[chunkLen .. $];
        }
    }
    trailing = accumulator.length;
    return out_;
}

void testStreamRoundtripDefaultNonceSingle()
{
    auto plaintext = tokenBytes(SMALL_CHUNK * 5 + 17);
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    size_t trailing;
    auto pt = streamDecrypt(enc, ct, trailing);
    assert(trailing == 0, "default-nonce single stream must drain cleanly");
    assert(pt == plaintext, "default-nonce single stream roundtrip mismatch");
}

void testStreamRoundtripNonDefaultNonceSingle()
{
    auto plaintext = tokenBytes(SMALL_CHUNK * 3 + 100);
    foreach (n; [256, 512])
    {
        auto enc = Encryptor("blake3", 1024, "kmac256", 1);
        enc.setNonceBits(n);
        auto ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
        size_t trailing;
        auto pt = streamDecrypt(enc, ct, trailing);
        assert(trailing == 0, "non-default-nonce single stream must drain cleanly");
        assert(pt == plaintext, "non-default-nonce single stream roundtrip mismatch");
    }
}

void testStreamTripleRoundtripDefaultNonce()
{
    auto plaintext = tokenBytes(SMALL_CHUNK * 4 + 33);
    auto enc = Encryptor("blake3", 1024, "kmac256", 3);
    auto ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    size_t trailing;
    auto pt = streamDecrypt(enc, ct, trailing);
    assert(trailing == 0, "Triple default-nonce stream must drain cleanly");
    assert(pt == plaintext, "Triple default-nonce stream roundtrip mismatch");
}

void testStreamTripleRoundtripNonDefaultNonce()
{
    auto plaintext = tokenBytes(SMALL_CHUNK * 3);
    foreach (n; [256, 512])
    {
        auto enc = Encryptor("blake3", 1024, "kmac256", 3);
        enc.setNonceBits(n);
        auto ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
        size_t trailing;
        auto pt = streamDecrypt(enc, ct, trailing);
        assert(trailing == 0, "Triple non-default-nonce stream must drain cleanly");
        assert(pt == plaintext, "Triple non-default-nonce stream roundtrip mismatch");
    }
}

void testStreamPartialChunkRaises()
{
    // Feeding only a partial chunk to the streaming decoder leaves a
    // trailing accumulator on close — same plausible-failure contract
    // as the lower-level StreamDecryptor.
    auto plaintext = new ubyte[100];
    plaintext[] = cast(ubyte) 'x';
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    // Feed only 30 bytes — header is complete (>= 20) but body
    // truncated. The drain loop must surface the trailing incomplete
    // chunk on close.
    size_t trailing;
    cast(void) streamDecrypt(enc, ct[0 .. 30], trailing);
    assert(trailing > 0, "trailing partial chunk must remain in accumulator");
}

void testParseChunkLenShortBuffer()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    size_t h = cast(size_t) enc.easyHeaderSize();
    auto buf = new ubyte[h - 1];
    auto err = collectException!ITBError(enc.parseChunkLen(buf));
    assert(err !is null, "short header buffer must throw");
    assert(err.statusCode == Status.BadInput,
        "short header buffer must surface as Status.BadInput");
}

void testParseChunkLenZeroDim()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    size_t h = cast(size_t) enc.easyHeaderSize();
    // headerSize bytes, but width / height fields are zero.
    auto hdr = new ubyte[h];
    auto err = collectException!ITBError(enc.parseChunkLen(hdr));
    assert(err !is null, "zero-dim header must throw");
}

void main()
{
    testStreamRoundtripDefaultNonceSingle();
    testStreamRoundtripNonDefaultNonceSingle();
    testStreamTripleRoundtripDefaultNonce();
    testStreamTripleRoundtripNonDefaultNonce();
    testStreamPartialChunkRaises();
    testParseChunkLenShortBuffer();
    testParseChunkLenZeroDim();
    writefln("test_easy_streams: ALL OK");
}
