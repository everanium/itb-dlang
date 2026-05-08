// Authenticated Streaming AEAD tests for the Easy Mode Encryptor
// (Encryptor.encryptStreamAuth / Encryptor.decryptStreamAuth).
// Mirrors the seed-based suite in test_streams_auth.d at the
// Encryptor abstraction level.

import std.algorithm.comparison : min;
import std.exception : collectException;
import std.stdio : writeln;
import itb;

enum size_t SMALL_CHUNK = 4096;

private static immutable string[] CANONICAL_MACS =
    ["kmac256", "hmac-sha256", "hmac-blake3"];
private static immutable string[] HASH_BY_WIDTH =
    ["siphash24", "blake3", "areion512"];

private ubyte[] pseudoPlaintext(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)((i * 17 + 3) & 0xff);
    return buf;
}

private struct EasyChunkSplit { ubyte[] prefix; ubyte[][] chunks; }

private EasyChunkSplit splitChunksEasy(ref Encryptor enc, const(ubyte)[] ct)
{
    ubyte[] prefix = ct[0 .. 32].dup;
    size_t hsz = cast(size_t) enc.easyHeaderSize();
    ubyte[][] chunks;
    size_t off = 32;
    while (off < ct.length)
    {
        size_t chunkLen = enc.parseChunkLen(ct[off .. off + hsz]);
        chunks ~= ct[off .. off + chunkLen].dup;
        off += chunkLen;
    }
    return EasyChunkSplit(prefix, chunks);
}

void testEasyAuthStreamSingleRoundtripMatrix()
{
    foreach (hashName; HASH_BY_WIDTH)
    {
        foreach (macName; CANONICAL_MACS)
        {
            auto enc = Encryptor(hashName, 1024, macName, 1);
            auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 11);
            ubyte[] ct;
            size_t off = 0;
            enc.encryptStreamAuth(
                (ubyte[] buf) @trusted {
                    size_t avail = plaintext.length - off;
                    size_t take = avail < buf.length ? avail : buf.length;
                    buf[0 .. take] = plaintext[off .. off + take];
                    off += take;
                    return take;
                },
                (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
                SMALL_CHUNK);
            ubyte[] recovered;
            size_t roff = 0;
            enc.decryptStreamAuth(
                (ubyte[] buf) @trusted {
                    size_t avail = ct.length - roff;
                    size_t take = avail < buf.length ? avail : buf.length;
                    buf[0 .. take] = ct[roff .. roff + take];
                    roff += take;
                    return take;
                },
                (const(ubyte)[] pt) @trusted { recovered ~= pt; },
                4096);
            assert(recovered == plaintext,
                "Single auth roundtrip mismatch: " ~ hashName ~ "/" ~ macName);
        }
    }
}

void testEasyAuthStreamTripleRoundtripMatrix()
{
    foreach (hashName; HASH_BY_WIDTH)
    {
        foreach (macName; CANONICAL_MACS)
        {
            auto enc = Encryptor(hashName, 1024, macName, 3);
            auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 7);
            ubyte[] ct;
            size_t off = 0;
            enc.encryptStreamAuth(
                (ubyte[] buf) @trusted {
                    size_t avail = plaintext.length - off;
                    size_t take = avail < buf.length ? avail : buf.length;
                    buf[0 .. take] = plaintext[off .. off + take];
                    off += take;
                    return take;
                },
                (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
                SMALL_CHUNK);
            ubyte[] recovered;
            size_t roff = 0;
            enc.decryptStreamAuth(
                (ubyte[] buf) @trusted {
                    size_t avail = ct.length - roff;
                    size_t take = avail < buf.length ? avail : buf.length;
                    buf[0 .. take] = ct[roff .. roff + take];
                    roff += take;
                    return take;
                },
                (const(ubyte)[] pt) @trusted { recovered ~= pt; },
                4096);
            assert(recovered == plaintext,
                "Triple auth roundtrip mismatch: " ~ hashName ~ "/" ~ macName);
        }
    }
}

void testEasyAuthStreamEmpty()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    ubyte[] ct;
    enc.encryptStreamAuth(
        (ubyte[] buf) @trusted => cast(size_t) 0,
        (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
        SMALL_CHUNK);
    assert(ct.length > 32);
    ubyte[] recovered;
    size_t roff = 0;
    enc.decryptStreamAuth(
        (ubyte[] buf) @trusted {
            size_t avail = ct.length - roff;
            size_t take = avail < buf.length ? avail : buf.length;
            buf[0 .. take] = ct[roff .. roff + take];
            roff += take;
            return take;
        },
        (const(ubyte)[] pt) @trusted { recovered ~= pt; },
        4096);
    assert(recovered.length == 0);
}

void testEasyAuthStreamSingleChunk()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto plaintext = cast(ubyte[]) "single short stream payload".dup;
    ubyte[] ct;
    size_t off = 0;
    enc.encryptStreamAuth(
        (ubyte[] buf) @trusted {
            size_t avail = plaintext.length - off;
            size_t take = avail < buf.length ? avail : buf.length;
            buf[0 .. take] = plaintext[off .. off + take];
            off += take;
            return take;
        },
        (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
        SMALL_CHUNK);
    ubyte[] recovered;
    size_t roff = 0;
    enc.decryptStreamAuth(
        (ubyte[] buf) @trusted {
            size_t avail = ct.length - roff;
            size_t take = avail < buf.length ? avail : buf.length;
            buf[0 .. take] = ct[roff .. roff + take];
            roff += take;
            return take;
        },
        (const(ubyte)[] pt) @trusted { recovered ~= pt; },
        4096);
    assert(recovered == plaintext);
}

private ubyte[] easyEncrypt(ref Encryptor enc, const(ubyte)[] plaintext, size_t cs)
{
    ubyte[] ct;
    size_t off = 0;
    enc.encryptStreamAuth(
        (ubyte[] buf) @trusted {
            size_t avail = plaintext.length - off;
            size_t take = avail < buf.length ? avail : buf.length;
            buf[0 .. take] = plaintext[off .. off + take];
            off += take;
            return take;
        },
        (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
        cs);
    return ct;
}

void testEasyAuthStreamReorderDetected()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 5);
    auto ct = easyEncrypt(enc, plaintext, SMALL_CHUNK);
    auto split = splitChunksEasy(enc, ct);
    assert(split.chunks.length >= 3);
    auto swap = split.chunks[0];
    split.chunks[0] = split.chunks[1];
    split.chunks[1] = swap;
    ubyte[] tampered = split.prefix.dup;
    foreach (c; split.chunks)
        tampered ~= c;
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = tampered.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = tampered[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.MACFailure);
}

void testEasyAuthStreamTruncateTailDetected()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 1);
    auto ct = easyEncrypt(enc, plaintext, SMALL_CHUNK);
    auto split = splitChunksEasy(enc, ct);
    ubyte[] truncated = split.prefix.dup;
    foreach (c; split.chunks[0 .. $ - 1])
        truncated ~= c;
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBStreamTruncatedError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = truncated.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = truncated[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.StreamTruncated);
}

void testEasyAuthStreamAfterFinalDetected()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto pa = pseudoPlaintext(64);
    auto pb = pseudoPlaintext(SMALL_CHUNK * 2);
    auto ctA = easyEncrypt(enc, pa, SMALL_CHUNK);
    auto ctB = easyEncrypt(enc, pb, SMALL_CHUNK);
    auto splitB = splitChunksEasy(enc, ctB);
    ctA ~= splitB.chunks[0];
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBStreamAfterFinalError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = ctA.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = ctA[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.StreamAfterFinal);
}

void testEasyAuthStreamCrossStreamReplayDetected()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto pa = pseudoPlaintext(SMALL_CHUNK * 2);
    auto pb = pseudoPlaintext(SMALL_CHUNK * 2);
    auto ctA = easyEncrypt(enc, pa, SMALL_CHUNK);
    auto ctB = easyEncrypt(enc, pb, SMALL_CHUNK);
    auto splitA = splitChunksEasy(enc, ctA);
    auto splitB = splitChunksEasy(enc, ctB);
    ubyte[] spliced = splitA.prefix.dup;
    spliced ~= splitB.chunks[0];
    foreach (c; splitA.chunks[1 .. $])
        spliced ~= c;
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = spliced.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = spliced[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.MACFailure);
}

void testEasyAuthStreamPrefixTamperDetected()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2);
    auto ct = easyEncrypt(enc, plaintext, SMALL_CHUNK);
    ct[5] ^= 0x80;
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = ct.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = ct[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.MACFailure);
}

void testEasyAuthStreamClosedPreflight()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    enc.close();
    ubyte[] ct;
    auto err = collectException!ITBError(
        enc.encryptStreamAuth(
            (ubyte[] buf) @trusted => cast(size_t) 0,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK));
    assert(err !is null);
    assert(err.statusCode == Status.EasyClosed);
    ubyte[] recovered;
    auto err2 = collectException!ITBError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted => cast(size_t) 0,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err2 !is null);
    assert(err2.statusCode == Status.EasyClosed);
}

void testEasyAuthStreamTruncateBelowPrefix()
{
    auto enc = Encryptor("blake3", 1024, "hmac-blake3", 1);
    auto ct = easyEncrypt(enc, cast(const(ubyte)[]) "abc", SMALL_CHUNK);
    auto head = ct[0 .. 10].dup;
    ubyte[] recovered;
    size_t roff = 0;
    auto err = collectException!ITBError(
        enc.decryptStreamAuth(
            (ubyte[] buf) @trusted {
                size_t avail = head.length - roff;
                size_t take = avail < buf.length ? avail : buf.length;
                buf[0 .. take] = head[roff .. roff + take];
                roff += take;
                return take;
            },
            (const(ubyte)[] pt) @trusted { recovered ~= pt; },
            4096));
    assert(err !is null);
    assert(err.statusCode == Status.BadInput);
}

void main()
{
    testEasyAuthStreamSingleRoundtripMatrix();
    testEasyAuthStreamTripleRoundtripMatrix();
    testEasyAuthStreamEmpty();
    testEasyAuthStreamSingleChunk();
    testEasyAuthStreamReorderDetected();
    testEasyAuthStreamTruncateTailDetected();
    testEasyAuthStreamAfterFinalDetected();
    testEasyAuthStreamCrossStreamReplayDetected();
    testEasyAuthStreamPrefixTamperDetected();
    testEasyAuthStreamClosedPreflight();
    testEasyAuthStreamTruncateBelowPrefix();
    writeln("test_easy_streams_auth: ALL OK");
}
