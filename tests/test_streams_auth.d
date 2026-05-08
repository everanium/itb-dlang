// Authenticated Streaming AEAD tests for the seed-based
// StreamEncryptorAuth / StreamDecryptorAuth classes and their
// free-function encryptStreamAuth / decryptStreamAuth counterparts
// (Single + Triple Ouroboros at every native hash width and across
// the three shipped MAC primitives).
//
// Coverage: per-(width × Single/Triple × MAC) round-trip; reorder;
// truncate-tail; cross-stream replay; stream-prefix tamper; empty
// stream; single-chunk; closed-state preflight; destructor flush.

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
        buf[i] = cast(ubyte)((i * 31 + 7) & 0xff);
    return buf;
}

private MAC mkMAC(string name)
{
    auto key = new ubyte[32];
    foreach (i; 0 .. 32)
        key[i] = 0x5A;
    return MAC(name, key);
}

void testAuthStreamSingleRoundtripMatrix()
{
    foreach (hashName; HASH_BY_WIDTH)
    {
        foreach (macName; CANONICAL_MACS)
        {
            auto n = Seed(hashName, 1024);
            auto d = Seed(hashName, 1024);
            auto s = Seed(hashName, 1024);
            auto mac = mkMAC(macName);
            auto plaintext = pseudoPlaintext(SMALL_CHUNK * 3 + 17);
            ubyte[] ct;
            {
                auto enc = StreamEncryptorAuth(n, d, s, mac,
                    (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
                    SMALL_CHUNK);
                enc.write(plaintext);
                enc.close();
            }
            assert(ct.length > 32, "auth roundtrip ciphertext too short");
            ubyte[] recovered;
            {
                auto dec = StreamDecryptorAuth(n, d, s, mac,
                    (const(ubyte)[] pt) @trusted { recovered ~= pt; });
                size_t off = 0;
                while (off < ct.length)
                {
                    size_t end = min(off + 4096, ct.length);
                    dec.feed(ct[off .. end]);
                    off = end;
                }
                dec.close();
            }
            assert(recovered == plaintext,
                "Single auth roundtrip mismatch: " ~ hashName ~ "/" ~ macName);
        }
    }
}

void testAuthStreamTripleRoundtripMatrix()
{
    foreach (hashName; HASH_BY_WIDTH)
    {
        foreach (macName; CANONICAL_MACS)
        {
            auto noise = Seed(hashName, 1024);
            auto d1 = Seed(hashName, 1024);
            auto d2 = Seed(hashName, 1024);
            auto d3 = Seed(hashName, 1024);
            auto s1 = Seed(hashName, 1024);
            auto s2 = Seed(hashName, 1024);
            auto s3 = Seed(hashName, 1024);
            auto mac = mkMAC(macName);
            auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 1);
            ubyte[] ct;
            {
                auto enc = StreamEncryptorAuth3(
                    noise, d1, d2, d3, s1, s2, s3, mac,
                    (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
                    SMALL_CHUNK);
                enc.write(plaintext);
                enc.close();
            }
            ubyte[] recovered;
            {
                auto dec = StreamDecryptorAuth3(
                    noise, d1, d2, d3, s1, s2, s3, mac,
                    (const(ubyte)[] pt) @trusted { recovered ~= pt; });
                dec.feed(ct);
                dec.close();
            }
            assert(recovered == plaintext,
                "Triple auth roundtrip mismatch: " ~ hashName ~ "/" ~ macName);
        }
    }
}

void testAuthStreamEmpty()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    ubyte[] ct;
    encryptStreamAuth(n, d, s, mac,
        (ubyte[] buf) @trusted => cast(size_t) 0,
        (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
        SMALL_CHUNK);
    assert(ct.length > 32, "empty stream still emits prefix + 1 chunk");
    ubyte[] recovered;
    size_t roff = 0;
    decryptStreamAuth(n, d, s, mac,
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

void testAuthStreamSingleChunk()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto plaintext = cast(ubyte[]) "single short payload".dup;
    ubyte[] ct;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK);
        enc.write(plaintext);
        enc.close();
    }
    ubyte[] recovered;
    {
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(ct);
        dec.close();
    }
    assert(recovered == plaintext);
}

private struct ChunkSplit { ubyte[] prefix; ubyte[][] chunks; }

private ChunkSplit splitChunks(const(ubyte)[] ct)
{
    ubyte[] prefix = ct[0 .. 32].dup;
    size_t hsz = cast(size_t) headerSize();
    ubyte[][] chunks;
    size_t off = 32;
    while (off < ct.length)
    {
        size_t chunkLen = parseChunkLen(ct[off .. off + hsz]);
        chunks ~= ct[off .. off + chunkLen].dup;
        off += chunkLen;
    }
    return ChunkSplit(prefix, chunks);
}

void testAuthStreamReorderDetected()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 1);
    ubyte[] ct;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK);
        enc.write(plaintext);
        enc.close();
    }
    auto split = splitChunks(ct);
    assert(split.chunks.length >= 3, "need ≥ 3 chunks for reorder");
    auto swap = split.chunks[0];
    split.chunks[0] = split.chunks[1];
    split.chunks[1] = swap;
    ubyte[] tampered = split.prefix.dup;
    foreach (c; split.chunks)
        tampered ~= c;
    ubyte[] recovered;
    auto err = collectException!ITBError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(tampered);
        dec.close();
    }());
    assert(err !is null, "reorder must throw");
    assert(err.statusCode == Status.MACFailure,
        "reorder must surface MACFailure");
}

void testAuthStreamTruncateTailDetected()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2 + 1);
    ubyte[] ct;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK);
        enc.write(plaintext);
        enc.close();
    }
    auto split = splitChunks(ct);
    ubyte[] truncated = split.prefix.dup;
    foreach (c; split.chunks[0 .. $ - 1])
        truncated ~= c;
    ubyte[] recovered;
    auto err = collectException!ITBStreamTruncatedError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(truncated);
        dec.close();
    }());
    assert(err !is null, "truncate-tail must throw");
    assert(err.statusCode == Status.StreamTruncated);
}

void testAuthStreamAfterFinalDetected()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto pa = pseudoPlaintext(64);
    auto pb = pseudoPlaintext(SMALL_CHUNK * 2);
    ubyte[] ctA, ctB;
    {
        auto encA = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ctA ~= chunk; },
            SMALL_CHUNK);
        encA.write(pa);
        encA.close();
    }
    {
        auto encB = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ctB ~= chunk; },
            SMALL_CHUNK);
        encB.write(pb);
        encB.close();
    }
    auto splitB = splitChunks(ctB);
    ctA ~= splitB.chunks[0];
    ubyte[] recovered;
    auto err = collectException!ITBError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(ctA);
        dec.close();
    }());
    assert(err !is null, "after-final must throw");
    assert(err.statusCode == Status.StreamAfterFinal);
}

void testAuthStreamCrossStreamReplayDetected()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto pa = pseudoPlaintext(SMALL_CHUNK * 2);
    auto pb = pseudoPlaintext(SMALL_CHUNK * 2);
    ubyte[] ctA, ctB;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ctA ~= chunk; },
            SMALL_CHUNK);
        enc.write(pa);
        enc.close();
    }
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ctB ~= chunk; },
            SMALL_CHUNK);
        enc.write(pb);
        enc.close();
    }
    auto splitA = splitChunks(ctA);
    auto splitB = splitChunks(ctB);
    ubyte[] spliced = splitA.prefix.dup;
    spliced ~= splitB.chunks[0];
    foreach (c; splitA.chunks[1 .. $])
        spliced ~= c;
    ubyte[] recovered;
    auto err = collectException!ITBError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(spliced);
        dec.close();
    }());
    assert(err !is null, "cross-stream replay must throw");
    assert(err.statusCode == Status.MACFailure);
}

void testAuthStreamPrefixTamperDetected()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 2);
    ubyte[] ct;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK);
        enc.write(plaintext);
        enc.close();
    }
    ct[5] ^= 0x80;
    ubyte[] recovered;
    auto err = collectException!ITBError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(ct);
        dec.close();
    }());
    assert(err !is null, "prefix tamper must throw");
    assert(err.statusCode == Status.MACFailure
        || err.statusCode == Status.BadMAC);
}

void testAuthStreamWriteAfterCloseRaises()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    ubyte[] sink;
    auto enc = StreamEncryptorAuth(n, d, s, mac,
        (const(ubyte)[] chunk) @trusted { sink ~= chunk; },
        SMALL_CHUNK);
    enc.write(cast(const(ubyte)[]) "hello");
    enc.close();
    auto err = collectException!ITBError(
        enc.write(cast(const(ubyte)[]) "world"));
    assert(err !is null, "write after close must throw");
    assert(err.statusCode == Status.EasyClosed);
}

void testAuthStreamDestructorFlushes()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    ubyte[] sink;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { sink ~= chunk; },
            SMALL_CHUNK);
        enc.write(cast(const(ubyte)[]) "drop-flush");
        // Destructor invokes close().
    }
    ubyte[] recovered;
    {
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(sink);
        dec.close();
    }
    assert(recovered == cast(const(ubyte)[]) "drop-flush");
}

void testAuthStreamTruncateBelowPrefix()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("hmac-blake3");
    ubyte[] ct;
    {
        auto enc = StreamEncryptorAuth(n, d, s, mac,
            (const(ubyte)[] chunk) @trusted { ct ~= chunk; },
            SMALL_CHUNK);
        enc.write(cast(const(ubyte)[]) "abc");
        enc.close();
    }
    auto head = ct[0 .. 16].dup;
    ubyte[] recovered;
    auto err = collectException!ITBError({
        auto dec = StreamDecryptorAuth(n, d, s, mac,
            (const(ubyte)[] pt) @trusted { recovered ~= pt; });
        dec.feed(head);
        dec.close();
    }());
    assert(err !is null, "partial prefix must throw");
    assert(err.statusCode == Status.BadInput);
}

void testAuthStreamFreeFunctionRoundtrip()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    auto mac = mkMAC("kmac256");
    auto plaintext = pseudoPlaintext(SMALL_CHUNK * 3 + 1);
    ubyte[] ct;
    size_t off = 0;
    encryptStreamAuth(n, d, s, mac,
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
    decryptStreamAuth(n, d, s, mac,
        (ubyte[] buf) @trusted {
            size_t avail = ct.length - roff;
            size_t take = avail < buf.length ? avail : buf.length;
            buf[0 .. take] = ct[roff .. roff + take];
            roff += take;
            return take;
        },
        (const(ubyte)[] pt) @trusted { recovered ~= pt; },
        4096);
    assert(recovered == plaintext, "free-function roundtrip mismatch");
}

void main()
{
    testAuthStreamSingleRoundtripMatrix();
    testAuthStreamTripleRoundtripMatrix();
    testAuthStreamEmpty();
    testAuthStreamSingleChunk();
    testAuthStreamReorderDetected();
    testAuthStreamTruncateTailDetected();
    testAuthStreamAfterFinalDetected();
    testAuthStreamCrossStreamReplayDetected();
    testAuthStreamPrefixTamperDetected();
    testAuthStreamWriteAfterCloseRaises();
    testAuthStreamDestructorFlushes();
    testAuthStreamTruncateBelowPrefix();
    testAuthStreamFreeFunctionRoundtrip();
    writeln("test_streams_auth: ALL OK");
}
