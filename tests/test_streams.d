// Phase-4 + Phase-5 mirror: chunked encrypt / decrypt round-trip.
//
// Mirrors bindings/rust/tests/test_streams.rs file-for-file. The
// streaming wrappers slice plaintext into chunks of `chunk_size` bytes
// and emit a concatenated ITB chunk stream; the decryptor consumes the
// concatenated stream by walking each chunk's header.
//
// Default-nonce coverage only — the global-state mutating non-default
// nonce tests live in test_streams_nonce.d so the default-state
// roundtrip tests below remain race-free.
import std.algorithm.comparison : min;
import std.exception : collectException;
import std.stdio : writeln;
import itb;

enum size_t SMALL_CHUNK = 4096;

ubyte[] pseudoPlaintext(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)(i & 0xff);
    return buf;
}

ubyte[] pseudoPayload(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)((i * 13 + 11) & 0xff);
    return buf;
}

// --------------------------------------------------------------------
// Phase-4 baseline tests.
// --------------------------------------------------------------------

void testStreamSingleRoundtrip200kb()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);

    auto plaintext = pseudoPlaintext(200 * 1024);

    ubyte[] ciphertext;
    {
        auto enc = StreamEncryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { ciphertext ~= chunk; },
            64 * 1024);
        enc.write(plaintext);
        enc.close();
    }
    assert(ciphertext.length > 0, "ciphertext must be non-empty");
    assert(ciphertext != plaintext, "ciphertext must differ from plaintext");

    ubyte[] recovered;
    {
        auto dec = StreamDecryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { recovered ~= chunk; });
        // Feed in 4 KB shards so chunk boundaries cross multiple feed() calls.
        size_t off = 0;
        while (off < ciphertext.length)
        {
            size_t end = min(off + 4096, ciphertext.length);
            dec.feed(ciphertext[off .. end]);
            off = end;
        }
        dec.close();
    }
    assert(recovered == plaintext, "200kb roundtrip mismatch");
}

void testStreamSingleRoundtripShortPayload()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);

    auto plaintext = cast(ubyte[])
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".dup;

    ubyte[] ciphertext;
    {
        auto enc = StreamEncryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { ciphertext ~= chunk; },
            64 * 1024);
        enc.write(plaintext);
        enc.close();
    }

    ubyte[] recovered;
    {
        auto dec = StreamDecryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { recovered ~= chunk; });
        dec.feed(ciphertext);
        dec.close();
    }
    assert(recovered == plaintext, "short-payload roundtrip mismatch");
}

void testStreamEncryptorStructApi()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);

    immutable string[] parts = ["first chunk ", "second chunk ", "third chunk"];

    ubyte[] ciphertext;
    {
        auto enc = StreamEncryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { ciphertext ~= chunk; },
            64 * 1024);
        foreach (p; parts)
            enc.write(cast(const(ubyte)[]) p);
        enc.close();
    }

    ubyte[] recovered;
    {
        auto dec = StreamDecryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { recovered ~= chunk; });
        dec.feed(ciphertext);
        dec.close();
    }

    string expected;
    foreach (p; parts) expected ~= p;
    assert(recovered == cast(const(ubyte)[]) expected,
        "multi-part roundtrip mismatch");
}

// --------------------------------------------------------------------
// Phase-5 extension — full Python-parity coverage.
// --------------------------------------------------------------------

void testClassRoundtripDefaultNonce()
{
    auto plaintext = pseudoPayload(SMALL_CHUNK * 5 + 17);
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);

    ubyte[] cbuf;
    {
        auto enc = StreamEncryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
            SMALL_CHUNK);
        // Push data in three irregular slices, exercising the
        // accumulator path on partial chunks.
        enc.write(plaintext[0 .. 1000]);
        enc.write(plaintext[1000 .. 5000]);
        enc.write(plaintext[5000 .. $]);
        enc.close();
    }

    ubyte[] pbuf;
    {
        auto dec = StreamDecryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; });
        // Feed ciphertext in 1-KB shards so feed() crosses chunk
        // boundaries on multiple iterations.
        size_t off = 0;
        while (off < cbuf.length)
        {
            size_t end = min(off + 1024, cbuf.length);
            dec.feed(cbuf[off .. end]);
            off = end;
        }
        dec.close();
    }
    assert(pbuf == plaintext, "irregular-slice roundtrip mismatch");
}

void testEncryptStreamDecryptStream()
{
    auto plaintext = pseudoPayload(SMALL_CHUNK * 4);
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);

    ubyte[] cbuf;
    {
        size_t pos = 0;
        encryptStream(n, d, s,
            (ubyte[] buf) @trusted {
                size_t avail = plaintext.length - pos;
                size_t n_ = min(avail, buf.length);
                buf[0 .. n_] = plaintext[pos .. pos + n_];
                pos += n_;
                return n_;
            },
            (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
            SMALL_CHUNK);
    }

    ubyte[] pbuf;
    {
        size_t pos = 0;
        decryptStream(n, d, s,
            (ubyte[] buf) @trusted {
                size_t avail = cbuf.length - pos;
                size_t n_ = min(avail, buf.length);
                buf[0 .. n_] = cbuf[pos .. pos + n_];
                pos += n_;
                return n_;
            },
            (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; },
            SMALL_CHUNK);
    }
    assert(pbuf == plaintext, "encryptStream/decryptStream roundtrip mismatch");
}

void testClassRoundtripDefaultNonceTriple()
{
    auto plaintext = pseudoPayload(SMALL_CHUNK * 4 + 33);
    auto s0 = Seed("blake3", 1024);
    auto s1 = Seed("blake3", 1024);
    auto s2 = Seed("blake3", 1024);
    auto s3 = Seed("blake3", 1024);
    auto s4 = Seed("blake3", 1024);
    auto s5 = Seed("blake3", 1024);
    auto s6 = Seed("blake3", 1024);

    ubyte[] cbuf;
    {
        auto enc = StreamEncryptor3(s0, s1, s2, s3, s4, s5, s6,
            (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
            SMALL_CHUNK);
        enc.write(plaintext[0 .. SMALL_CHUNK]);
        enc.write(plaintext[SMALL_CHUNK .. 3 * SMALL_CHUNK]);
        enc.write(plaintext[3 * SMALL_CHUNK .. $]);
        enc.close();
    }

    ubyte[] pbuf;
    {
        auto dec = StreamDecryptor3(s0, s1, s2, s3, s4, s5, s6,
            (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; });
        dec.feed(cbuf);
        dec.close();
    }
    assert(pbuf == plaintext, "Triple class roundtrip mismatch");
}

void testEncryptStreamTripleDecryptStreamTriple()
{
    auto plaintext = pseudoPayload(SMALL_CHUNK * 5 + 7);
    auto s0 = Seed("blake3", 1024);
    auto s1 = Seed("blake3", 1024);
    auto s2 = Seed("blake3", 1024);
    auto s3 = Seed("blake3", 1024);
    auto s4 = Seed("blake3", 1024);
    auto s5 = Seed("blake3", 1024);
    auto s6 = Seed("blake3", 1024);

    ubyte[] cbuf;
    {
        size_t pos = 0;
        encryptStreamTriple(s0, s1, s2, s3, s4, s5, s6,
            (ubyte[] buf) @trusted {
                size_t avail = plaintext.length - pos;
                size_t n_ = min(avail, buf.length);
                buf[0 .. n_] = plaintext[pos .. pos + n_];
                pos += n_;
                return n_;
            },
            (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
            SMALL_CHUNK);
    }

    ubyte[] pbuf;
    {
        size_t pos = 0;
        decryptStreamTriple(s0, s1, s2, s3, s4, s5, s6,
            (ubyte[] buf) @trusted {
                size_t avail = cbuf.length - pos;
                size_t n_ = min(avail, buf.length);
                buf[0 .. n_] = cbuf[pos .. pos + n_];
                pos += n_;
                return n_;
            },
            (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; },
            SMALL_CHUNK);
    }
    assert(pbuf == plaintext, "Triple encryptStream/decryptStream roundtrip mismatch");
}

void testWriteAfterCloseRaises()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    ubyte[] cbuf;
    auto enc = StreamEncryptor(n, d, s,
        (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
        SMALL_CHUNK);
    enc.write(cast(const(ubyte)[]) "hello");
    enc.close();
    auto err = collectException!ITBError(
        enc.write(cast(const(ubyte)[]) "world"));
    assert(err !is null, "write after close must throw");
    assert(err.statusCode == Status.EasyClosed);
}

void testPartialChunkAtCloseRaises()
{
    auto n = Seed("blake3", 1024);
    auto d = Seed("blake3", 1024);
    auto s = Seed("blake3", 1024);
    ubyte[] cbuf;
    {
        auto enc = StreamEncryptor(n, d, s,
            (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
            SMALL_CHUNK);
        ubyte[100] tail = cast(ubyte) 'x';
        enc.write(tail[]);
        enc.close();
    }

    ubyte[] pbuf;
    auto dec = StreamDecryptor(n, d, s,
        (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; });
    // Feed only the first 30 bytes — header is complete (>= 20) but
    // the body is truncated. close() must raise on the trailing
    // incomplete chunk.
    dec.feed(cbuf[0 .. 30]);
    auto err = collectException!ITBError(dec.close());
    assert(err !is null, "close with truncated tail must throw");
    assert(err.statusCode == Status.BadInput);
}

// Note: the non-default-nonce streaming tests live in
// test_streams_nonce.d — they mutate the process-global setNonceBits
// atomic and stay out of this file so the default-state tests above
// remain race-free.

void main()
{
    testStreamSingleRoundtrip200kb();
    testStreamSingleRoundtripShortPayload();
    testStreamEncryptorStructApi();
    testClassRoundtripDefaultNonce();
    testEncryptStreamDecryptStream();
    testClassRoundtripDefaultNonceTriple();
    testEncryptStreamTripleDecryptStreamTriple();
    testWriteAfterCloseRaises();
    testPartialChunkAtCloseRaises();
    writeln("test_streams: ALL OK");
}
