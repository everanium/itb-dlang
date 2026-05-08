// Phase-5 mirror: streaming roundtrips across non-default nonce sizes.
//
// Mirrors bindings/rust/tests/test_streams_nonce.rs file-for-file.
//
// These tests mutate the process-global `nonce_bits` atomic; they live
// in their own standalone D test program so per-process isolation
// keeps them out of test_streams.d (which exercises default-nonce
// streaming and would race the default-state assumption otherwise).
import std.algorithm.comparison : min;
import std.stdio : writeln;
import itb;

enum size_t SMALL_CHUNK = 4096;

ubyte[] pseudoPayload(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)((i * 31 + 11) & 0xff);
    return buf;
}

void testClassRoundtripNonDefaultNonceSingle()
{
    auto orig = getNonceBits();
    auto plaintext = pseudoPayload(SMALL_CHUNK * 3 + 100);
    foreach (n; [256, 512])
    {
        setNonceBits(n);
        auto noise = Seed("blake3", 1024);
        auto data  = Seed("blake3", 1024);
        auto start = Seed("blake3", 1024);

        ubyte[] cbuf;
        {
            auto enc = StreamEncryptor(noise, data, start,
                (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
                SMALL_CHUNK);
            enc.write(plaintext);
            enc.close();
        }

        ubyte[] pbuf;
        {
            auto dec = StreamDecryptor(noise, data, start,
                (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; });
            dec.feed(cbuf);
            dec.close();
        }
        assert(pbuf == plaintext,
            "Single class roundtrip mismatch under non-default nonce");
    }
    setNonceBits(orig);
}

void testEncryptStreamAcrossNonceSizesSingle()
{
    auto orig = getNonceBits();
    auto plaintext = pseudoPayload(SMALL_CHUNK * 3 + 256);
    foreach (n; [128, 256, 512])
    {
        setNonceBits(n);
        auto noise = Seed("blake3", 1024);
        auto data  = Seed("blake3", 1024);
        auto start = Seed("blake3", 1024);

        ubyte[] cbuf;
        {
            size_t pos = 0;
            encryptStream(noise, data, start,
                (ubyte[] buf) @trusted {
                    size_t avail = plaintext.length - pos;
                    size_t k = min(avail, buf.length);
                    buf[0 .. k] = plaintext[pos .. pos + k];
                    pos += k;
                    return k;
                },
                (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
                SMALL_CHUNK);
        }

        ubyte[] pbuf;
        {
            size_t pos = 0;
            decryptStream(noise, data, start,
                (ubyte[] buf) @trusted {
                    size_t avail = cbuf.length - pos;
                    size_t k = min(avail, buf.length);
                    buf[0 .. k] = cbuf[pos .. pos + k];
                    pos += k;
                    return k;
                },
                (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; },
                SMALL_CHUNK);
        }
        assert(pbuf == plaintext,
            "Single encryptStream/decryptStream roundtrip mismatch");
    }
    setNonceBits(orig);
}

void testClassRoundtripNonDefaultNonceTriple()
{
    auto orig = getNonceBits();
    auto plaintext = pseudoPayload(SMALL_CHUNK * 3);
    foreach (n; [256, 512])
    {
        setNonceBits(n);
        auto noise = Seed("blake3", 1024);
        auto d1 = Seed("blake3", 1024);
        auto d2 = Seed("blake3", 1024);
        auto d3 = Seed("blake3", 1024);
        auto s1 = Seed("blake3", 1024);
        auto s2 = Seed("blake3", 1024);
        auto s3 = Seed("blake3", 1024);

        ubyte[] cbuf;
        {
            auto enc = StreamEncryptor3(noise, d1, d2, d3, s1, s2, s3,
                (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
                SMALL_CHUNK);
            enc.write(plaintext);
            enc.close();
        }

        ubyte[] pbuf;
        {
            auto dec = StreamDecryptor3(noise, d1, d2, d3, s1, s2, s3,
                (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; });
            dec.feed(cbuf);
            dec.close();
        }
        assert(pbuf == plaintext,
            "Triple class roundtrip mismatch under non-default nonce");
    }
    setNonceBits(orig);
}

void testEncryptStreamTripleAcrossNonceSizes()
{
    auto orig = getNonceBits();
    auto plaintext = pseudoPayload(SMALL_CHUNK * 3 + 100);
    foreach (n; [128, 256, 512])
    {
        setNonceBits(n);
        auto noise = Seed("blake3", 1024);
        auto d1 = Seed("blake3", 1024);
        auto d2 = Seed("blake3", 1024);
        auto d3 = Seed("blake3", 1024);
        auto s1 = Seed("blake3", 1024);
        auto s2 = Seed("blake3", 1024);
        auto s3 = Seed("blake3", 1024);

        ubyte[] cbuf;
        {
            size_t pos = 0;
            encryptStreamTriple(noise, d1, d2, d3, s1, s2, s3,
                (ubyte[] buf) @trusted {
                    size_t avail = plaintext.length - pos;
                    size_t k = min(avail, buf.length);
                    buf[0 .. k] = plaintext[pos .. pos + k];
                    pos += k;
                    return k;
                },
                (const(ubyte)[] chunk) @trusted { cbuf ~= chunk; },
                SMALL_CHUNK);
        }

        ubyte[] pbuf;
        {
            size_t pos = 0;
            decryptStreamTriple(noise, d1, d2, d3, s1, s2, s3,
                (ubyte[] buf) @trusted {
                    size_t avail = cbuf.length - pos;
                    size_t k = min(avail, buf.length);
                    buf[0 .. k] = cbuf[pos .. pos + k];
                    pos += k;
                    return k;
                },
                (const(ubyte)[] chunk) @trusted { pbuf ~= chunk; },
                SMALL_CHUNK);
        }
        assert(pbuf == plaintext,
            "Triple encryptStream/decryptStream roundtrip mismatch");
    }
    setNonceBits(orig);
}

void main()
{
    testClassRoundtripNonDefaultNonceSingle();
    testEncryptStreamAcrossNonceSizesSingle();
    testClassRoundtripNonDefaultNonceTriple();
    testEncryptStreamTripleAcrossNonceSizes();
    writeln("test_streams_nonce: ALL OK");
}
