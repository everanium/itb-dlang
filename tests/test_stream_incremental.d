/// Explicit write / end / read round trip with pathological batch
/// sizes (17-byte feed, 23-byte drain) across multiple chunks.
module test_stream_incremental;

import std.stdio : writeln;

import itb;

void main()
{
    // Small chunk size so the 64 KiB payload spans many chunks.
    auto opts = Opts().withChunkSize(4096);
    auto sender = Pipeline.create("streaming-aead-triple-mac-v1", opts);
    auto receiver = Pipeline.open("streaming-aead-triple-mac-v1",
        sender.blob, opts);

    auto plain = new ubyte[65_536];
    foreach (i, ref b; plain)
        b = cast(ubyte)(i % 241);

    // Encrypt: 17-byte writes, then end + 23-byte drains.
    ubyte[] wire;
    {
        auto sess = sender.encryptStream();
        for (size_t off = 0; off < plain.length; off += 17)
        {
            immutable hi = off + 17 < plain.length ? off + 17 : plain.length;
            sess.write(plain[off .. hi]);
        }
        sess.end();
        ubyte[23] buf;
        for (;;)
        {
            bool fin;
            immutable n = sess.read(buf[], fin);
            wire ~= buf[0 .. n];
            if (fin)
                break;
        }
    }
    assert(wire.length > 0);

    // Decrypt with the same pathological batch sizes.
    ubyte[] back;
    {
        auto sess = receiver.decryptStream();
        for (size_t off = 0; off < wire.length; off += 17)
        {
            immutable hi = off + 17 < wire.length ? off + 17 : wire.length;
            sess.write(wire[off .. hi]);
        }
        sess.end();
        ubyte[23] buf;
        for (;;)
        {
            bool fin;
            immutable n = sess.read(buf[], fin);
            back ~= buf[0 .. n];
            if (fin)
                break;
        }
    }
    assert(back == plain, "incremental round trip");

    writeln("PASS test_stream_incremental");
}
