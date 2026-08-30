/// Round trip through the stream pumps on a Streaming AEAD profile,
/// plus pump ↔ one-shot cross-compatibility.
module test_stream_pump;

import std.stdio : writeln;

import itb;

ubyte[] patterned(size_t n, uint mod)
{
    auto outBuf = new ubyte[n];
    foreach (i, ref b; outBuf)
        b = cast(ubyte)(i % mod);
    return outBuf;
}

void main()
{
    auto sender = Pipeline.create("streaming-aead-triple-mac-v1");
    auto receiver = Pipeline.open("streaming-aead-triple-mac-v1", sender.blob);

    // 1 MiB pump round trip.
    {
        auto plain = patterned(1 << 20, 251);
        auto wire = sender.encryptStreamPump(plain);
        assert(wire.length > 0);
        auto back = receiver.decryptStreamPump(wire);
        assert(back == plain, "pump round trip @1MiB");
    }

    // Pump matches one-shot in both directions.
    {
        auto plain = patterned(65_536, 199);
        auto wire = sender.encryptStreamOneShot(plain);

        auto back = receiver.decryptStreamPump(wire);
        assert(back == plain, "one-shot wire through pump decrypt");

        auto back2 = receiver.decryptStreamOneShot(wire);
        assert(back2 == plain, "one-shot wire through one-shot decrypt");
    }

    writeln("PASS test_stream_pump");
}
