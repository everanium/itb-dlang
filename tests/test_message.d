/// Single Message round trip across every shipped cipher profile at
/// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
/// has no cipher surface and is exercised in test_errors.d instead.
module test_message;

import std.format : format;
import std.stdio : writeln;

import itb;

/// Deterministic non-trivial payload (xorshift fill).
ubyte[] payload(size_t n, ulong seed)
{
    ulong x = seed | 1;
    auto outBuf = new ubyte[n];
    foreach (ref b; outBuf)
    {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b = cast(ubyte) x;
    }
    return outBuf;
}

void main()
{
    static immutable profiles = [
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    ];
    foreach (profile; profiles)
    {
        auto sender = Pipeline.create(profile);
        auto receiver = Pipeline.open(profile, sender.blob);
        foreach (size; [4 * 1024, 256 * 1024])
        {
            auto plain = payload(size, size);
            auto wire = sender.encryptMessage(plain);
            auto back = receiver.decryptMessage(wire);
            assert(back == plain, format("%s @%d", profile, size));
        }
    }
    writeln("PASS test_message");
}
