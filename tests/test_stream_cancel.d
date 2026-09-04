/// Destroying an encrypt session mid-flight cleans up and leaves the
/// Pipeline usable.
module test_stream_cancel;

import std.stdio : writeln;

import itb;

void main()
{
    auto sender = Pipeline.create("streaming-aead-triple-mac-v1");

    {
        auto sess = sender.encryptStream();
        auto chunk = new ubyte[100_000];
        chunk[] = 0xA5;
        sess.write(chunk);
        // Scope exit without end() — the destructor cancels and
        // frees the session; the test passing (process not hanging)
        // is the assertion.
    }

    // The Pipeline stays usable after the cancelled session.
    auto receiver = Pipeline.load(sender.save());
    auto plain = cast(const(ubyte)[]) "after cancel";
    auto wire = sender.encryptMessage(plain);
    assert(receiver.decryptMessage(wire) == plain);

    writeln("PASS test_stream_cancel");
}
