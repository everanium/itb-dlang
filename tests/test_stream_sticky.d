/// A decrypt session fed a tampered wire fails with a sticky MAC
/// failure. Uses a position probe rather than a single bit flip
/// because the over-sized container carries CSPRNG residue in the
/// non-payload area — a flip that lands inside the residue is
/// architecturally inert (residue is not payload) and the session
/// finishes clean. Probing 32 evenly-spaced positions makes the
/// all-residue probability negligible; the first position that
/// surfaces an error must give Status.MACFailure and remain sticky
/// on subsequent reads.
module test_stream_sticky;

import std.format : format;
import std.stdio : writeln;

import itb;

void main()
{
    auto sender = Pipeline.create("streaming-aead-triple-mac-v1");
    auto receiver = Pipeline.open("streaming-aead-triple-mac-v1", sender.blob);

    auto plain = new ubyte[65_536];
    foreach (i, ref b; plain)
        b = cast(ubyte)(i % 227);
    auto baseWire = sender.encryptStreamOneShot(plain);
    assert(baseWire.length > 128,
        format("wire too short to place a distributed probe: %d bytes",
            baseWire.length));

    enum probes = 32;
    // Evenly spread through the wire body; skip the first / last
    // 16 bytes so a hit against the outer envelope framing does not
    // muddy the observation.
    immutable size_t bodyStart = 16;
    immutable size_t bodyEnd = baseWire.length - 16;
    immutable size_t stride = (bodyEnd - bodyStart) / probes;

    foreach (probe; 0 .. probes)
    {
        immutable idx = bodyStart + probe * stride;

        auto wire = baseWire.dup;
        wire[idx] ^= 0x01;

        auto sess = receiver.decryptStream();
        // Ignore Write / End status — the failure may surface on
        // either side or only on the drain that follows.
        try
            sess.write(wire);
        catch (ItbException)
        {
        }
        try
            sess.end();
        catch (ItbException)
        {
        }

        ubyte[4096] buf;
        ItbException firstErr = null;
        bool finishedClean = false;
        for (;;)
        {
            bool fin;
            try
            {
                cast(void) sess.read(buf[], fin);
            }
            catch (ItbException e)
            {
                firstErr = e;
                break;
            }
            if (fin)
            {
                finishedClean = true;
                break;
            }
        }
        if (finishedClean)
            continue; // Residue hit at this offset — next probe.

        assert(firstErr !is null,
            "read loop exited without error nor finish");
        assert(firstErr.status == Status.MACFailure,
            format("expected MAC failure on tampered wire at probe %d (byte %d), got %s",
                probe, idx, firstErr.status));

        // Sticky: a subsequent read reports the same status.
        bool fin2;
        try
        {
            cast(void) sess.read(buf[], fin2);
            assert(false, "sticky failure expected on re-read");
        }
        catch (ItbException again)
        {
            assert(again.status == firstErr.status, "failure must be sticky");
        }
        writeln("PASS test_stream_sticky");
        return;
    }
    assert(false,
        "no probe among 32 evenly-spaced positions surfaced a MAC failure — "
        ~ "either the probe pattern is degenerate or authentication is not "
        ~ "covering the wire body it should");
}
