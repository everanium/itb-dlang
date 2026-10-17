/// Init → save → load → EncryptMessage → DecryptMessage round trip.
module test_smoke;

import std.stdio : writeln;

import itb3;

void main()
{
    auto sender = Pipeline.create("singlemsg-triple-mac-v1");
    assert(sender.save().length > 0, "blob must be non-empty");

    auto receiver = Pipeline.load(sender.save());

    auto plain = cast(const(ubyte)[]) "smoke round-trip payload";
    auto wire = sender.encryptMessage(plain);
    assert(wire != plain, "wire must differ from plaintext");

    auto back = receiver.decryptMessage(wire);
    assert(back == plain, "decrypt must invert encrypt");

    const(ubyte)[][] masters;
    foreach (i; 0 .. 8)
    {
        auto k = new ubyte[32];
        k[] = cast(ubyte) (0x11 * (i + 1));
        masters ~= k;
    }

    auto k1 = Pipeline.createKeys("singlemsg-triple-mac-v1", masters);
    auto k2 = Pipeline.createKeys("singlemsg-triple-mac-v1", Opts(), masters);
    assert(k1.save() == k2.save(), "createKeys must produce identical blobs");

    auto kWire = k1.encryptMessage(plain);
    auto kBack = k2.decryptMessage(kWire);
    assert(kBack == plain, "createKeys handles must interoperate");

    // Duplicate key must fail with BadInput.
    auto dupMasters = masters.dup;
    dupMasters[1] = dupMasters[0];
    bool caughtDup = false;
    try
    {
        auto bad = Pipeline.createKeys("singlemsg-triple-mac-v1", dupMasters);
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput, "duplicate key must return BadInput");
        caughtDup = true;
    }
    assert(caughtDup, "duplicate key must throw ItbException");

    // Short (< 16 bytes) key must fail with BadInput.
    auto shortMasters = masters.dup;
    shortMasters[0] = new ubyte[8];
    bool caughtShort = false;
    try
    {
        auto bad = Pipeline.createKeys("singlemsg-triple-mac-v1", shortMasters);
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput, "short key must return BadInput");
        caughtShort = true;
    }
    assert(caughtShort, "short key must throw ItbException");

    writeln("PASS test_smoke");
}
