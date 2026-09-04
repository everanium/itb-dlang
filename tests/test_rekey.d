/// Init → Rekey → Load receiver with the rotated blob → round trip.
module test_rekey;

import std.stdio : writeln;

import itb;

void main()
{
    auto sender = Pipeline.create("singlemsg-triple-mac-v1");
    auto blobBefore = sender.save();

    ubyte[32] perm = 0x11;
    ubyte[32] wrap = 0x22;
    auto rotated = sender.rekey(perm[], wrap[]);
    assert(rotated != blobBefore, "rekey must refresh the blob");
    assert(sender.save() == rotated, "save must report the rotated blob");

    auto receiver = Pipeline.load(rotated);
    auto plain = cast(const(ubyte)[]) "post-rekey payload";
    auto wire = sender.encryptMessage(plain);
    assert(receiver.decryptMessage(wire) == plain);

    writeln("PASS test_rekey");
}
