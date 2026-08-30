/// Init → Rekey → Open receiver with the rotated blob → round trip.
module test_rekey;

import std.stdio : writeln;

import itb;

void main()
{
    auto sender = Pipeline.create("singlemsg-triple-mac-v1");
    auto blobBefore = sender.blob.dup;

    ubyte[32] perm = 0x11;
    ubyte[32] wrap = 0x22;
    sender.rekey(perm[], wrap[]);
    assert(sender.blob != blobBefore, "rekey must refresh the blob");

    auto receiver = Pipeline.open("singlemsg-triple-mac-v1", sender.blob);
    auto plain = cast(const(ubyte)[]) "post-rekey payload";
    auto wire = sender.encryptMessage(plain);
    assert(receiver.decryptMessage(wire) == plain);

    writeln("PASS test_rekey");
}
