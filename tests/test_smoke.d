/// Init → save → load → EncryptMessage → DecryptMessage round trip.
module test_smoke;

import std.stdio : writeln;

import itb;

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

    writeln("PASS test_smoke");
}
