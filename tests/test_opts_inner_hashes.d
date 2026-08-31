/// Per-call constellation override via the typed `withInnerHashes`
/// helper: register a base width-512 profile, then Init / Open with
/// an 8-entry width-512 alternate constellation and round-trip a
/// Single Message.
module test_opts_inner_hashes;

import std.stdio : writeln;

import itb;

void main()
{
    // Base profile is a shipped single-primitive width-512 Single
    // Message profile; the per-call withInnerHashes override rebinds
    // all 8 slots to an alternate width-512 constellation for one
    // Pipeline pair without touching the shipped registry.
    auto override_ = Opts().withInnerHashes([
        "areion512", "blake2b512", "areion512", "blake2b512",
        "areion512", "blake2b512", "areion512", "blake2b512",
    ]);

    auto sender = Pipeline.create("singlemsg-triple-mac-v1", override_);
    auto receiver = Pipeline.open(
        "singlemsg-triple-mac-v1", sender.blob, override_);
    auto plain = cast(const(ubyte)[]) "mixed-hashes typed override round trip";
    auto wire = sender.encryptMessage(plain);
    assert(receiver.decryptMessage(wire) == plain);

    writeln("PASS test_opts_inner_hashes");
}
