/// Error-mapping surface: opaque-string relay, unknown profile,
/// closed Pipeline, duplicate profile registration (with an 8-entry
/// `hashes` constellation).
module test_errors;

import std.stdio : writeln;

import itb;

/// Runs `dg`, asserting it throws an [ItbException]; returns it.
ItbException expectThrow(scope void delegate() dg, string what)
{
    try
    {
        dg();
    }
    catch (ItbException e)
    {
        return e;
    }
    assert(false, what ~ ": expected ItbException, none thrown");
}

void main()
{
    // Unknown profile is UnknownProfile with a non-empty diagnostic,
    // on create and on lookup alike.
    {
        auto e = expectThrow({ cast(void) Pipeline.create("no-such-profile"); },
            "unknown profile");
        assert(e.status == Status.UnknownProfile);
        assert(e.msg.length > 0);
        e = expectThrow({ cast(void) lookup("no-such-profile"); },
            "lookup unknown profile");
        assert(e.status == Status.UnknownProfile);
    }

    // A negative maxWorkers opts value is clamped, not rejected.
    {
        auto p = Pipeline.create("singlemsg-triple-mac-v1",
            Opts().withMaxWorkers(-1));
        cast(void) p.save();
    }

    // Typoed opts key (lowercase s) — Go rejects unknown keys.
    {
        auto opts = Opts().withRaw("chunksize", "4096");
        auto e = expectThrow({
            cast(void) Pipeline.create("singlemsg-triple-mac-v1", opts);
        }, "unknown opts key");
        assert(e.status == Status.BadInput);
    }

    // Closed Pipeline reports TripleClosed; close is idempotent.
    {
        auto p = Pipeline.create("singlemsg-triple-mac-v1");
        p.close();
        p.close(); // idempotent
        auto e = expectThrow({
            cast(void) p.encryptMessage(cast(const(ubyte)[]) "payload");
        }, "closed pipeline");
        assert(e.status == Status.TripleClosed);
        e = expectThrow({ cast(void) p.save(); }, "closed save");
        assert(e.status == Status.TripleClosed);
        e = expectThrow({ p.maxWorkers(2); }, "closed maxWorkers");
        assert(e.status == Status.TripleClosed);
    }

    // Register a mixed profile, round-trip it, read it back, then hit
    // the duplicate-name status.
    {
        // 8-entry width-256 hashes constellation, layers off.
        Profile prof;
        prof.mode = "singlemsg-nomac";
        prof.width = 256;
        prof.mixedHashes = [
            "blake3", "blake2s", "areion256", "blake2b256",
            "chacha20", "blake3", "blake2s", "areion256",
        ];
        prof.keyBits = 1024;
        register("dlang-binding-test-mixed", prof);

        // The registered profile round-trips.
        auto sender = Pipeline.create("dlang-binding-test-mixed");
        auto receiver = Pipeline.load(sender.save());
        auto plain = cast(const(ubyte)[]) "custom profile";
        auto wire = sender.encryptMessage(plain);
        assert(receiver.decryptMessage(wire) == plain);
        auto back = lookup("dlang-binding-test-mixed");
        assert(back.name == "dlang-binding-test-mixed");
        assert(back.mixedHashes == prof.mixedHashes);

        // Duplicate name is a distinct status.
        auto e = expectThrow({
            register("dlang-binding-test-mixed", prof);
        }, "duplicate profile");
        assert(e.status == Status.ProfileExists);

        // A non-empty name inside the record must equal the argument.
        auto mismatch = lookup("singlemsg-triple-nomac-v1");
        mismatch.name = "some-other-name";
        e = expectThrow({
            register("dlang-binding-test-mismatch", mismatch);
        }, "name mismatch");
        assert(e.status == Status.BadInput);
    }

    // An unknown inner-hash name is relayed to Go and rejected there
    // — the binding performs no name validation of its own.
    {
        auto opts = Opts().withInnerHash("no-such-hash");
        auto e = expectThrow({
            cast(void) Pipeline.create("singlemsg-triple-mac-v1", opts);
        }, "opaque name relay");
        assert(e.status != Status.OK);
    }

    writeln("PASS test_errors");
}
