/// Error-mapping surface: opaque-string relay, closed Pipeline,
/// duplicate profile registration (with an 8-entry `innerHashes`
/// constellation).
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
    // Unknown profile is BadInput with a non-empty diagnostic.
    {
        auto e = expectThrow({ cast(void) Pipeline.create("no-such-profile"); },
            "unknown profile");
        assert(e.status == Status.BadInput);
        assert(e.msg.length > 0);
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
    }

    // Register a mixed profile, round-trip it, then hit the
    // duplicate-name status.
    {
        // 8-entry width-256 innerHashes constellation, layers off.
        auto opts = Opts()
            .withRaw("mode", "singlemsg-nomac")
            .withRaw("width", "256")
            .withRaw("innerHashes",
                "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256")
            .withRaw("keyBits", "1024")
            .withRaw("parallaxOn", "false")
            .withRaw("wrapperOn", "false");
        registerProfile("dlang-binding-test-mixed", opts);

        // The registered profile round-trips.
        auto sender = Pipeline.create("dlang-binding-test-mixed");
        auto receiver = Pipeline.open("dlang-binding-test-mixed", sender.blob);
        auto plain = cast(const(ubyte)[]) "custom profile";
        auto wire = sender.encryptMessage(plain);
        assert(receiver.decryptMessage(wire) == plain);

        // Duplicate name is a distinct status.
        auto e = expectThrow({
            registerProfile("dlang-binding-test-mixed", opts);
        }, "duplicate profile");
        assert(e.status == Status.ProfileExists);
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
