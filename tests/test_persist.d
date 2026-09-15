/// Persistence surface: save / saveF / load / loadF round trips,
/// inspect, lookup / profiles, maxWorkers.
module test_persist;

import std.algorithm : canFind, isSorted;
import std.conv : to;
import std.file : exists, getAttributes, remove;
import std.process : thisProcessID;
import std.stdio : writeln;

import itb3;

void roundTrip(ref Pipeline sender, ref Pipeline receiver, string what)
{
    auto plain = cast(const(ubyte)[]) "persist payload";
    auto wire = sender.encryptMessage(plain);
    assert(receiver.decryptMessage(wire) == plain, what);
}

void main()
{
    auto sender = Pipeline.create("singlemsg-triple-mac-v1");

    // save → load; save is stable; load retains the bytes.
    auto blob = sender.save();
    assert(sender.save() == blob, "save must be stable");
    {
        auto receiver = Pipeline.load(blob);
        roundTrip(sender, receiver, "in-memory");
        assert(receiver.save() == blob, "load must retain the blob bytes");
    }

    // load with master overrides == sender rekey.
    ubyte[32] perm = 0x31;
    ubyte[32] wrap = 0x32;
    {
        auto receiver = Pipeline.load(blob, perm[], wrap[]);
        assert(receiver.save() != blob, "master overrides must rotate the blob");
        cast(void) sender.rekey(perm[], wrap[]);
        roundTrip(sender, receiver, "overrides");
    }

    // inspect == lookup for a shipped profile; garbage is BadInput.
    auto prof = inspect(blob);
    assert(prof.name == "singlemsg-triple-mac-v1");
    assert(prof.mode == "singlemsg-mac");
    assert(prof.width == 512);
    assert(prof.innerHash == "areion512");
    assert(prof.macName == "hmac-blake3");
    assert(prof.wrapper && prof.parallax);
    // The recipe fields match the registry entry; the two
    // inspection-only fields separate the two records.
    {
        auto recipe = prof;
        recipe.nonceBits.nullify();
        recipe.barrierFill.nullify();
        assert(recipe == lookup("singlemsg-triple-mac-v1"));
    }

    // inspect carries the blob's runtime globals; lookup does not.
    // Defaults first: the compile-in nonce width and fill margin.
    assert(!prof.nonceBits.isNull && prof.nonceBits.get == 512);
    assert(!prof.barrierFill.isNull && prof.barrierFill.get == 1);
    {
        // Per-Pipeline overrides travel through the blob into inspect.
        auto tuned = Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withNonceBits(256).withBarrierFill(4));
        auto tunedProf = inspect(tuned.save());
        assert(tunedProf.nonceBits.get == 256);
        assert(tunedProf.barrierFill.get == 4);
        assert(tunedProf.toJson().canFind(`"nonce_bits":256`));
        assert(tunedProf.toJson().canFind(`"barrier_fill":4`));
    }
    {
        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        auto registry = lookup("singlemsg-triple-mac-v1");
        assert(registry.nonceBits.isNull);
        assert(registry.barrierFill.isNull);
        assert(!registry.toJson().canFind("nonce_bits"));
        assert(!registry.toJson().canFind("barrier_fill"));
    }
    try
    {
        cast(void) inspect(cast(const(ubyte)[]) "not a blob");
        assert(false, "inspect garbage must throw");
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput);
    }

    // profiles lists the shipped catalogue, sorted, each resolvable.
    auto names = profiles();
    assert(names.canFind("singlemsg-triple-mac-v1"));
    assert(names.isSorted);
    foreach (n; names)
        assert(lookup(n).name == n);

    // saveF → loadF on a temp file (mode 0600); missing file.
    auto path = "/tmp/itb-dlang-persist-" ~ thisProcessID.to!string ~ ".blob";
    sender.saveF(path);
    assert(exists(path));
    assert((getAttributes(path) & 511) == 384, "mode must be 0600");
    {
        auto receiver = Pipeline.loadF(path);
        roundTrip(sender, receiver, "on-disk");
    }
    remove(path);
    try
    {
        cast(void) Pipeline.loadF(path);
        assert(false, "loadF of a missing file must throw");
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput);
    }

    // maxWorkers clamps and round-trips.
    sender.maxWorkers(2);
    sender.maxWorkers(-1);
    sender.maxWorkers(100_000);
    {
        auto receiver = Pipeline.load(sender.save());
        receiver.maxWorkers(1);
        roundTrip(sender, receiver, "workers");
    }

    writeln("PASS test_persist");
}
