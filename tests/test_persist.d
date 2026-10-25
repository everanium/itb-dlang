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
        recipe.containerMode.nullify();
        assert(recipe == lookup("singlemsg-triple-mac-v1"));
    }

    // inspect carries the blob's runtime globals; lookup does not.
    // Defaults first: the compile-in nonce width and fill margin.
    assert(!prof.nonceBits.isNull && prof.nonceBits.get == 512);
    assert(!prof.barrierFill.isNull && prof.barrierFill.get == 1);
    assert(!prof.containerMode.isNull && prof.containerMode.get == 1);
    {
        // Per-Pipeline overrides travel through the blob into inspect.
        auto tuned = Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withMode(2).withNonceBits(256).withBarrierFill(4));
        auto tunedProf = inspect(tuned.save());
        assert(tunedProf.containerMode.get == 2);
        assert(tunedProf.nonceBits.get == 256);
        assert(tunedProf.barrierFill.get == 4);
        assert(tunedProf.toJson().canFind(`"container_mode":2`));
        assert(tunedProf.toJson().canFind(`"nonce_bits":256`));
        assert(tunedProf.toJson().canFind(`"barrier_fill":4`));
    }
    {
        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        auto registry = lookup("singlemsg-triple-mac-v1");
        assert(registry.containerMode.isNull);
        assert(registry.nonceBits.isNull);
        assert(registry.barrierFill.isNull);
        assert(!registry.toJson().canFind("container_mode"));
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

    // The DRBG choice round-trips and travels in the blob as a
    // recipe field: inspect reports it, and the JSON carries it.
    foreach (drbgName; ["csprng", "aesitb128"])
    {
        auto drbgSender = Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withDrbg(drbgName));
        auto drbgBlob = drbgSender.save();
        auto receiver = Pipeline.load(drbgBlob);
        roundTrip(drbgSender, receiver, "drbg " ~ drbgName);
        roundTrip(receiver, drbgSender, "drbg reply " ~ drbgName);
        auto drbgProf = inspect(drbgBlob);
        assert(drbgProf.drbg == drbgName);
        assert(drbgProf.toJson().canFind(`"drbg":"` ~ drbgName ~ `"`));
    }
    {
        // Default: neither the inspected record nor the registry
        // entry carries the key.
        auto defaultProf = inspect(blob);
        assert(defaultProf.drbg.length == 0);
        assert(!defaultProf.toJson().canFind("drbg"));
        auto registry = lookup("singlemsg-triple-mac-v1");
        assert(registry.drbg.length == 0);
        assert(!registry.toJson().canFind("drbg"));
    }
    {
        // A registered copy of an inspected record keeps drbg; the
        // name and the inspection-only fields are cleared.
        auto drbgSender = Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withDrbg("csprng"));
        auto copy = inspect(drbgSender.save());
        copy.name = "";
        copy.nonceBits.nullify();
        copy.barrierFill.nullify();
        copy.containerMode.nullify();
        register("dlang-binding-test-drbg-copy", copy);
        auto back = lookup("dlang-binding-test-drbg-copy");
        assert(back.drbg == "csprng");
        assert(back.toJson().canFind(`"drbg":"csprng"`));
        auto copySender = Pipeline.create("dlang-binding-test-drbg-copy");
        auto receiver = Pipeline.load(copySender.save());
        roundTrip(copySender, receiver, "registered drbg");
    }

    // Interlock 168-bit chunk width round-trips on a 512-bit profile
    // and travels in the blob as a recipe field; 256-bit hashes and
    // unknown widths are rejected with Status.BadInput.
    {
        auto ilSender = Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withInterlock("168"));
        auto ilBlob = ilSender.save();
        auto receiver = Pipeline.load(ilBlob);
        roundTrip(ilSender, receiver, "interlock 168");
        roundTrip(receiver, ilSender, "interlock 168 reply");
        auto ilProf = inspect(ilBlob);
        assert(ilProf.interlock == "168");
        assert(ilProf.toJson().canFind(`"interlock":"168"`));

        auto defaultProf = inspect(blob);
        assert(defaultProf.interlock.length == 0);
        assert(!defaultProf.toJson().canFind("interlock"));
        auto registry = lookup("singlemsg-triple-mac-v1");
        assert(registry.interlock.length == 0);
        assert(!registry.toJson().canFind("interlock"));

        auto copy = ilProf;
        copy.name = "";
        copy.nonceBits.nullify();
        copy.barrierFill.nullify();
        copy.containerMode.nullify();
        register("dlang-binding-test-interlock-copy", copy);
        auto back = lookup("dlang-binding-test-interlock-copy");
        assert(back.interlock == "168");
        assert(back.toJson().canFind(`"interlock":"168"`));
        auto copySender = Pipeline.create("dlang-binding-test-interlock-copy");
        auto copyReceiver = Pipeline.load(copySender.save());
        roundTrip(copySender, copyReceiver, "registered interlock");
    }
    try
    {
        cast(void) Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withInnerHash("blake3").withInterlock("168"));
        assert(false, "interlock 168 on 256-bit hash must throw");
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput);
    }
    try
    {
        cast(void) Pipeline.create("singlemsg-triple-mac-v1",
                Opts().withInterlock("96"));
        assert(false, "interlock 96 must throw");
    }
    catch (ItbException e)
    {
        assert(e.status == Status.BadInput);
    }

    writeln("PASS test_persist");
}
