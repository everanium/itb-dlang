/// The runtime surface the stress harness drives: GOMAXPROCS, the
/// heap profile, the pool counters, the shipped hash-registry
/// enumeration, and the auto DRBG tier report.
module test_runtime;

import std.algorithm : canFind;
import std.file : exists, getSize, read, remove;
import std.stdio : writeln;

import itb3;

void main()
{
    // GOMAXPROCS: zero queries, a positive value sets and returns the
    // previous one. The original value is restored so nothing later in
    // the process sees the override.
    immutable original = setGOMAXPROCS(0);
    assert(original > 0, "query must report a positive GOMAXPROCS");
    assert(setGOMAXPROCS(2) == original, "set must return the previous value");
    assert(setGOMAXPROCS(0) == 2, "GOMAXPROCS must read back as 2");
    cast(void) setGOMAXPROCS(original);

    // Pool counters: the slot count comes from the library, the layout
    // is 1 + 5*T + 8 with T in slot 0, and every counter is a
    // non-negative monotonic total.
    immutable slots = poolStatsLen();
    assert(slots >= 9, "poolStatsLen must report at least 9 slots");
    auto counters = new long[slots];
    assert(poolStats(counters) == slots, "poolStats must fill every slot");
    immutable tiers = counters[0];
    assert(tiers > 0, "slot 0 must carry the tier count");
    assert(1 + 5 * tiers + 8 == slots, "slot layout must be 1 + 5*T + 8");
    foreach (c; counters)
        assert(c >= 0, "no counter may be negative");

    // A destination shorter than the requirement is a relayed
    // BufferTooSmall, not a silent truncation.
    bool tooSmall = false;
    try
        cast(void) poolStats(new long[1]);
    catch (ItbException e)
        tooSmall = e.status == Status.BufferTooSmall;
    assert(tooSmall, "a short destination must raise BufferTooSmall");

    // Heap profile: a writable path yields a non-empty pprof file whose
    // gzip magic is intact; an unwritable one throws.
    immutable path = "/tmp/itb-d-runtime-test.pprof";
    writeHeapProfile(path);
    assert(exists(path), "heap profile was not created");
    assert(getSize(path) > 0, "heap profile is empty");
    auto magic = cast(ubyte[]) read(path, 2);
    remove(path);
    assert(magic == [0x1f, 0x8b], "heap profile is not a gzip stream");

    bool rejected = false;
    try
        writeHeapProfile("/proc/itb-no-such-directory/heap.pprof");
    catch (ItbException)
        rejected = true;
    assert(rejected, "an unwritable path must throw");

    // Hash registry: the names Pipeline.create accepts for innerHash,
    // in canonical order, with the canonical first entry present.
    auto names = hashNames();
    assert(names.length > 0, "hashNames must not be empty");
    assert(names.canFind("areion512"), "hashNames must carry areion512");
    assert(names.canFind("aesitb128"), "hashNames must carry aesitb128");
    assert(!names.canFind("nope"), "hashNames must not carry an unregistered name");

    // The enumeration is the authority the flag validation reads: a
    // name it carries constructs.
    auto opts = Opts().withInnerHash("blake3");
    auto p = Pipeline.create("singlemsg-triple-mac-v1", opts);
    assert(p.save().length > 0, "a registry name must construct");

    // Auto DRBG tier: one of the two fill ciphers, resolved per host.
    immutable tier = drbgAutoTier();
    assert(tier == "aes-256-ctr" || tier == "chacha20", "drbg auto tier: " ~ tier);

    writeln("PASS test_runtime");
}
