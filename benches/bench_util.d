/// Shared timing + reporting helpers for the D binding
/// micro-benchmarks. Wall-clock via core.time.MonoTime; output is a
/// fixed-width table:
///
///   bench             size     mb_per_sec
///   message           1 MiB    <n>
///   ...
module bench_util;

import core.time : MonoTime;
import std.conv : to;
import std.format : format;
import std.process : environment;
import std.stdio : writefln, writeln;

import itb;

/// Iteration floor per case.
enum benchMinIters = 3;

/// Per-case wall-clock budget (seconds, env: ITB_BENCH_MIN_SEC).
double benchMinSeconds()
{
    auto raw = environment.get("ITB_BENCH_MIN_SEC", "");
    if (raw.length > 0)
    {
        try
        {
            immutable v = raw.to!double;
            if (v > 0.0)
                return v;
        }
        catch (Exception)
        {
        }
    }
    return 5.0;
}

/// Reads the bench-shape env vars and builds an [Opts]. Defaults
/// match root Go BENCH3.md so numbers are directly comparable.
Opts benchBuildOpts()
{
    static bool isOn(string v)
    {
        return v == "true" || v == "1";
    }

    auto opts = Opts()
        .withRaw("nonceBits", envOr("ITB_NONCE_BITS", "512"))
        .withRaw("keyBits", envOr("ITB_KEY_BITS", "1024"))
        .withParallax(isOn(environment.get("ITB_WITH_PARALLAX", "false")))
        .withWrapper(isOn(environment.get("ITB_WITH_WRAPPER", "false")));
    auto innerHash = environment.get("ITB_INNER_HASH", "");
    if (innerHash.length > 0)
        opts = opts.withInnerHash(innerHash);
    auto macName = environment.get("ITB_MAC_NAME", "");
    if (macName.length > 0)
        opts = opts.withMacName(macName);
    return opts;
}

/// The bench profile name (env: ITB_PROFILE, else `fallback`).
string benchProfileName(string fallback)
{
    return envOr("ITB_PROFILE", fallback);
}

private string envOr(string key, string fallback)
{
    auto v = environment.get(key, "");
    return v.length > 0 ? v : fallback;
}

/// CSPRNG-fills `buf` so plaintext content matches the root Go bench
/// (crypto/rand). getrandom returns at most ~33 MiB per call on
/// Linux, so loop until the whole buffer is filled. Not in the
/// timing loop.
void fillRandom(scope ubyte[] buf) @trusted
{
    for (size_t off = 0; off < buf.length;)
    {
        immutable r = getrandom(&buf[off], buf.length - off, 0);
        if (r <= 0)
            throw new Exception("getrandom failed");
        off += r;
    }
}

private extern (C) ptrdiff_t getrandom(void* buf, size_t buflen, uint flags)
    @system @nogc nothrow;

void benchHeader()
{
    writefln("%-17s %-8s %s", "bench", "size", "mb_per_sec");
}

string benchSizeLabel(size_t size)
{
    if (size >= (1UL << 20))
        return format("%d MiB", size >> 20);
    return format("%d KiB", size >> 10);
}

/// Runs `fn` until the wall-clock budget is spent (with an iteration
/// floor + one untimed warm-up), then prints one table row.
void benchCase(string name, size_t size, scope void delegate() fn)
{
    fn(); // warm-up
    immutable start = MonoTime.currTime;
    double elapsed = 0.0;
    size_t iters = 0;
    immutable budget = benchMinSeconds();
    while (elapsed < budget || iters < benchMinIters)
    {
        fn();
        iters++;
        elapsed = (MonoTime.currTime - start).total!"hnsecs" / 1e7;
    }
    immutable mb = cast(double) size * cast(double) iters / (1024.0 * 1024.0);
    writefln("%-17s %-8s %.1f", name, benchSizeLabel(size), mb / elapsed);
}
