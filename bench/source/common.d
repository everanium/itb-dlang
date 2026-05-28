/// Shared scaffolding for the D Easy Mode benchmark binaries.
///
/// The harness mirrors the Go ``testing.B`` benchmark style on the
/// itb_ext_test.go / itb3_ext_test.go side: each bench function runs
/// a short warm-up batch to reach steady state, then a measured batch
/// whose total wall-clock time is divided by the iteration count to
/// produce the canonical ``ns/op`` throughput line. The output line
/// also carries an MB/s figure derived from the configured payload
/// size, matching the Go reporter's ``-benchmem``-less default.
///
/// Environment variables (mirrored from itb's bitbyte_test.go +
/// extended for Easy Mode):
///
/// * `ITB_NONCE_BITS` - process-wide nonce width override; valid
///   values 128 / 256 / 512. Maps to `itb.setNonceBits` before any
///   encryptor is constructed. Default 128.
/// * `ITB_LOCKBATCH` - non-empty / non-`0` enables Lock Batch (the
///   performance Lock Soup mode); set with `ITB_LOCKSEED`. Every Easy
///   Mode encryptor additionally calls `Encryptor.setLockBatch(1)`.
///   Inert unless Lock Soup is engaged via `ITB_LOCKSEED`. Default off.
/// * `ITB_LOCKSEED` - when set to a non-empty / non-`0` value, every
///   Easy Mode encryptor in this run calls `Encryptor.setLockSeed`
///   with mode=1. The Go side's auto-couple invariant then engages
///   BitSoup + LockSoup automatically; no separate flags required
///   for Easy Mode. Default off.
/// * `ITB_BENCH_FILTER` - substring filter on bench-case names; only
///   cases whose name contains the filter run. Default unset.
/// * `ITB_BENCH_MIN_SEC` - minimum measured wall-clock seconds per
///   case. Default 5.0 - wide enough to absorb the cold-cache /
///   warm-up transient that distorts shorter measurement windows
///   on the 16 MiB encrypt / decrypt path.
///
/// Worker count defaults to `itb.setMaxWorkers(0)` (auto-detect),
/// matching the Go bench default. Bench scripts may override before
/// calling `measureAndPrint`.
module bench.common;

import core.atomic : atomicOp;
import std.conv : to;
import std.datetime.stopwatch : StopWatch, AutoStart;
import std.format : format;
import std.process : environment;
import std.stdio : stderr, writefln, writeln;

/// Default 16 MiB CSPRNG-filled payload, matching the Go bench /
/// Python bench / Rust bench / Ada bench surfaces.
enum size_t PAYLOAD_16MB = 16 << 20;

/// Canonical PRF-grade primitive order. Mirrored verbatim across
/// every binding's bench harness so cross-language diff comparisons
/// align row-for-row.
immutable string[] PRIMITIVES_CANONICAL = [
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
];

/// Reads `ITB_NONCE_BITS` from the environment with the same
/// 128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
/// back to `defaultValue` on missing / invalid input (with a stderr
/// diagnostic for the invalid case).
int envNonceBits(int defaultValue) @trusted
{
    string v = environment.get("ITB_NONCE_BITS", "");
    if (v.length == 0)
        return defaultValue;
    switch (v)
    {
        case "128": return 128;
        case "256": return 256;
        case "512": return 512;
        default:
            stderr.writefln(
                "ITB_NONCE_BITS=%s invalid (expected 128/256/512); using %d",
                v, defaultValue);
            return defaultValue;
    }
}

/// `true` when `ITB_LOCKBATCH` is set to a non-empty / non-`0` value.
/// Triggers `Encryptor.setLockBatch(1)` on every encryptor. Inert
/// unless Lock Soup is engaged via `ITB_LOCKSEED`.
bool envLockBatch() @trusted
{
    string v = environment.get("ITB_LOCKBATCH", "");
    return !(v.length == 0 || v == "0");
}

/// `true` when `ITB_LOCKSEED` is set to a non-empty / non-`0` value.
/// Triggers `Encryptor.setLockSeed(1)` on every encryptor; Easy Mode
/// auto-couples BitSoup + LockSoup as a side effect.
bool envLockSeed() @trusted
{
    string v = environment.get("ITB_LOCKSEED", "");
    return !(v.length == 0 || v == "0");
}

/// Optional substring filter for bench-case names, read from
/// `ITB_BENCH_FILTER`. Cases whose name does not contain the filter
/// substring are skipped; used to scope a run down to a single
/// primitive or operation during development. Returns `null` when
/// the variable is unset or empty.
string envFilter() @trusted
{
    string v = environment.get("ITB_BENCH_FILTER", "");
    return v.length == 0 ? null : v;
}

/// Minimum wall-clock seconds the measured iter loop should take,
/// read from `ITB_BENCH_MIN_SEC` (default 5.0). The runner keeps
/// doubling iteration count until the measured run reaches this
/// threshold, mirroring Go's `-benchtime=Ns` semantics. The
/// 5-second default is wide enough to absorb the cold-cache /
/// warm-up transient that distorts shorter measurement windows on
/// the 16 MiB encrypt / decrypt path.
double envMinSeconds() @trusted
{
    string v = environment.get("ITB_BENCH_MIN_SEC", "");
    if (v.length == 0)
        return 5.0;
    try
    {
        double f = v.to!double;
        if (f > 0.0)
            return f;
    }
    catch (Exception)
    {
        // fall through to invalid-input diagnostic below
    }
    stderr.writefln(
        "ITB_BENCH_MIN_SEC=%s invalid (expected positive float); using 5.0",
        v);
    return 5.0;
}

// xorshift64* state seeded from the monotonic clock + a per-call
// counter so successive `randomBytes` calls within the same
// nanosecond still diverge. The bench harness does not require
// cryptographic strength here, only that the payload is non-uniform
// and changes between runs so a primitive cannot collapse on a
// constant input.
private shared ulong _randomCounter;

/// Returns `n` non-deterministic test bytes via a clock-seeded
/// xorshift64* LCG. Matches the Go-side generateDataExt /
/// crypto/rand-fill pattern in spirit; the bench harness does not
/// require cryptographic strength here, only payload non-uniformity
/// and run-to-run divergence.
ubyte[] randomBytes(size_t n) @trusted
{
    ulong salt = atomicOp!"+="(_randomCounter, 1UL);
    auto sw = StopWatch(AutoStart.yes);
    sw.stop();
    ulong nanos = cast(ulong) sw.peek.total!"nsecs";
    ulong state = (nanos * 0x9E37_79B9_7F4A_7C15UL)
        + salt
        + 0xBF58_476D_1CE4_E5B9UL;
    if (state == 0)
        state = 0xDEAD_BEEF_CAFE_F00DUL;
    auto outBuf = new ubyte[n];
    size_t i = 0;
    while (i < n)
    {
        // xorshift64* - adequate for non-cryptographic test fill.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        ulong v = state * 0x2545_F491_4F6C_DD1DUL;
        size_t take = (n - i) < 8 ? (n - i) : 8;
        foreach (k; 0 .. take)
            outBuf[i + k] = cast(ubyte)((v >> (8 * k)) & 0xFF);
        i += take;
    }
    return outBuf;
}

/// Per-iter callable; accepts an iteration count and runs the
/// per-iter body that many times. The harness measures wall-clock
/// time outside the callable.
alias BenchFn = void delegate(ulong) @trusted;

/// One bench case: name + per-iter callable + payload byte count
/// (used to compute the MB/s column).
struct BenchCase
{
    string name;
    BenchFn run;
    size_t payloadBytes;
}

/// Run a benchmark case to convergence and emit a single
/// Go-bench-style report line.
///
/// Convergence policy: warm up with one iteration, then double the
/// iteration count until the measured wall-clock duration meets
/// `minSeconds`. The final `ns/op` figure is the measured duration
/// of that final batch divided by its iteration count. Iteration
/// count is capped at `1 << 24` so a very fast op cannot escalate
/// past that ceiling for one batch.
private void measure(ref BenchCase c, double minSeconds) @trusted
{
    // Warm-up - one iteration to hit cache / cold-start transients
    // before the measured loop.
    c.run(1);

    long minNs = cast(long)(minSeconds * 1.0e9);
    ulong iters = 1;
    long elapsed = 0;
    while (true)
    {
        auto sw = StopWatch(AutoStart.yes);
        c.run(iters);
        sw.stop();
        elapsed = sw.peek.total!"nsecs";
        if (elapsed >= minNs)
            break;
        if (iters >= (1UL << 24))
            break;
        iters *= 2;
    }

    double nsPerOp = cast(double) elapsed / cast(double) iters;
    double mbPerS = 0.0;
    if (nsPerOp > 0.0)
    {
        double bytesPerSec = cast(double) c.payloadBytes / (nsPerOp / 1.0e9);
        mbPerS = bytesPerSec / cast(double)(1UL << 20);
    }
    // Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
    // column-aligned for human reading.
    writeln(format("%-60s\t%10d\t%14.1f ns/op\t%9.2f MB/s",
        c.name, iters, nsPerOp, mbPerS));
}

/// Measure a single pre-built case at the given `minSeconds` threshold
/// and emit one Go-bench-style report line.  Used by the lazy bench
/// runner in bench_wrapper.d — the caller handles filtering and the
/// header line; this function handles only measurement + output for one
/// case.
void measureAndPrint(ref BenchCase c, double minSeconds) @trusted
{
    measure(c, minSeconds);
}

/// Pure D substring containment. Returns `true` iff `needle` occurs
/// somewhere in `haystack`. Empty `needle` returns `true`.
private bool _contains(string haystack, string needle) @safe @nogc nothrow pure
{
    if (needle.length == 0)
        return true;
    if (needle.length > haystack.length)
        return false;
    foreach (i; 0 .. haystack.length - needle.length + 1)
    {
        bool match = true;
        foreach (j; 0 .. needle.length)
        {
            if (haystack[i + j] != needle[j])
            {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}
