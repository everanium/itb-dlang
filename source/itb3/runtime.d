/// Process-wide Go runtime knobs plus the library version strings.
module itb3.runtime;

import itb3.error;
import itb3.ffi;

/// Version of the D binding itself. The libitb3 version is read at
/// run time via [libitb3Version].
enum bindingVersion = "0.5.1";

/// Sets the Go runtime's soft heap limit in bytes and returns the
/// previous limit. A negative value queries without changing.
long setMemoryLimit(long bytes) @trusted nothrow @nogc
{
    return ITB_SetMemoryLimit(bytes);
}

/// Sets the Go GC trigger percentage and returns the previous value.
/// A negative value queries without changing.
int setGCPercent(int pct) @trusted nothrow @nogc
{
    return ITB_SetGCPercent(pct);
}

/// Sets the Go runtime's GOMAXPROCS and returns the previous value.
/// Zero or a negative value queries without changing.
int setGOMAXPROCS(int n) @trusted nothrow @nogc
{
    return ITB_SetGOMAXPROCS(n);
}

/// Writes the Go runtime's heap profile (pprof format) to `path`
/// after one forced garbage collection. An empty path falls back to
/// the `ITB_MEMPROFILE` environment variable; a path that is still
/// empty, or a file-system failure, throws
/// [itb3.error.ItbException] carrying [itb3.status.Status.BadInput].
void writeHeapProfile(string path) @trusted
{
    import std.string : toStringz;

    check(ITB_WriteHeapProfile(path.toStringz));
}

/// Number of `long` slots [poolStats] fills. Size the destination
/// from this call, never from a constant.
size_t poolStatsLen() @trusted nothrow @nogc
{
    immutable int n = ITB_PoolStatsLen();
    return n > 0 ? cast(size_t) n : 0;
}

/// Copies the library's pool hit / miss counters into `dst` and
/// returns the slot count written. Every counter is a monotonically
/// increasing total since library load; difference two snapshots.
/// Slot layout, with `T` the tier count in slot 0: tier `i` holds
/// starter width, checkouts, constructor misses, regrow replacements
/// and bytes allocated at slots `1 + 5*i .. 1 + 5*i + 4`; the scratch
/// byte pool's get / new / regrow / regrow-bytes follow at `1 + 5*T`,
/// and the parallax chunk pool's at `1 + 5*T + 4`. A `dst` shorter
/// than [poolStatsLen] throws
/// [itb3.status.Status.BufferTooSmall].
size_t poolStats(scope long[] dst) @trusted
{
    size_t written = 0;
    check(ITB_PoolStats(dst.length ? &dst[0] : null, dst.length, &written));
    return written;
}

/// Returns the libitb3 library version string (`version` is a D
/// keyword, hence the long-form name).
string libitb3Version() @trusted
{
    return readCString((buf, cap, len) => ITB_Version(buf, cap, len));
}

/// Returns the fill cipher the auto DRBG tier selected on this host
/// (`"aes-256-ctr"` or `"chacha20"`): the tier a Pipeline uses when its
/// drbg option is empty, resolved per host and recorded in no blob.
string drbgAutoTier() @trusted
{
    return readCString((buf, cap, len) => ITB_DRBGAutoTier(buf, cap, len));
}
