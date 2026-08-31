/// Process-wide Go runtime knobs plus the library version strings.
module itb.runtime;

import itb.error;
import itb.ffi;

/// Version of the D binding itself. The libitb version is read at
/// run time via [libitbVersion].
enum bindingVersion = "0.3.1";

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

/// Returns the libitb library version string (`version` is a D
/// keyword, hence the long-form name).
string libitbVersion() @trusted
{
    return readCString((buf, cap, len) => ITB_Version(buf, cap, len));
}
