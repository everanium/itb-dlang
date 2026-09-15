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

/// Returns the libitb3 library version string (`version` is a D
/// keyword, hence the long-form name).
string libitb3Version() @trusted
{
    return readCString((buf, cap, len) => ITB_Version(buf, cap, len));
}
