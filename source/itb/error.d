/// Exception type shared by every fallible call in the binding.
module itb.error;

import itb.ffi;
import itb.status;

/// Thrown when libitb returns a non-OK status. `status` carries the
/// structural code; the message appends the `ITB_LastError`
/// diagnostic captured immediately after the failing call
/// (errno-style last-write-wins — the text may belong to a different
/// call under concurrent FFI use; the status code is always
/// attributable).
class ItbException : Exception
{
    /// The libitb status code of the failing call.
    Status status;

    this(Status st, string diagnostic,
         string file = __FILE__, size_t line = __LINE__) @safe
    {
        import std.format : format;

        status = st;
        auto msg = diagnostic.length == 0
            ? format("itb: status=%d (%s)", cast(int) st, statusLabel(st))
            : format("itb: status=%d (%s): %s", cast(int) st, statusLabel(st), diagnostic);
        super(msg, file, line);
    }
}

/// Builds an [ItbException] from a raw return code, pulling the
/// `ITB_LastError` diagnostic at construction time.
package(itb) ItbException fromRc(int rc,
        string file = __FILE__, size_t line = __LINE__) @safe
{
    return new ItbException(statusFromRc(rc), lastError(), file, line);
}

/// Maps a raw FFI return code onto success / thrown [ItbException].
package(itb) void check(int rc,
        string file = __FILE__, size_t line = __LINE__) @safe
{
    if (rc != Status.OK)
        throw fromRc(rc, file, line);
}

/// Two-phase read over the `(out, cap, *out_len)` C-string contract:
/// probe with null / 0 for the required capacity, then read and
/// NUL-strip. Returns the empty string when the call yields nothing.
package(itb) string readCString(
        scope int delegate(char*, size_t, size_t*) @system call) @trusted
{
    size_t need = 0;
    // The null/0 probe form is part of the contract — it reports the
    // required capacity without writing.
    int rc = call(null, 0, &need);
    if ((rc != Status.OK && rc != Status.BufferTooSmall) || need <= 1)
        return "";
    auto buf = new char[need];
    rc = call(&buf[0], buf.length, &need);
    if (rc != Status.OK)
        return "";
    // need includes the trailing NUL.
    return cast(string) buf[0 .. need - 1];
}

/// Reads the `ITB_LastError` diagnostic (NUL-stripped). Returns the
/// empty string when no diagnostic is recorded.
string lastError() @trusted
{
    return readCString((buf, cap, len) => ITB_LastError(buf, cap, len));
}
