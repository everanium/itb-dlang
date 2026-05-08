/// Typed exception hierarchy raised by every safe wrapper on a non-OK
/// libitb status, plus the `raiseFor` helper that maps a numeric status
/// code to the right exception with the right structured payload
/// attached.
///
/// The 5-class layout lets callers catch the structurally-distinct
/// failure modes selectively while still falling through to the base
/// class for generic handling:
///
///     base                    ← ITBError (carries .statusCode + .message)
///     EasyMismatch (.field)   ← ITBEasyMismatchError
///     BlobModeMismatch        ← ITBBlobModeMismatchError
///     BlobMalformed           ← ITBBlobMalformedError
///     BlobVersionTooNew       ← ITBBlobVersionTooNewError
///
/// The structured `.statusCode` field on every exception preserves the
/// "match by code" idiom alongside the type-based catch hierarchy.
///
/// Threading caveat. The textual `message` is read from a process-wide
/// atomic inside libitb that follows the C `errno` discipline: the
/// most recent non-OK status across the whole process wins, and a
/// sibling thread that calls into libitb between the failing call and
/// the diagnostic read overwrites the message. The structural
/// `.statusCode` on the failing call's return value is unaffected —
/// only the textual diagnostic is racy.
module itb.errors;

import std.conv : to;

import itb.status;
import itb.sys;

/// Base exception raised by every fallible libitb wrapper on a non-OK
/// status that does not have a more specific typed subclass below.
class ITBError : Exception
{
    /// Structural status code (one of the constants in `itb.status`).
    /// The code is the only piece of an `ITBError` reliably
    /// attributable to the failing call — the textual `message` is
    /// racy under concurrent FFI use across threads.
    int statusCode;

    /// Detail message read from `ITB_LastError` at construction time.
    /// Empty string if libitb did not record a textual diagnostic.
    string detail;

    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(formatMessage(code, detailMsg), file, line, next);
        this.statusCode = code;
        this.detail = detailMsg;
    }
}

/// Easy Mode encryptor: persisted-config field disagrees with the
/// receiving encryptor (peek / import / chunk-len boundary). The
/// mismatched field name is exposed via `.field`.
class ITBEasyMismatchError : ITBError
{
    /// Name of the field that disagreed (e.g. `"primitive"`,
    /// `"key_bits"`, `"mode"`, `"mac"`). Empty string if libitb did
    /// not record one. Field names use the snake_case form libitb
    /// emits over the FFI; do not D-camelCase them on the way out.
    string field;

    this(int code, string fieldName, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
        this.field = fieldName;
    }
}

/// Native Blob: persisted mode (Single / Triple) or width does not
/// match the receiving Blob.
class ITBBlobModeMismatchError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Native Blob: payload fails internal sanity checks (magic / CRC /
/// structural).
class ITBBlobMalformedError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Native Blob: persisted format version is newer than this build of
/// libitb knows how to parse.
class ITBBlobVersionTooNewError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Streaming AEAD: input exhausted without observing a chunk whose
/// recovered final_flag is set. Surfaced by the auth-stream decrypt
/// loop on truncate-tail.
class ITBStreamTruncatedError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Streaming AEAD: extra chunk bytes followed the terminating chunk
/// (final_flag = 1). Surfaced by the auth-stream decrypt loop when a
/// transcript carries data past the terminator.
class ITBStreamAfterFinalError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Returns true when the call succeeded; false otherwise. Thin helper
/// for the rare callers that want to inspect a status without
/// allocating an exception.
bool isOk(int status) @safe @nogc nothrow pure
{
    return status == Status.OK;
}

/// Translates a non-OK status code into the right typed exception and
/// throws. Reads `ITB_LastError` for the textual diagnostic and (for
/// `EASY_MISMATCH`) `ITB_Easy_LastMismatchField` for the field name.
/// Never returns. Throws `Error` if called with `Status.OK` (caller
/// bug — defensive guard).
void raiseFor(int status) @trusted
{
    if (status == Status.OK)
    {
        throw new Error("itb.errors.raiseFor called with Status.OK");
    }

    string detailMsg = readLastError();

    switch (status)
    {
        case Status.EasyMismatch:
            throw new ITBEasyMismatchError(status, readLastMismatchField(), detailMsg);

        case Status.BlobModeMismatch:
            throw new ITBBlobModeMismatchError(status, detailMsg);

        case Status.BlobMalformed:
            throw new ITBBlobMalformedError(status, detailMsg);

        case Status.BlobVersionTooNew:
            throw new ITBBlobVersionTooNewError(status, detailMsg);

        case Status.StreamTruncated:
            throw new ITBStreamTruncatedError(status, detailMsg);

        case Status.StreamAfterFinal:
            throw new ITBStreamAfterFinalError(status, detailMsg);

        default:
            throw new ITBError(status, detailMsg);
    }
}

/// `raiseFor` shorthand: returns silently on `Status.OK`, otherwise
/// raises the appropriate typed exception. Used by every safe wrapper
/// on its FFI return value.
void check(int status) @trusted
{
    if (status != Status.OK)
    {
        raiseFor(status);
    }
}

/// Reads `ITB_LastError` into a D string, stripping the trailing NUL
/// libitb's C-string getters count in `outLen`. Returns the empty
/// string when libitb has no diagnostic, the buffer-size probe fails,
/// or the second pass fails — never throws (the diagnostic itself is
/// best-effort and an exception inside the exception constructor would
/// mask the real failure).
string readLastError() @trusted nothrow
{
    size_t outLen = 0;
    int rc = ITB_LastError(null, 0, &outLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
    {
        return "";
    }
    if (outLen <= 1)
    {
        return "";
    }
    char[] buf = new char[outLen];
    rc = ITB_LastError(buf.ptr, outLen, &outLen);
    if (rc != Status.OK || outLen <= 1)
    {
        return "";
    }
    // Strip the trailing NUL libitb counts in outLen.
    return (cast(string) buf[0 .. outLen - 1]).idup;
}

/// Reads `ITB_Easy_LastMismatchField` into a D string, stripping the
/// trailing NUL libitb counts in `outLen`. Returns the empty string
/// when libitb has no field on record. Never throws (best-effort, like
/// `readLastError`).
string readLastMismatchField() @trusted nothrow
{
    size_t outLen = 0;
    int rc = ITB_Easy_LastMismatchField(null, 0, &outLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
    {
        return "";
    }
    if (outLen <= 1)
    {
        return "";
    }
    char[] buf = new char[outLen];
    rc = ITB_Easy_LastMismatchField(buf.ptr, outLen, &outLen);
    if (rc != Status.OK || outLen <= 1)
    {
        return "";
    }
    return (cast(string) buf[0 .. outLen - 1]).idup;
}

/// Generic size-out-param string accessor: probes with `cap = 0` to
/// discover the required size, then allocates and reads. Used by every
/// libitb getter that takes an `(out_buf, cap, out_len)` triple
/// (`ITB_Version`, `ITB_HashName`, `ITB_MACName`,
/// `ITB_SeedHashName`, `ITB_Easy_Primitive`, `ITB_Easy_PrimitiveAt`,
/// `ITB_Easy_MACName`, `ITB_Blob_GetMACName`, etc.).
///
/// The trailing NUL libitb writes is stripped uniformly here so the
/// returned D string never carries the C-side terminator. The caller
/// passes a delegate that takes `(out_ptr, cap, out_len_ptr)` and
/// returns the libitb status code.
string readString(scope int delegate(char*, size_t, size_t*) @system call) @trusted
{
    size_t outLen = 0;
    int rc = call(null, 0, &outLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
    {
        raiseFor(rc);
    }
    if (outLen <= 1)
    {
        return "";
    }
    char[] buf = new char[outLen];
    rc = call(buf.ptr, outLen, &outLen);
    if (rc != Status.OK)
    {
        raiseFor(rc);
    }
    if (outLen <= 1)
    {
        return "";
    }
    // Strip the trailing NUL libitb counts in outLen.
    return (cast(string) buf[0 .. outLen - 1]).idup;
}

/// Same shape as `readString` but for byte-buffer getters
/// (`ITB_GetSeedHashKey`, `ITB_Easy_PRFKey`, `ITB_Easy_MACKey`,
/// `ITB_Blob_GetKey`, `ITB_Blob_GetMACKey`). No NUL-strip — these
/// return raw bytes, not a C string.
ubyte[] readBytes(scope int delegate(ubyte*, size_t, size_t*) @system call) @trusted
{
    size_t outLen = 0;
    int rc = call(null, 0, &outLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
    {
        raiseFor(rc);
    }
    if (outLen == 0)
    {
        return [];
    }
    ubyte[] buf = new ubyte[outLen];
    rc = call(buf.ptr, outLen, &outLen);
    if (rc != Status.OK)
    {
        raiseFor(rc);
    }
    return buf[0 .. outLen];
}

// ----- Internals --------------------------------------------------------

private string formatMessage(int code, string detail) @safe pure nothrow
{
    string codeStr;
    try
    {
        codeStr = code.to!string;
    }
    catch (Exception)
    {
        codeStr = "?";
    }
    if (detail.length == 0)
    {
        return "itb: status=" ~ codeStr;
    }
    return "itb: status=" ~ codeStr ~ " (" ~ detail ~ ")";
}
