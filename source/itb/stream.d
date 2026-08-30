/// Incremental stream sessions over an open
/// [itb.pipeline.Pipeline].
///
/// A session is a dumb byte pump: [EncryptStream] takes plaintext in
/// through `write` and yields wire through `read` / `drainAll`;
/// [DecryptStream] is the mirror (wire in, plaintext out). All
/// chunking, MAC, envelope, and wire-format decisions stay inside
/// libitb. The destructor cancels the session and frees the Go-side
/// state. A session must not outlive its parent Pipeline.
module itb.stream;

import itb.buffer;
import itb.error;
import itb.ffi;

/// Feed / drain slice size used by the pump loops.
private enum size_t pumpBuf = 1 << 20;

/// Shared body for the two session directions. The Go-side session
/// handle is direction-agnostic once opened, so both structs carry
/// identical behaviour.
private mixin template SessionBody()
{
    package(itb) size_t handle;
    private bool ended;

    @disable this(this);

    ~this() @trusted
    {
        if (handle == 0)
            return;
        // StreamFree cancels and releases the session from any state.
        // The status is deliberately ignored on the destructor path.
        cast(void) ITB_Triple_StreamFree(handle);
        handle = 0;
    }

    /// Feeds `src` into the session. Blocks until the cipher chain
    /// accepts the bytes; errors are sticky. An empty slice is a
    /// no-op.
    void write(scope const(ubyte)[] src) @trusted
    {
        check(ITB_Triple_StreamWrite(handle,
            src.length ? &src[0] : null, src.length));
    }

    /// Signals end-of-input. Idempotent; `write` after `end` fails
    /// with `BadInput`.
    void end() @trusted
    {
        check(ITB_Triple_StreamEnd(handle));
        ended = true;
    }

    /// Drains up to `dst.length` produced bytes into `dst`; returns
    /// the byte count and sets `finished` once the session has ended
    /// AND the spool is fully drained. Partial drains are normal.
    /// After `end`, an empty-spool read blocks until the terminal
    /// bytes arrive or the session errors.
    size_t read(scope ubyte[] dst, out bool finished) @trusted
    {
        size_t n = 0;
        int fin = 0;
        check(ITB_Triple_StreamRead(handle,
            dst.length ? &dst[0] : null, dst.length, &n, &fin));
        finished = fin != 0;
        return n;
    }

    /// Calls `end` (if not yet called) and returns every remaining
    /// output byte in a move-only malloc-backed buffer (it converts
    /// implicitly to `ubyte[]` and frees itself at scope exit).
    BorrowedBytes drainAll() @trusted
    {
        if (!ended)
            end();
        OwnedBuilder acc;
        auto buf = scratch();
        scope (exit) freeScratch(buf);
        for (;;)
        {
            bool fin;
            immutable n = read(buf, fin);
            acc.put(buf[0 .. n]);
            if (fin)
                return acc.take();
        }
    }

    /// Feeds `src` in bounded slices, draining available output
    /// after each write, then ends the session and drains the tail.
    package(itb) BorrowedBytes pump(scope const(ubyte)[] src) @trusted
    {
        OwnedBuilder acc;
        // Encrypt output runs ~1.25x the input plus framing; decrypt
        // output is smaller. Reserving the encrypt-side envelope up
        // front makes the common case a single allocation.
        acc.reserve(src.length + src.length / 4 + 131_072);
        auto buf = scratch();
        scope (exit) freeScratch(buf);
        for (size_t off = 0; off < src.length; off += pumpBuf)
        {
            immutable hi = off + pumpBuf < src.length
                ? off + pumpBuf : src.length;
            write(src[off .. hi]);
            // Drain whatever the chain has produced so far; a read
            // before end() never blocks.
            for (;;)
            {
                bool fin;
                immutable n = read(buf, fin);
                if (n == 0)
                    break;
                acc.put(buf[0 .. n]);
            }
        }
        end();
        for (;;)
        {
            bool fin;
            immutable n = read(buf, fin);
            acc.put(buf[0 .. n]);
            if (fin)
                return acc.take();
        }
    }

    /// Malloc-backed feed / drain scratch slice — keeps the pump
    /// loops off the GC heap alongside the accumulator.
    private static ubyte[] scratch() @trusted
    {
        import core.exception : onOutOfMemoryError;
        import core.stdc.stdlib : malloc;

        auto raw = cast(ubyte*) malloc(pumpBuf);
        if (raw is null)
            onOutOfMemoryError();
        return raw[0 .. pumpBuf];
    }

    /// Releases a [scratch] slice.
    private static void freeScratch(ubyte[] buf) @trusted @nogc nothrow
    {
        import core.stdc.stdlib : free;

        if (buf.length)
            free(&buf[0]);
    }
}

/// Incremental encrypt session: plaintext in, wire out.
struct EncryptStream
{
    mixin SessionBody;
}

/// Incremental decrypt session: wire in, plaintext out.
struct DecryptStream
{
    mixin SessionBody;
}
