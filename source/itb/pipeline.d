/// RAII wrapper around the Triple Pipeline handle.
module itb.pipeline;

import itb.buffer;
import itb.error;
import itb.ffi;
import itb.opts;
import itb.status;
import itb.stream;

/// Defaults the druntime GC to non-parallel marking for every program
/// that links the binding.
///
/// druntime's conservative GC spawns up to `threads - 1` helper
/// threads at the first parallel mark and parks them on a
/// manual-reset event. Between collections the helpers cycle through
/// wake / empty-work / wake on that event, and in a process whose
/// cores are saturated by libitb's Go worker pool this cycling
/// contends with the workers on every core (measured on a 16-core
/// host: ~25% of process CPU in futex lock/wake under the helper
/// threads, throughput at 16-64 MiB payloads down ~35-40%). With
/// `parallel:0` the helpers are never spawned and marking runs on
/// the collecting thread; binding-scale D heaps mark in
/// single-digit milliseconds, so no pause-time regression is
/// observable at this heap shape.
///
/// The constructor runs before druntime parses runtime options, so
/// an explicit `--DRT-gcopt=parallel:N` (or an application-defined
/// `rt_options`) still overrides this default.
pragma(crt_constructor)
private extern (C) void itb_binding_gc_mark_tune()
{
    import core.gc.config : config;

    config.parallel = 0;
}

/// Floor capacity for blob output buffers (Init / Rekey).
private enum size_t blobCap = 64 * 1024;

/// Pre-allocation formula for Message / one-shot stream outputs:
/// `max(131072, payload * 5/4 + 131072)`.
private size_t outCap(size_t payload) @safe pure nothrow @nogc
{
    immutable size_t cap = payload + payload / 4 + 131_072;
    return cap > 131_072 ? cap : 131_072;
}

/// Single retry-once dispatch site for the cold blob outputs (Init /
/// Rekey): pre-allocate `cap`, and on `BufferTooSmall` retry once
/// with the exact size the FFI reported through the length out-param.
///
/// Retry guard: only re-runs when the FFI reports a required length
/// strictly greater than the current capacity (pattern P1 in the
/// fleet audit).
///
/// The buffer is GC-managed because the blob is small (64 KiB floor),
/// long-lived, and freely aliasable. Cipher outputs go through
/// [retryOnceOwned] instead, which keeps the hot path off the GC heap.
package(itb) ubyte[] retryOnce(size_t cap,
        scope int delegate(ubyte[] buf, size_t* len) @system call) @trusted
{
    auto buf = new ubyte[cap];
    size_t len = 0;
    int rc = call(buf, &len);
    if (rc == Status.BufferTooSmall && len > cap)
    {
        buf = new ubyte[len];
        rc = call(buf, &len);
    }
    check(rc);
    return buf[0 .. len];
}

/// Malloc-backed counterpart of [retryOnce] for the cipher hot path
/// (Message / one-shot stream outputs). Same retry-once shape and P1
/// guard; the buffer lives on the C heap inside the returned
/// [BorrowedBytes], so bench-scale allocation churn never lands on
/// the D GC heap (the collector's scan cost over fresh multi-MiB
/// GC slices is what previously held D throughput at ~55% of native
/// Go at 64 MB payloads).
package(itb) BorrowedBytes retryOnceOwned(size_t cap,
        scope int delegate(ubyte[] buf, size_t* len) @system call) @trusted
{
    import core.exception : onOutOfMemoryError;
    import core.stdc.stdlib : free, malloc;

    auto raw = cast(ubyte*) malloc(cap);
    if (raw is null)
        onOutOfMemoryError();
    scope (failure)
        free(raw);
    size_t len = 0;
    int rc = call(raw[0 .. cap], &len);
    if (rc == Status.BufferTooSmall && len > cap)
    {
        free(raw);
        raw = cast(ubyte*) malloc(len);
        if (raw is null)
            onOutOfMemoryError();
        rc = call(raw[0 .. len], &len);
    }
    check(rc);
    return BorrowedBytes(raw, len);
}

/// Signature shared by the four buffer-in / buffer-out cipher entries.
private alias CipherFn = extern (C) int function(
    size_t, const(void)*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

/// A Triple Pipeline session plus its exported blob bytes.
///
/// The blob carries the session bundle the receiver feeds to
/// [Pipeline.open]; [Pipeline.rekey] refreshes it. The destructor
/// frees the handle (libitb zeroes key material internally). The
/// struct is non-copyable; pass by `ref` or move.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
struct Pipeline
{
    private size_t handle;
    private ubyte[] blobBytes;

    @disable this(this);

    /// Constructs a fresh Pipeline against the named profile (the
    /// `init` name is reserved in D; `create` is the constructor
    /// entry). On a blob-buffer retry the Init re-runs and yields a
    /// fresh session (the undersized attempt is closed by libitb
    /// before returning).
    static Pipeline create(string profile, Opts opts = Opts()) @trusted
    {
        import std.string : toStringz;

        auto profileC = profile.toStringz;
        auto optsC = opts.build().toStringz;
        Pipeline p;
        p.blobBytes = retryOnce(blobCap, (buf, len)
            => ITB_Triple_Init(profileC, optsC,
                buf.length ? &buf[0] : null, buf.length, len, &p.handle));
        return p;
    }

    /// Reconstructs a Pipeline from a blob produced by
    /// [Pipeline.create] or [Pipeline.rekey], using the blob-embedded
    /// parallax + wrapper masters.
    static Pipeline open(string profile, scope const(ubyte)[] blob,
            Opts opts = Opts()) @safe
    {
        return openImpl(profile, blob, opts, null, null, 0);
    }

    /// Reconstructs a Pipeline overriding the blob-embedded masters
    /// with the supplied parallax (`perm`) + wrapper (`wrap`) masters.
    static Pipeline open(string profile, scope const(ubyte)[] blob,
            Opts opts, scope const(ubyte)[] perm,
            scope const(ubyte)[] wrap) @safe
    {
        if (perm.length == 0 || wrap.length == 0)
            throw new ItbException(Status.BadInput,
                "master override slices must be non-empty");
        return openImpl(profile, blob, opts, perm, wrap, 2);
    }

    private static Pipeline openImpl(string profile,
            scope const(ubyte)[] blob, Opts opts,
            scope const(ubyte)[] perm, scope const(ubyte)[] wrap,
            size_t mastersCount) @trusted
    {
        import std.string : toStringz;

        auto profileC = profile.toStringz;
        auto optsC = opts.build().toStringz;
        Pipeline p;
        check(ITB_Triple_Open(profileC,
            blob.length ? &blob[0] : null, blob.length,
            optsC,
            perm.length ? &perm[0] : null, perm.length,
            wrap.length ? &wrap[0] : null, wrap.length,
            mastersCount, &p.handle));
        p.blobBytes = blob.dup;
        return p;
    }

    ~this() @trusted
    {
        if (handle == 0)
            return;
        // Free closes then releases the handle; safe from any state.
        // The status is deliberately ignored on the destructor path.
        cast(void) ITB_Triple_Free(handle);
        handle = 0;
    }

    /// The exported session bundle bytes for the receiver side.
    const(ubyte)[] blob() const @safe pure nothrow @nogc
    {
        return blobBytes;
    }

    /// Rotates the parallax + wrapper masters and refreshes
    /// [Pipeline.blob]. Must not run concurrently with cipher calls
    /// or open stream sessions on the same Pipeline.
    void rekey(scope const(ubyte)[] perm, scope const(ubyte)[] wrap) @trusted
    {
        immutable size_t cap = blobBytes.length > blobCap
            ? blobBytes.length : blobCap;
        blobBytes = retryOnce(cap, (buf, len)
            => ITB_Triple_Rekey(handle,
                perm.length ? &perm[0] : null, perm.length,
                wrap.length ? &wrap[0] : null, wrap.length,
                buf.length ? &buf[0] : null, buf.length, len));
    }

    /// Zeroes the Pipeline's key material and marks it closed.
    /// Idempotent; subsequent cipher calls fail with
    /// [Status.TripleClosed].
    void close() @trusted
    {
        check(ITB_Triple_Close(handle));
    }

    /// Single Message encrypt: one call, one self-contained wire.
    /// The result is a move-only malloc-backed buffer; it converts
    /// implicitly to `ubyte[]` and frees itself at scope exit.
    BorrowedBytes encryptMessage(scope const(ubyte)[] plain) @safe
    {
        return cipher(&ITB_Triple_EncryptMessage, plain);
    }

    /// Receive-side counterpart of [Pipeline.encryptMessage].
    BorrowedBytes decryptMessage(scope const(ubyte)[] wire) @safe
    {
        return cipher(&ITB_Triple_DecryptMessage, wire);
    }

    /// One-shot stream encrypt for callers holding the whole
    /// plaintext in memory. For an incremental feed use
    /// [Pipeline.encryptStream] / [Pipeline.encryptStreamPump].
    BorrowedBytes encryptStreamOneShot(scope const(ubyte)[] plain) @safe
    {
        return cipher(&ITB_Triple_EncryptStream, plain);
    }

    /// Receive-side counterpart of [Pipeline.encryptStreamOneShot].
    BorrowedBytes decryptStreamOneShot(scope const(ubyte)[] wire) @safe
    {
        return cipher(&ITB_Triple_DecryptStream, wire);
    }

    /// Opens an incremental encrypt session (plaintext in, wire out).
    /// The session must not outlive the Pipeline.
    EncryptStream encryptStream() @trusted
    {
        EncryptStream s;
        check(ITB_Triple_EncryptStreamBegin(handle, &s.handle));
        return s;
    }

    /// Opens an incremental decrypt session (wire in, plaintext out).
    /// The session must not outlive the Pipeline.
    DecryptStream decryptStream() @trusted
    {
        DecryptStream s;
        check(ITB_Triple_DecryptStreamBegin(handle, &s.handle));
        return s;
    }

    /// Pumps `src` through an incremental encrypt session with a
    /// bounded feed / drain slice, returning the produced wire. The
    /// session is freed on return.
    BorrowedBytes encryptStreamPump(scope const(ubyte)[] src) @safe
    {
        auto sess = encryptStream();
        return sess.pump(src);
    }

    /// Receive-side counterpart of [Pipeline.encryptStreamPump].
    BorrowedBytes decryptStreamPump(scope const(ubyte)[] src) @safe
    {
        auto sess = decryptStream();
        return sess.pump(src);
    }

    /// Shared body for the four buffer-in / buffer-out cipher entries.
    private BorrowedBytes cipher(CipherFn f, scope const(ubyte)[] src) @trusted
    {
        return retryOnceOwned(outCap(src.length), (buf, len)
            => f(handle,
                src.length ? &src[0] : null, src.length,
                buf.length ? &buf[0] : null, buf.length, len));
    }
}

/// Registers a user-defined Triple profile under `name` so subsequent
/// [Pipeline.create] / [Pipeline.open] calls resolve it. The opts
/// follow the register-profile grammar validated by Go (`mode`,
/// `width`, `innerHash` / `innerHashes`, `keyBits`, `macName`,
/// `outerCipher`, `parallaxPalette`, `parallaxSegmentSize`,
/// `chunkSize`, `parallaxOn`, `wrapperOn`) — build them with
/// [Opts.withRaw] plus the typed setters where key names coincide. A
/// duplicate name fails with [Status.ProfileExists].
void registerProfile(string name, Opts opts) @trusted
{
    import std.string : toStringz;

    check(ITB_Triple_RegisterProfile(name.toStringz, opts.build().toStringz));
}
