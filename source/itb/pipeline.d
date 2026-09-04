/// RAII wrapper around the Triple Pipeline handle.
module itb.pipeline;

import itb.buffer;
import itb.error;
import itb.ffi;
import itb.opts;
import itb.profile;
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

/// Floor capacity for blob / JSON output buffers (Init / Rekey / Save
/// / Inspect / Lookup / Profiles).
private enum size_t blobCap = 64 * 1024;

/// Pre-allocation formula for Message / one-shot stream outputs:
/// `max(131072, payload * 5/4 + 131072)`.
private size_t outCap(size_t payload) @safe pure nothrow @nogc
{
    immutable size_t cap = payload + payload / 4 + 131_072;
    return cap > 131_072 ? cap : 131_072;
}

/// Single retry-once dispatch site for the cold blob / JSON outputs
/// (Init / Rekey / Save / Inspect / Lookup / Profiles): pre-allocate
/// `cap`, and on `BufferTooSmall` retry once
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

/// A Triple Pipeline session.
///
/// [Pipeline.save] exports the session bundle the receiver feeds to
/// [Pipeline.load]; [Pipeline.rekey] refreshes it. The destructor
/// frees the handle (libitb zeroes key material internally). The
/// struct is non-copyable; pass by `ref` or move.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
struct Pipeline
{
    private size_t handle;

    @disable this(this);

    /// Constructs a fresh Pipeline against the named profile (the
    /// `init` name is reserved in D; `create` is the constructor
    /// entry). The session bundle is available through
    /// [Pipeline.save]. On a blob-buffer retry the Init re-runs and
    /// yields a fresh session (the undersized attempt is closed by
    /// libitb before returning).
    static Pipeline create(string profile, Opts opts = Opts()) @trusted
    {
        import std.string : toStringz;

        auto profileC = profile.toStringz;
        auto optsC = opts.build().toStringz;
        Pipeline p;
        cast(void) retryOnce(blobCap, (buf, len)
            => ITB_Triple_Init(profileC, optsC,
                buf.length ? &buf[0] : null, buf.length, len, &p.handle));
        return p;
    }

    /// Reconstructs a Pipeline from a blob produced by [Pipeline.save]
    /// or [Pipeline.rekey]. Pass empty `perm` / `wrap` to use the
    /// blob-embedded masters; supply both to override them (the pair
    /// is validated by libitb). The profile shape travels inside the
    /// blob — no profile name, no opts. A blob whose record names a
    /// primitive absent from the local build fails with
    /// [Status.RecipePrimitiveUnknown]; a record failing the profile
    /// field rules with [Status.BlobMalformedRecipe].
    static Pipeline load(scope const(ubyte)[] blob,
            scope const(ubyte)[] perm = null,
            scope const(ubyte)[] wrap = null) @trusted
    {
        Pipeline p;
        check(ITB_Triple_Load(
            blob.length ? &blob[0] : null, blob.length,
            perm.length ? &perm[0] : null, perm.length,
            wrap.length ? &wrap[0] : null, wrap.length,
            mastersCount(perm, wrap), &p.handle));
        return p;
    }

    /// [Pipeline.load] for a blob stored at `path`; the file is read
    /// inside libitb (a missing or unreadable file fails with
    /// [Status.BadInput] and the diagnostic attached).
    static Pipeline loadF(string path,
            scope const(ubyte)[] perm = null,
            scope const(ubyte)[] wrap = null) @trusted
    {
        import std.string : toStringz;

        Pipeline p;
        check(ITB_Triple_LoadF(path.toStringz,
            perm.length ? &perm[0] : null, perm.length,
            wrap.length ? &wrap[0] : null, wrap.length,
            mastersCount(perm, wrap), &p.handle));
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

    /// The current session bundle bytes for the receiver side (the
    /// Init blob, or the bytes of the latest [Pipeline.rekey]). A
    /// closed Pipeline fails with [Status.TripleClosed].
    ubyte[] save() @trusted
    {
        return retryOnce(blobCap, (buf, len)
            => ITB_Triple_Save(handle,
                buf.length ? &buf[0] : null, buf.length, len));
    }

    /// Writes the current blob to `path` inside libitb (mode 0600; the
    /// containing directory must exist).
    void saveF(string path) @trusted
    {
        import std.string : toStringz;

        check(ITB_Triple_SaveF(handle, path.toStringz));
    }

    /// Sets the worker cap for every subsequent cipher call. `n` is
    /// clamped by libitb (`<= 0` selects auto, `> 256` becomes 256);
    /// only the handle state is reported. The cap is per-machine and
    /// never travels in the blob.
    void maxWorkers(int n) @trusted
    {
        check(ITB_Triple_MaxWorkers(handle, n));
    }

    /// Rotates the parallax + wrapper masters and returns the fresh
    /// blob (also available through [Pipeline.save]). Must not run
    /// concurrently with cipher calls or open stream sessions on the
    /// same Pipeline.
    ubyte[] rekey(scope const(ubyte)[] perm, scope const(ubyte)[] wrap) @trusted
    {
        return retryOnce(blobCap, (buf, len)
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

/// The masters pair crosses as (perm, wrap, count): both absent → 0,
/// otherwise 2 — libitb validates the pair.
private size_t mastersCount(scope const(ubyte)[] perm,
        scope const(ubyte)[] wrap) @safe pure nothrow @nogc
{
    return (perm.length == 0 && wrap.length == 0) ? 0 : 2;
}

/// Decodes the profile record embedded in `blob` without constructing
/// a Pipeline. No registry read, no primitive probe — a primitive
/// name the local build lacks is returned unchanged.
Profile inspect(scope const(ubyte)[] blob) @trusted
{
    auto json = retryOnce(blobCap, (buf, len)
        => ITB_Triple_Inspect(
            blob.length ? &blob[0] : null, blob.length,
            buf.length ? &buf[0] : null, buf.length, len));
    return Profile.fromJson(cast(string) json);
}

/// Registers a user-defined Triple profile under `name` so subsequent
/// [Pipeline.create] calls resolve it. The record's field rules are
/// validated by libitb; a duplicate name fails with
/// [Status.ProfileExists]. A non-empty `profile.name` must equal
/// `name`.
void register(string name, const Profile profile) @trusted
{
    import std.string : toStringz;

    check(ITB_Triple_Register(name.toStringz, profile.toJson().toStringz));
}

/// Returns the profile registered under `name` — a shipped catalogue
/// entry or a prior [register] call. An unregistered name fails with
/// [Status.UnknownProfile].
Profile lookup(string name) @trusted
{
    import std.string : toStringz;

    auto nameC = name.toStringz;
    auto json = retryOnce(blobCap, (buf, len)
        => ITB_Triple_Lookup(nameC,
            buf.length ? &buf[0] : null, buf.length, len));
    return Profile.fromJson(cast(string) json);
}

/// Returns the sorted list of every registered profile name.
string[] profiles() @trusted
{
    import std.json : parseJSON;

    auto json = retryOnce(blobCap, (buf, len)
        => ITB_Triple_Profiles(buf.length ? &buf[0] : null, buf.length, len));
    string[] names;
    foreach (v; parseJSON(cast(string) json).array)
        names ~= v.str;
    return names;
}
