/// The `extern (C)` surface of libitb3 as the binding calls it: one
/// declaration per `ITB_*` export, each reached through a guard that
/// blocks druntime's collector signals for the duration of the call.
///
/// D speaks the C ABI natively, so this module is a one-to-one mirror
/// of the Triple Pipeline prototypes in `dist/<os>-<arch>/libitb3.h`.
/// Linking is compile-time (`-litb3` with an rpath onto the dist
/// directory — see `run_tests.sh` / `run_bench.sh` / `build.sh`); no
/// runtime loader code lives in the binding.
///
/// Type mapping:
///   - C `int`        → D `int`
///   - C `int64_t`    → D `long`
///   - C `size_t`     → D `size_t`
///   - C `uintptr_t`  → D `size_t` (host word size on every platform
///                      libitb3 supports)
///   - C `void*`      → D `void*`
///   - C `char*`      → D `const(char)*` (libitb3 never mutates the
///                      name / opts strings it receives)
///
/// Threading note. `ITB_LastError` follows the C `errno` discipline:
/// the most recent non-OK status on the calling thread wins, and the
/// textual diagnostic attached to an [itb3.error.ItbException] may
/// belong to a different call under concurrent FFI use. The status
/// code on the failing call's return value is always attributable.
///
/// Safety. Every declaration here is `@system` — raw FFI taking and
/// returning pointers the D type system cannot reason about. The
/// `@trusted` wrappers in `itb3.pipeline` / `itb3.stream` /
/// `itb3.runtime` / `itb3.error` re-establish memory safety at the
/// binding boundary by pairing every pointer with its length before
/// each call.

///
/// GC-signal guard. druntime stops the world for a collection by
/// sending every registered thread a signal whose handler runs on the
/// interrupted thread's current stack and records the handler's stack
/// pointer as that thread's stack top. A thread inside a libitb3 call
/// is executing on a Go goroutine stack — a small heap-allocated
/// stack; the goroutine that serves a cgo callback starts at 4 KiB —
/// so the handler's frame lands in Go-owned memory below the
/// goroutine's stack pointer, and the recorded stack top is a heap
/// address rather than one on the thread's OS stack. Either effect is
/// fatal: the frame overwrites whatever Go memory sits below the
/// stack, and the collector's conservative scan from that heap
/// address up to the OS stack base walks unmapped pages and faults.
/// The trigger is any collection, started by any thread, while any
/// druntime thread is inside libitb3 with its stack pointer on a
/// goroutine stack; which thread allocated is immaterial.
///
/// Every guarded entry below therefore blocks both GC signals on the
/// calling thread for the duration of the raw call. A signal sent
/// while the thread is inside libitb3 stays pending until the call
/// returns, and the thread is then suspended on its own stack with
/// every D frame in view of the collector. Blocking alone is not
/// enough with druntime's default numbers: the Go runtime keeps a
/// per-signal policy table in which signal 34 — glibc's SIGRTMIN,
/// druntime's default suspend signal — is one it unconditionally
/// unblocks on every thread that enters it (the slot is musl's
/// SIGSYNCCALL), so the first entry of a thread into Go strips the
/// block from that thread's mask. Signals above SIGRTMIN keep the
/// mask the caller set, hence the relocation in
/// [itb_binding_gc_signals_relocate].
///
/// Nothing inside a guarded region may allocate from the D GC heap or
/// otherwise wait on the collector: a thread that has blocked its own
/// suspend signal and then waits for a collection in progress
/// deadlocks that collection, which is waiting for the thread to
/// answer the signal. The wrappers enclose the raw call and nothing
/// else; every buffer is sized and allocated by the caller before
/// entry. The guard costs two `pthread_sigmask` calls per entry.
module itb3.ffi;

import core.sys.posix.signal : pthread_sigmask, SIG_BLOCK, SIG_SETMASK,
    sigaddset, sigemptyset, sigset_t, SIGRTMIN;
import core.thread.osthread : thread_getGCSignals, thread_setGCSignals;

/// Moves druntime's stop-the-world signals to `SIGRTMIN + 2` (suspend)
/// and `SIGRTMIN + 3` (resume) for every program that links the
/// binding. See the module documentation for why the defaults cannot
/// be blocked across a call into the Go runtime.
///
/// `thread_setGCSignals` is honoured only before `thread_init()`, so
/// the call sits in a crt constructor. This is a contract of the
/// binding: the two signal numbers are reserved for druntime's
/// collector in every process that links it, and an application must
/// neither call `thread_setGCSignals` itself nor use those numbers
/// for its own purposes.
pragma(crt_constructor)
private extern (C) void itb_binding_gc_signals_relocate()
{
    thread_setGCSignals(SIGRTMIN + 2, SIGRTMIN + 3);
}

/// The collector's two signals as a mask, resolved once druntime is
/// up so that the guard never hard-codes the numbers.
private __gshared sigset_t gcSignals;

shared static this()
{
    int suspend, resume;
    thread_getGCSignals(suspend, resume);
    sigemptyset(&gcSignals);
    sigaddset(&gcSignals, suspend);
    sigaddset(&gcSignals, resume);
}

/// Blocks the collector's signals on the calling thread between
/// `enter` and `leave`; `saved` is the mask to restore.
private struct GcSignalGuard
{
    sigset_t saved;

    static GcSignalGuard enter() @system @nogc nothrow
    {
        GcSignalGuard guard;
        pthread_sigmask(SIG_BLOCK, &gcSignals, &guard.saved);
        return guard;
    }

    void leave() @system @nogc nothrow
    {
        pthread_sigmask(SIG_SETMASK, &saved, null);
    }
}

extern (C):
@system:
@nogc:
nothrow:

// ─── Raw exports ───────────────────────────────────────────────────
//
// One-to-one mirror of libitb3.h. Each is bound to the C symbol by an
// explicit mangle and reached only through its guarded entry below;
// nothing else in the binding calls a raw_ name.

// ─── Library introspection + Go runtime knobs ──────────────────────

pragma(mangle, "ITB_Version") int raw_ITB_Version(char* outBuf, size_t capBytes, size_t* outLen);
pragma(mangle, "ITB_DRBGAutoTier") int raw_ITB_DRBGAutoTier(char* outBuf, size_t capBytes, size_t* outLen);
pragma(mangle, "ITB_LastError") int raw_ITB_LastError(char* outBuf, size_t capBytes, size_t* outLen);
pragma(mangle, "ITB_SetMemoryLimit") long raw_ITB_SetMemoryLimit(long limit);
pragma(mangle, "ITB_SetGCPercent") int raw_ITB_SetGCPercent(int pct);
pragma(mangle, "ITB_SetGOMAXPROCS") int raw_ITB_SetGOMAXPROCS(int n);
pragma(mangle, "ITB_WriteHeapProfile") int raw_ITB_WriteHeapProfile(const(char)* path);
pragma(mangle, "ITB_PoolStatsLen") int raw_ITB_PoolStatsLen();
pragma(mangle, "ITB_PoolStats") int raw_ITB_PoolStats(long* outBuf, size_t capElems, size_t* outLen);

// ─── Triple Pipeline lifecycle ─────────────────────────────────────

pragma(mangle, "ITB_Triple_Init") int raw_ITB_Triple_Init(
    const(char)* profile,
    const(char)* opts,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen,
    size_t* outHandle);

pragma(mangle, "ITB_Triple_Load") int raw_ITB_Triple_Load(
    const(void)* blob,
    size_t blobLen,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    size_t mastersCount,
    size_t* outHandle);

pragma(mangle, "ITB_Triple_LoadF") int raw_ITB_Triple_LoadF(
    const(char)* path,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    size_t mastersCount,
    size_t* outHandle);

pragma(mangle, "ITB_Triple_Save") int raw_ITB_Triple_Save(
    size_t handle,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen);

pragma(mangle, "ITB_Triple_SaveF") int raw_ITB_Triple_SaveF(size_t handle, const(char)* path);

pragma(mangle, "ITB_Triple_Inspect") int raw_ITB_Triple_Inspect(
    const(void)* blob,
    size_t blobLen,
    void* jsonOut,
    size_t jsonCap,
    size_t* jsonLen);

pragma(mangle, "ITB_Triple_MaxWorkers") int raw_ITB_Triple_MaxWorkers(size_t handle, int n);

pragma(mangle, "ITB_Triple_Rekey") int raw_ITB_Triple_Rekey(
    size_t handle,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen);

pragma(mangle, "ITB_Triple_Close") int raw_ITB_Triple_Close(size_t handle);
pragma(mangle, "ITB_Triple_Free") int raw_ITB_Triple_Free(size_t handle);

// ─── Buffer-in / buffer-out cipher entries ─────────────────────────

pragma(mangle, "ITB_Triple_EncryptStream") int raw_ITB_Triple_EncryptStream(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

pragma(mangle, "ITB_Triple_DecryptStream") int raw_ITB_Triple_DecryptStream(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

pragma(mangle, "ITB_Triple_EncryptMessage") int raw_ITB_Triple_EncryptMessage(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

pragma(mangle, "ITB_Triple_DecryptMessage") int raw_ITB_Triple_DecryptMessage(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

// ─── Profile records ───────────────────────────────────────────────

pragma(mangle, "ITB_Triple_Register") int raw_ITB_Triple_Register(const(char)* name, const(char)* profileJSON);
pragma(mangle, "ITB_Triple_Lookup") int raw_ITB_Triple_Lookup(
    const(char)* name,
    void* jsonOut,
    size_t jsonCap,
    size_t* jsonLen);
pragma(mangle, "ITB_Triple_Profiles") int raw_ITB_Triple_Profiles(void* jsonOut, size_t jsonCap, size_t* jsonLen);
pragma(mangle, "ITB_Triple_HashNames") int raw_ITB_Triple_HashNames(void* jsonOut, size_t jsonCap, size_t* jsonLen);

// ─── Incremental stream sessions ───────────────────────────────────

pragma(mangle, "ITB_Triple_EncryptStreamBegin") int raw_ITB_Triple_EncryptStreamBegin(size_t pipe, size_t* outStream);
pragma(mangle, "ITB_Triple_DecryptStreamBegin") int raw_ITB_Triple_DecryptStreamBegin(size_t pipe, size_t* outStream);
pragma(mangle, "ITB_Triple_StreamWrite") int raw_ITB_Triple_StreamWrite(size_t stream, const(void)* src, size_t srcLen);
pragma(mangle, "ITB_Triple_StreamEnd") int raw_ITB_Triple_StreamEnd(size_t stream);
pragma(mangle, "ITB_Triple_StreamRead") int raw_ITB_Triple_StreamRead(
    size_t stream,
    void* outBuf,
    size_t outCap,
    size_t* outLen,
    int* finished);
pragma(mangle, "ITB_Triple_StreamFree") int raw_ITB_Triple_StreamFree(size_t stream);

// ─── Guarded entries ───────────────────────────────────────────────
//
// The names the rest of the binding calls. Each keeps the C signature
// of its export, so a function pointer taken here still fits the
// `extern (C)` aliases in `itb3.pipeline`, and each is mangled apart
// from the export so the program never interposes on libitb3's own
// symbol.

pragma(mangle, "itb_binding_guarded_ITB_Version")
int ITB_Version(char* outBuf, size_t capBytes, size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Version(outBuf, capBytes, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_DRBGAutoTier")
int ITB_DRBGAutoTier(char* outBuf, size_t capBytes, size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_DRBGAutoTier(outBuf, capBytes, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_LastError")
int ITB_LastError(char* outBuf, size_t capBytes, size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_LastError(outBuf, capBytes, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_SetMemoryLimit")
long ITB_SetMemoryLimit(long limit)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_SetMemoryLimit(limit);
}

pragma(mangle, "itb_binding_guarded_ITB_SetGCPercent")
int ITB_SetGCPercent(int pct)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_SetGCPercent(pct);
}

pragma(mangle, "itb_binding_guarded_ITB_SetGOMAXPROCS")
int ITB_SetGOMAXPROCS(int n)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_SetGOMAXPROCS(n);
}

pragma(mangle, "itb_binding_guarded_ITB_WriteHeapProfile")
int ITB_WriteHeapProfile(const(char)* path)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_WriteHeapProfile(path);
}

pragma(mangle, "itb_binding_guarded_ITB_PoolStatsLen")
int ITB_PoolStatsLen()
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_PoolStatsLen();
}

pragma(mangle, "itb_binding_guarded_ITB_PoolStats")
int ITB_PoolStats(long* outBuf, size_t capElems, size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_PoolStats(outBuf, capElems, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Init")
int ITB_Triple_Init(
    const(char)* profile,
    const(char)* opts,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen,
    size_t* outHandle)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Init(profile, opts, blobOut, blobCap, blobLen, outHandle);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Load")
int ITB_Triple_Load(
    const(void)* blob,
    size_t blobLen,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    size_t mastersCount,
    size_t* outHandle)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Load(blob, blobLen, permMaster, permMasterLen, wrapMaster, wrapMasterLen, mastersCount, outHandle);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_LoadF")
int ITB_Triple_LoadF(
    const(char)* path,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    size_t mastersCount,
    size_t* outHandle)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_LoadF(path, permMaster, permMasterLen, wrapMaster, wrapMasterLen, mastersCount, outHandle);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Save")
int ITB_Triple_Save(
    size_t handle,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Save(handle, blobOut, blobCap, blobLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_SaveF")
int ITB_Triple_SaveF(size_t handle, const(char)* path)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_SaveF(handle, path);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Inspect")
int ITB_Triple_Inspect(
    const(void)* blob,
    size_t blobLen,
    void* jsonOut,
    size_t jsonCap,
    size_t* jsonLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Inspect(blob, blobLen, jsonOut, jsonCap, jsonLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_MaxWorkers")
int ITB_Triple_MaxWorkers(size_t handle, int n)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_MaxWorkers(handle, n);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Rekey")
int ITB_Triple_Rekey(
    size_t handle,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Rekey(handle, permMaster, permMasterLen, wrapMaster, wrapMasterLen, blobOut, blobCap, blobLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Close")
int ITB_Triple_Close(size_t handle)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Close(handle);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Free")
int ITB_Triple_Free(size_t handle)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Free(handle);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_EncryptStream")
int ITB_Triple_EncryptStream(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_EncryptStream(handle, plaintext, ptLen, outBuf, outCap, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_DecryptStream")
int ITB_Triple_DecryptStream(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_DecryptStream(handle, wire, wireLen, outBuf, outCap, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_EncryptMessage")
int ITB_Triple_EncryptMessage(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_EncryptMessage(handle, plaintext, ptLen, outBuf, outCap, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_DecryptMessage")
int ITB_Triple_DecryptMessage(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_DecryptMessage(handle, wire, wireLen, outBuf, outCap, outLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Register")
int ITB_Triple_Register(const(char)* name, const(char)* profileJSON)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Register(name, profileJSON);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Lookup")
int ITB_Triple_Lookup(
    const(char)* name,
    void* jsonOut,
    size_t jsonCap,
    size_t* jsonLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Lookup(name, jsonOut, jsonCap, jsonLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_Profiles")
int ITB_Triple_Profiles(void* jsonOut, size_t jsonCap, size_t* jsonLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_Profiles(jsonOut, jsonCap, jsonLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_HashNames")
int ITB_Triple_HashNames(void* jsonOut, size_t jsonCap, size_t* jsonLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_HashNames(jsonOut, jsonCap, jsonLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_EncryptStreamBegin")
int ITB_Triple_EncryptStreamBegin(size_t pipe, size_t* outStream)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_EncryptStreamBegin(pipe, outStream);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_DecryptStreamBegin")
int ITB_Triple_DecryptStreamBegin(size_t pipe, size_t* outStream)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_DecryptStreamBegin(pipe, outStream);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_StreamWrite")
int ITB_Triple_StreamWrite(size_t stream, const(void)* src, size_t srcLen)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_StreamWrite(stream, src, srcLen);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_StreamEnd")
int ITB_Triple_StreamEnd(size_t stream)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_StreamEnd(stream);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_StreamRead")
int ITB_Triple_StreamRead(
    size_t stream,
    void* outBuf,
    size_t outCap,
    size_t* outLen,
    int* finished)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_StreamRead(stream, outBuf, outCap, outLen, finished);
}

pragma(mangle, "itb_binding_guarded_ITB_Triple_StreamFree")
int ITB_Triple_StreamFree(size_t stream)
{
    auto guard = GcSignalGuard.enter();
    scope (exit) guard.leave();
    return raw_ITB_Triple_StreamFree(stream);
}
