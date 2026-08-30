/// Raw extern (C) declarations over the libitb `ITB_Triple_*` surface.
///
/// D speaks the C ABI natively, so this module is a one-to-one mirror
/// of the Triple Pipeline prototypes in `dist/<os>-<arch>/libitb.h`.
/// Linking is compile-time (`-litb` with an rpath onto the dist
/// directory — see `run_tests.sh` / `run_bench.sh` / `build.sh`); no
/// runtime loader code lives in the binding.
///
/// Type mapping:
///   - C `int`        → D `int`
///   - C `int64_t`    → D `long`
///   - C `size_t`     → D `size_t`
///   - C `uintptr_t`  → D `size_t` (host word size on every platform
///                      libitb supports)
///   - C `void*`      → D `void*`
///   - C `char*`      → D `const(char)*` (libitb never mutates the
///                      name / opts strings it receives)
///
/// Threading note. `ITB_LastError` follows the C `errno` discipline:
/// the most recent non-OK status on the calling thread wins, and the
/// textual diagnostic attached to an [itb.error.ItbException] may
/// belong to a different call under concurrent FFI use. The status
/// code on the failing call's return value is always attributable.
///
/// Safety. Every declaration here is `@system` — raw FFI taking and
/// returning pointers the D type system cannot reason about. The
/// `@trusted` wrappers in `itb.pipeline` / `itb.stream` /
/// `itb.runtime` / `itb.error` re-establish memory safety at the
/// binding boundary by pairing every pointer with its length before
/// each call.
module itb.ffi;

extern (C):
@system:
@nogc:
nothrow:

// ─── Library introspection + Go runtime knobs ──────────────────────

int ITB_Version(char* outBuf, size_t capBytes, size_t* outLen);
int ITB_LastError(char* outBuf, size_t capBytes, size_t* outLen);
long ITB_SetMemoryLimit(long limit);
int ITB_SetGCPercent(int pct);

// ─── Triple Pipeline lifecycle ─────────────────────────────────────

int ITB_Triple_Init(
    const(char)* profile,
    const(char)* opts,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen,
    size_t* outHandle);

int ITB_Triple_Open(
    const(char)* profile,
    const(void)* blob,
    size_t blobLen,
    const(char)* opts,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    size_t mastersCount,
    size_t* outHandle);

int ITB_Triple_Rekey(
    size_t handle,
    const(void)* permMaster,
    size_t permMasterLen,
    const(void)* wrapMaster,
    size_t wrapMasterLen,
    void* blobOut,
    size_t blobCap,
    size_t* blobLen);

int ITB_Triple_Close(size_t handle);
int ITB_Triple_Free(size_t handle);

// ─── Buffer-in / buffer-out cipher entries ─────────────────────────

int ITB_Triple_EncryptStream(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

int ITB_Triple_DecryptStream(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

int ITB_Triple_EncryptMessage(
    size_t handle,
    const(void)* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

int ITB_Triple_DecryptMessage(
    size_t handle,
    const(void)* wire,
    size_t wireLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

// ─── Profile registration ──────────────────────────────────────────

int ITB_Triple_RegisterProfile(const(char)* name, const(char)* opts);

// ─── Incremental stream sessions ───────────────────────────────────

int ITB_Triple_EncryptStreamBegin(size_t pipe, size_t* outStream);
int ITB_Triple_DecryptStreamBegin(size_t pipe, size_t* outStream);
int ITB_Triple_StreamWrite(size_t stream, const(void)* src, size_t srcLen);
int ITB_Triple_StreamEnd(size_t stream);
int ITB_Triple_StreamRead(
    size_t stream,
    void* outBuf,
    size_t outCap,
    size_t* outLen,
    int* finished);
int ITB_Triple_StreamFree(size_t stream);
