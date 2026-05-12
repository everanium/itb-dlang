/// Raw extern (C) bindings over libitb's C ABI.
///
/// D speaks the C ABI natively, so this module is a one-to-one mirror of
/// `dist/<os>-<arch>/libitb.h`: every libitb export is declared as an
/// `extern (C)` function with the matching signature. Linking is
/// resolved at build time via DUB's `lflags` (see the binding's
/// `dub.json`), with `rpath` baked into the executables so the linker
/// finds `libitb.so` next to the binding directory at run time.
///
/// Type mapping:
///   - C `int`        → D `int`
///   - C `size_t`     → D `size_t`
///   - C `uintptr_t`  → D `size_t` (host word size; D's `size_t` is the
///                      machine word, equal to `uintptr_t` on the
///                      platforms libitb supports)
///   - C `uint64_t`   → D `ulong`
///   - C `uint8_t*`   → D `ubyte*`
///   - C `void*`      → D `void*`
///   - C `char*`      → D `char*`
///
/// Threading note. `ITB_LastError` and `ITB_Easy_LastMismatchField`
/// read process-global atomics that follow the C `errno` discipline:
/// the most recent non-OK status across the whole process wins, and a
/// sibling thread that calls into libitb between the failing call and
/// the diagnostic read overwrites the message. Multi-threaded D
/// applications that need reliable diagnostic attribution should
/// serialise FFI calls under a process-wide lock or accept that the
/// textual message returned by an `ITBError` may belong to a different
/// call. The structural status code on the failing call's return value
/// is unaffected — only the textual diagnostic is racy.
///
/// Safety. Every declaration here is `@system` — these are raw FFI
/// calls that take and return pointers to memory the D type system
/// cannot reason about. The `@trusted` wrappers in
/// `itb.seed` / `itb.mac` / `itb.cipher` / `itb.encryptor` /
/// `itb.blob` / `itb.streams` re-establish memory safety at the
/// binding boundary by validating handles, lengths, and buffers before
/// each call.
module itb.sys;

extern (C):
@system:
@nogc:
nothrow:

// ----- General library introspection -------------------------------------

int ITB_Version(char* outBuf, size_t capBytes, size_t* outLen);
int ITB_HashCount();
int ITB_HashName(int i, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_HashWidth(int i);
int ITB_LastError(char* outBuf, size_t capBytes, size_t* outLen);
int ITB_MaxKeyBits();
int ITB_Channels();
int ITB_HeaderSize();
int ITB_ParseChunkLen(void* header, size_t headerLen, size_t* outChunkLen);

// ----- Seed surface -----------------------------------------------------

int ITB_NewSeed(char* hashName, int keyBits, size_t* outHandle);
int ITB_FreeSeed(size_t handle);
int ITB_SeedWidth(size_t handle, int* outStatus);
int ITB_SeedHashName(size_t handle, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_NewSeedFromComponents(
    char* hashName,
    ulong* components,
    int componentsLen,
    ubyte* hashKey,
    int hashKeyLen,
    size_t* outHandle);
int ITB_GetSeedHashKey(size_t handle, ubyte* outBuf, size_t capBytes, size_t* outLen);
int ITB_GetSeedComponents(size_t handle, ulong* outBuf, int capCount, int* outLen);
int ITB_AttachLockSeed(size_t noiseHandle, size_t lockHandle);

// ----- Low-level Encrypt / Decrypt --------------------------------------

int ITB_Encrypt(
    size_t noiseHandle,
    size_t dataHandle,
    size_t startHandle,
    void* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);
int ITB_Decrypt(
    size_t noiseHandle,
    size_t dataHandle,
    size_t startHandle,
    void* ciphertext,
    size_t ctLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

int ITB_Encrypt3(
    size_t noiseHandle,
    size_t dataHandle1,
    size_t dataHandle2,
    size_t dataHandle3,
    size_t startHandle1,
    size_t startHandle2,
    size_t startHandle3,
    void* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);
int ITB_Decrypt3(
    size_t noiseHandle,
    size_t dataHandle1,
    size_t dataHandle2,
    size_t dataHandle3,
    size_t startHandle1,
    size_t startHandle2,
    size_t startHandle3,
    void* ciphertext,
    size_t ctLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

// ----- MAC surface ------------------------------------------------------

int ITB_MACCount();
int ITB_MACName(int i, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_MACKeySize(int i);
int ITB_MACTagSize(int i);
int ITB_MACMinKeyBytes(int i);
int ITB_NewMAC(char* macName, void* key, size_t keyLen, size_t* outHandle);
int ITB_FreeMAC(size_t handle);

int ITB_EncryptAuth(
    size_t noiseHandle,
    size_t dataHandle,
    size_t startHandle,
    size_t macHandle,
    void* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);
int ITB_DecryptAuth(
    size_t noiseHandle,
    size_t dataHandle,
    size_t startHandle,
    size_t macHandle,
    void* ciphertext,
    size_t ctLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

int ITB_EncryptAuth3(
    size_t noiseHandle,
    size_t dataHandle1,
    size_t dataHandle2,
    size_t dataHandle3,
    size_t startHandle1,
    size_t startHandle2,
    size_t startHandle3,
    size_t macHandle,
    void* plaintext,
    size_t ptLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);
int ITB_DecryptAuth3(
    size_t noiseHandle,
    size_t dataHandle1,
    size_t dataHandle2,
    size_t dataHandle3,
    size_t startHandle1,
    size_t startHandle2,
    size_t startHandle3,
    size_t macHandle,
    void* ciphertext,
    size_t ctLen,
    void* outBuf,
    size_t outCap,
    size_t* outLen);

// ----- Process-global config knobs --------------------------------------

int ITB_SetBitSoup(int mode);
int ITB_GetBitSoup();
int ITB_SetLockSoup(int mode);
int ITB_GetLockSoup();
int ITB_SetMaxWorkers(int n);
int ITB_GetMaxWorkers();
int ITB_SetNonceBits(int n);
int ITB_GetNonceBits();
int ITB_SetBarrierFill(int n);
int ITB_GetBarrierFill();
long ITB_SetMemoryLimit(long limit);
int ITB_SetGCPercent(int pct);

// ----- Easy Mode encryptor surface --------------------------------------

int ITB_Easy_New(char* primitive, int keyBits, char* macName, int mode, size_t* outHandle);
int ITB_Easy_Free(size_t handle);
int ITB_Easy_Encrypt(size_t handle, void* plaintext, size_t ptLen, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Easy_Decrypt(size_t handle, void* ciphertext, size_t ctLen, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Easy_EncryptAuth(size_t handle, void* plaintext, size_t ptLen, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Easy_DecryptAuth(size_t handle, void* ciphertext, size_t ctLen, void* outBuf, size_t outCap, size_t* outLen);

int ITB_Easy_SetNonceBits(size_t handle, int n);
int ITB_Easy_SetBarrierFill(size_t handle, int n);
int ITB_Easy_SetBitSoup(size_t handle, int mode);
int ITB_Easy_SetLockSoup(size_t handle, int mode);
int ITB_Easy_SetLockSeed(size_t handle, int mode);
int ITB_Easy_SetChunkSize(size_t handle, int n);

int ITB_Easy_Primitive(size_t handle, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_Easy_KeyBits(size_t handle, int* outStatus);
int ITB_Easy_Mode(size_t handle, int* outStatus);
int ITB_Easy_MACName(size_t handle, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_Easy_SeedCount(size_t handle, int* outStatus);
int ITB_Easy_SeedComponents(size_t handle, int slot, ulong* outBuf, int capCount, int* outLen);
int ITB_Easy_HasPRFKeys(size_t handle, int* outStatus);
int ITB_Easy_PRFKey(size_t handle, int slot, ubyte* outBuf, size_t capBytes, size_t* outLen);
int ITB_Easy_MACKey(size_t handle, ubyte* outBuf, size_t capBytes, size_t* outLen);
int ITB_Easy_Close(size_t handle);

int ITB_Easy_Export(size_t handle, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Easy_Import(size_t handle, void* blob, size_t blobLen);
int ITB_Easy_PeekConfig(
    void* blob,
    size_t blobLen,
    char* primOut,
    size_t primCap,
    size_t* primLen,
    int* keyBitsOut,
    int* modeOut,
    char* macOut,
    size_t macCap,
    size_t* macLen);
int ITB_Easy_LastMismatchField(char* outBuf, size_t capBytes, size_t* outLen);

int ITB_Easy_NonceBits(size_t handle, int* outStatus);
int ITB_Easy_HeaderSize(size_t handle, int* outStatus);
int ITB_Easy_ParseChunkLen(size_t handle, void* header, size_t headerLen, size_t* outChunkLen);

int ITB_Easy_NewMixed(
    char* primN,
    char* primD,
    char* primS,
    char* primL,
    int keyBits,
    char* macName,
    size_t* outHandle);
int ITB_Easy_NewMixed3(
    char* primN,
    char* primD1,
    char* primD2,
    char* primD3,
    char* primS1,
    char* primS2,
    char* primS3,
    char* primL,
    int keyBits,
    char* macName,
    size_t* outHandle);
int ITB_Easy_PrimitiveAt(size_t handle, int slot, char* outBuf, size_t capBytes, size_t* outLen);
int ITB_Easy_IsMixed(size_t handle, int* outStatus);

// ----- Native Blob surface ----------------------------------------------

int ITB_Blob128_New(size_t* outHandle);
int ITB_Blob256_New(size_t* outHandle);
int ITB_Blob512_New(size_t* outHandle);
int ITB_Blob_Free(size_t handle);
int ITB_Blob_Width(size_t handle, int* outStatus);
int ITB_Blob_Mode(size_t handle, int* outStatus);
int ITB_Blob_SetKey(size_t handle, int slot, void* key, size_t keyLen);
int ITB_Blob_GetKey(size_t handle, int slot, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Blob_SetComponents(size_t handle, int slot, ulong* components, size_t count);
int ITB_Blob_GetComponents(size_t handle, int slot, ulong* outBuf, size_t outCap, size_t* outCount);
int ITB_Blob_SetMACKey(size_t handle, void* key, size_t keyLen);
int ITB_Blob_GetMACKey(size_t handle, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Blob_SetMACName(size_t handle, char* name, size_t nameLen);
int ITB_Blob_GetMACName(size_t handle, char* outBuf, size_t outCap, size_t* outLen);
int ITB_Blob_Export(size_t handle, int optsBitmask, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Blob_Export3(size_t handle, int optsBitmask, void* outBuf, size_t outCap, size_t* outLen);
int ITB_Blob_Import(size_t handle, void* blob, size_t blobLen);
int ITB_Blob_Import3(size_t handle, void* blob, size_t blobLen);

// ----- Streaming AEAD per-chunk surface ----------------------------------
//
// One ABI export per (Single / Triple) × (Encrypt / Decrypt) ×
// (128 / 256 / 512). The encrypt path takes streamID + cumulative
// pixel offset + final_flag in; the decrypt path takes streamID +
// cumulative pixel offset in and writes final_flag_out. Easy Mode
// counterparts route per-chunk dispatch through the encryptor's
// bound config + MAC closure.

int ITB_EncryptStreamAuthenticated128(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_EncryptStreamAuthenticated256(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_EncryptStreamAuthenticated512(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);

int ITB_DecryptStreamAuthenticated128(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);
int ITB_DecryptStreamAuthenticated256(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);
int ITB_DecryptStreamAuthenticated512(
    size_t noiseHandle, size_t dataHandle, size_t startHandle, size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);

int ITB_EncryptStreamAuthenticated3x128(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_EncryptStreamAuthenticated3x256(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_EncryptStreamAuthenticated3x512(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);

int ITB_DecryptStreamAuthenticated3x128(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);
int ITB_DecryptStreamAuthenticated3x256(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);
int ITB_DecryptStreamAuthenticated3x512(
    size_t noiseHandle,
    size_t dataHandle1, size_t dataHandle2, size_t dataHandle3,
    size_t startHandle1, size_t startHandle2, size_t startHandle3,
    size_t macHandle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);

int ITB_Easy_EncryptStreamAuth(
    size_t handle,
    void* plaintext, size_t ptLen,
    ubyte* streamID, ulong cumulativePixelOffset, int finalFlag,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_Easy_DecryptStreamAuth(
    size_t handle,
    void* ciphertext, size_t ctLen,
    ubyte* streamID, ulong cumulativePixelOffset,
    void* outBuf, size_t outCap, size_t* outLen, int* finalFlagOut);

// ----- Format-deniability wrapper surface -------------------------------
//
// 12 entry points binding the Go-side `wrapper` package to the FFI:
// key / nonce introspection (2), Single Message wrap / unwrap (2),
// in-place wrap / unwrap (2), streaming writer init / update / free
// (3), streaming reader init / update / free (3). Wraps an ITB
// ciphertext under one of three outer keystream ciphers — AES-128-CTR,
// ChaCha20 (RFC8439), SipHash-2-4 in CTR mode — for format-deniability.
// See the Go-side `github.com/everanium/itb/wrapper` package for the
// canonical contract. Bindings module: `itb.wrapper`.

int ITB_WrapperKeySize(char* cipherName, size_t* outSize);
int ITB_WrapperNonceSize(char* cipherName, size_t* outSize);

int ITB_Wrap(
    char* cipherName,
    void* key, size_t keyLen,
    void* blob, size_t blobLen,
    void* outBuf, size_t outCap, size_t* outLen);
int ITB_Unwrap(
    char* cipherName,
    void* key, size_t keyLen,
    void* wire, size_t wireLen,
    void* outBuf, size_t outCap, size_t* outLen);

int ITB_WrapInPlace(
    char* cipherName,
    void* key, size_t keyLen,
    void* blob, size_t blobLen,
    void* outNonce, size_t nonceCap);
int ITB_UnwrapInPlace(
    char* cipherName,
    void* key, size_t keyLen,
    void* wire, size_t wireLen);

int ITB_WrapStreamWriter_Init(
    char* cipherName,
    void* key, size_t keyLen,
    void* outNonce, size_t nonceCap,
    size_t* outHandle);
int ITB_WrapStreamWriter_Update(
    size_t handle,
    void* src, size_t srcLen,
    void* dst, size_t dstCap);
int ITB_WrapStreamWriter_Free(size_t handle);

int ITB_UnwrapStreamReader_Init(
    char* cipherName,
    void* key, size_t keyLen,
    void* wireNonce, size_t nonceLen,
    size_t* outHandle);
int ITB_UnwrapStreamReader_Update(
    size_t handle,
    void* src, size_t srcLen,
    void* dst, size_t dstCap);
int ITB_UnwrapStreamReader_Free(size_t handle);
