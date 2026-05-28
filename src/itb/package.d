/// ITB encryption — D language binding over libitb's C ABI.
///
/// The library wraps the C ABI exported by `cmd/cshared`
/// (`libitb.so` / `.dll` / `.dylib`) through `extern (C)` declarations
/// at the binding's `itb.sys` boundary. Linkage is link-time via DUB's
/// `lflags` (no runtime dlopen), with `rpath` baked into produced
/// executables so the loader finds `libitb` next to the binding's
/// directory.
///
/// Quick start:
///
/// ---
/// import itb;
///
/// auto noise = Seed("blake3", 1024);
/// auto data  = Seed("blake3", 1024);
/// auto start = Seed("blake3", 1024);
/// auto ct = encrypt(noise, data, start, cast(const(ubyte)[]) "hello world");
/// auto pt = decrypt(noise, data, start, ct);
/// assert(pt == cast(const(ubyte)[]) "hello world");
/// ---
///
/// Authenticated variants take an additional MAC:
///
/// ---
/// auto mac = MAC("hmac-blake3", new ubyte[32]);
/// auto ct = encryptAuth(noise, data, start, mac, plaintext);
/// auto pt = decryptAuth(noise, data, start, mac, ct);
/// ---
///
/// Hash names match the canonical FFI registry.
/// MAC names: `kmac256`, `hmac-sha256`, `hmac-blake3`.
module itb;

public import itb.status : Status;
public import itb.errors :
    ITBError,
    ITBEasyMismatchError,
    ITBBlobModeMismatchError,
    ITBBlobMalformedError,
    ITBBlobVersionTooNewError,
    ITBStreamTruncatedError,
    ITBStreamAfterFinalError;
public import itb.registry :
    version_,
    listHashes,
    listMACs,
    HashInfo,
    MACInfo,
    maxKeyBits,
    channels,
    headerSize,
    parseChunkLen,
    setBitSoup,
    getBitSoup,
    setLockSoup,
    getLockSoup,
    setLockBatch,
    getLockBatch,
    setMaxWorkers,
    getMaxWorkers,
    setNonceBits,
    getNonceBits,
    setBarrierFill,
    getBarrierFill,
    setMemoryLimit,
    setGcPercent;
public import itb.seed : Seed;
public import itb.mac : MAC;
public import itb.cipher :
    encrypt,
    decrypt,
    encryptTriple,
    decryptTriple,
    encryptAuth,
    decryptAuth,
    encryptAuthTriple,
    decryptAuthTriple;
public import itb.encryptor :
    Encryptor,
    EasyConfig,
    peekConfig,
    lastMismatchField;
public import itb.blob :
    Blob128,
    Blob256,
    Blob512,
    BlobSlot,
    BlobOpt,
    slotFromName;
public import itb.streams :
    StreamEncryptor,
    StreamDecryptor,
    StreamEncryptor3,
    StreamDecryptor3,
    StreamEncryptorAuth,
    StreamDecryptorAuth,
    StreamEncryptorAuth3,
    StreamDecryptorAuth3,
    encryptStream,
    decryptStream,
    encryptStreamTriple,
    decryptStreamTriple,
    encryptStreamAuth,
    decryptStreamAuth,
    encryptStreamAuthTriple,
    decryptStreamAuthTriple,
    DEFAULT_CHUNK_SIZE;
public import itb.wrapper :
    Cipher,
    CIPHER_NAMES,
    ffiName,
    cipherFromName,
    keySize,
    nonceSize,
    wrapperGenerateKey,
    wrapperDeriveKey,
    wrap,
    unwrap,
    wrapInPlace,
    unwrapInPlace,
    WrapStreamWriter,
    UnwrapStreamReader,
    WrapperError,
    WrapperInvalidCipherError,
    WrapperInvalidKeyError,
    WrapperInvalidNonceError,
    WrapperHandleClosedError;
