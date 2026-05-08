/// Named numeric constants for every libitb status code.
///
/// Source-of-truth for the codes is cmd/cshared/internal/capi/errors.go;
/// the constants here mirror it bit-identically so tests / callers can
/// match against named values rather than magic numbers.
///
/// Codes 0..10 cover the low-level Seed / Encrypt / Decrypt / MAC
/// surface. Codes 11..18 are reserved for the Easy Mode encryptor
/// (itb.encryptor). Codes 19..22 are reserved for the native Blob
/// surface (itb.blob). Code 99 is a generic "internal" sentinel for
/// paths the caller cannot recover from at the binding layer.
///
/// Usage. The status codes are scoped under the `Status` named enum
/// so callers write `Status.OK`, `Status.EasyMismatch`, etc. rather
/// than relying on bare top-level identifiers (which would clash with
/// every typical `OK` / `Internal` symbol elsewhere).
module itb.status;

@safe:
@nogc:
nothrow:
pure:

/// libitb status code returned by every FFI entry point. `OK` is the
/// only success value; every other constant indicates a specific class
/// of failure that the caller can match on.
enum Status : int
{
    OK                       = 0,
    BadHash                  = 1,
    BadKeyBits               = 2,
    BadHandle                = 3,
    BadInput                 = 4,
    BufferTooSmall           = 5,
    EncryptFailed            = 6,
    DecryptFailed            = 7,
    SeedWidthMix             = 8,
    BadMAC                   = 9,
    MACFailure               = 10,

    EasyClosed               = 11,
    EasyMalformed            = 12,
    EasyVersionTooNew        = 13,
    EasyUnknownPrimitive     = 14,
    EasyUnknownMAC           = 15,
    EasyBadKeyBits           = 16,
    EasyMismatch             = 17,
    EasyLockSeedAfterEncrypt = 18,

    BlobModeMismatch         = 19,
    BlobMalformed            = 20,
    BlobVersionTooNew        = 21,
    BlobTooManyOpts          = 22,

    /// Streaming AEAD: input exhausted without observing a chunk
    /// whose recovered final_flag is set. Surfaced by the auth-stream
    /// decrypt loop on truncate-tail.
    StreamTruncated          = 23,
    /// Streaming AEAD: extra chunk bytes followed the terminating
    /// chunk. Surfaced by the auth-stream decrypt loop when a
    /// transcript carries data past final_flag = 1.
    StreamAfterFinal         = 24,

    Internal                 = 99,
}
