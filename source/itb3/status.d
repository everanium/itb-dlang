/// Status codes mirrored from the libitb3 C ABI
/// (`cmd/cshared/internal/capi/errors.go`). Numeric values are stable
/// across releases.
module itb3.status;

@safe:
nothrow:
@nogc:
pure:

/// Integer status code returned by every libitb3 entry point. `OK` is
/// the only success value; every other constant indicates a specific
/// class of failure that the caller can match on.
enum Status : int
{
    OK                = 0,
    BadHash           = 1,
    BadKeyBits        = 2,
    BadHandle         = 3,
    BadInput          = 4,
    BufferTooSmall    = 5,
    EncryptFailed     = 6,
    DecryptFailed     = 7,
    SeedWidthMix      = 8,
    BadMAC            = 9,
    MACFailure        = 10,

    BlobMalformedRecipe    = 11,
    RecipePrimitiveUnknown = 12,
    UnknownProfile         = 13,
    Reserved14        = 14,
    Reserved15        = 15,
    Reserved16        = 16,
    Reserved17        = 17,

    BlobModeMismatch  = 19,
    BlobMalformed     = 20,
    BlobVersionTooNew = 21,
    BlobTooManyOpts   = 22,

    StreamTruncated   = 23,
    StreamAfterFinal  = 24,

    TripleClosed      = 25,
    ProfileExists     = 26,

    Internal          = 99,
}

/// Maps a raw FFI return code onto the [Status] enum; unknown codes
/// collapse to [Status.Internal] so callers always hold a named value.
Status statusFromRc(int rc)
{
    switch (rc)
    {
    case 0: .. case 17:
    case 19: .. case 26:
        return cast(Status) rc;
    default:
        return Status.Internal;
    }
}
