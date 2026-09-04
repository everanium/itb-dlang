/// Status codes mirrored from the libitb C ABI
/// (`cmd/cshared/internal/capi/errors.go`). Numeric values are stable
/// across releases.
module itb.status;

@safe:
nothrow:
@nogc:
pure:

/// Integer status code returned by every libitb entry point. `OK` is
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

/// Short human-readable label for a status code.
string statusLabel(Status st)
{
    final switch (st)
    {
    case Status.OK:                return "ok";
    case Status.BadHash:           return "unknown hash name";
    case Status.BadKeyBits:        return "invalid key bits";
    case Status.BadHandle:         return "invalid handle";
    case Status.BadInput:          return "invalid input";
    case Status.BufferTooSmall:    return "output buffer too small";
    case Status.EncryptFailed:     return "encrypt failed";
    case Status.DecryptFailed:     return "decrypt failed";
    case Status.SeedWidthMix:      return "seed width mismatch";
    case Status.BadMAC:            return "unknown MAC name or invalid MAC handle";
    case Status.MACFailure:        return "MAC verification failed";
    case Status.BlobMalformedRecipe:    return "blob recipe malformed";
    case Status.RecipePrimitiveUnknown: return "blob recipe names an unknown primitive";
    case Status.UnknownProfile:         return "unknown profile name";
    case Status.Reserved14:
    case Status.Reserved15:
    case Status.Reserved16:
    case Status.Reserved17:        return "reserved status";
    case Status.BlobModeMismatch:  return "blob mode mismatch";
    case Status.BlobMalformed:     return "malformed state blob";
    case Status.BlobVersionTooNew: return "blob version too new";
    case Status.BlobTooManyOpts:   return "too many blob export opts";
    case Status.StreamTruncated:   return "stream truncated before terminator";
    case Status.StreamAfterFinal:  return "stream chunk after terminator";
    case Status.TripleClosed:      return "Triple Pipeline is closed";
    case Status.ProfileExists:     return "profile name already registered";
    case Status.Internal:          return "internal error";
    }
}
