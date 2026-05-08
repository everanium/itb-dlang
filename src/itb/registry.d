/// Registry, library configuration, and stream-header helpers.
///
/// Exposes the libitb free-function surface that is not tied to a
/// specific seed / MAC / encryptor instance: hash + MAC catalogs,
/// `version()`, the global `set` / `get` knobs, and the
/// `parseChunkLen` helper used by streaming consumers.
///
/// All free functions in this module operate on libitb's process-wide
/// state. Concurrent invocation across threads is safe at the FFI
/// layer (libitb internals serialise where needed) but the toggles
/// themselves describe global behaviour that affects every active
/// encryptor — applications that mutate them under load must
/// coordinate themselves.
module itb.registry;

import itb.errors : check, ITBError, readString;
import itb.status : Status;
import itb.sys;

/// Returns the libitb library version string (e.g. `"0.5.4"`).
string version_() @trusted
{
    return readString((char* outBuf, size_t cap, size_t* outLen) =>
        ITB_Version(outBuf, cap, outLen));
}

/// One row of the hash registry: primitive name and native key width
/// in bits.
struct HashInfo
{
    string name;
    int widthBits;
}

/// Returns the list of PRF-grade hashes libitb knows about, in
/// canonical FFI order: `areion256`, `areion512`, `siphash24`,
/// `aescmac`, `blake2b256`, `blake2b512`, `blake2s`, `blake3`,
/// `chacha20`. The below-spec lab primitives `crc128` / `fnv1a` /
/// `md5` are not exposed through this surface and never appear here.
HashInfo[] listHashes() @trusted
{
    int n = ITB_HashCount();
    HashInfo[] out_ = new HashInfo[n];
    foreach (i; 0 .. n)
    {
        out_[i].name = readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_HashName(i, buf, cap, outLen));
        out_[i].widthBits = ITB_HashWidth(i);
    }
    return out_;
}

/// One row of the MAC registry: name, key size in bytes, tag size in
/// bytes, minimum required key bytes for the underlying primitive.
struct MACInfo
{
    string name;
    int keySize;
    int tagSize;
    int minKeyBytes;
}

/// Returns the list of MACs libitb knows about, in canonical FFI
/// order: `kmac256`, `hmac-sha256`, `hmac-blake3`.
MACInfo[] listMACs() @trusted
{
    int n = ITB_MACCount();
    MACInfo[] out_ = new MACInfo[n];
    foreach (i; 0 .. n)
    {
        out_[i].name = readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_MACName(i, buf, cap, outLen));
        out_[i].keySize = ITB_MACKeySize(i);
        out_[i].tagSize = ITB_MACTagSize(i);
        out_[i].minKeyBytes = ITB_MACMinKeyBytes(i);
    }
    return out_;
}

/// Returns the maximum supported ITB key width in bits (typically
/// 1024 for the shipping primitives).
int maxKeyBits() @trusted @nogc nothrow
{
    return ITB_MaxKeyBits();
}

/// Returns the number of native channel slots (typically 7 for the
/// 128 / 256 / 512-bit shipping primitives).
int channels() @trusted @nogc nothrow
{
    return ITB_Channels();
}

/// Returns the current ciphertext-chunk header size in bytes
/// (nonce + width(2) + height(2)). Tracks the active `setNonceBits`
/// configuration: 20 by default, 36 under `setNonceBits(256)`,
/// 68 under `setNonceBits(512)`. Used by streaming consumers to know
/// how many bytes to read from disk / wire before calling
/// `parseChunkLen` on each chunk.
int headerSize() @trusted @nogc nothrow
{
    return ITB_HeaderSize();
}

/// Inspects a chunk header (the fixed-size
/// `[nonce || width(2) || height(2)]` prefix at the start of a
/// ciphertext chunk) and returns the total chunk length on the wire.
///
/// The buffer must contain at least `headerSize()` bytes; only the
/// header is consulted, the body bytes do not need to be present.
/// Throws `ITBError` on too-short buffer, zero dimensions, or
/// overflow.
size_t parseChunkLen(const(ubyte)[] header) @trusted
{
    size_t out_ = 0;
    int rc = ITB_ParseChunkLen(cast(void*) header.ptr, header.length, &out_);
    check(rc);
    return out_;
}

// ----- Global toggles --------------------------------------------------

/// Enables (`mode = 1`) or disables (`mode = 0`) bit-soup mode
/// process-wide. Independent of lock-soup at the setter level — the
/// cascade direction is `setLockSoup(1) → setBitSoup(1)`, not the
/// reverse. In Single Ouroboros, either flag alone activates the
/// bit-permutation overlay at dispatch time. Throws `ITBError` on
/// invalid mode.
void setBitSoup(int mode) @trusted
{
    check(ITB_SetBitSoup(mode));
}

int getBitSoup() @trusted @nogc nothrow
{
    return ITB_GetBitSoup();
}

/// Enables (`mode = 1`) or disables (`mode = 0`) lock-soup mode
/// process-wide. Auto-couples bit-soup on the on-direction.
void setLockSoup(int mode) @trusted
{
    check(ITB_SetLockSoup(mode));
}

int getLockSoup() @trusted @nogc nothrow
{
    return ITB_GetLockSoup();
}

/// Sets the worker-pool cap for parallelised cipher operations. `n` of
/// 0 lets libitb pick (one worker per logical CPU); positive `n`
/// caps at that count.
void setMaxWorkers(int n) @trusted
{
    check(ITB_SetMaxWorkers(n));
}

int getMaxWorkers() @trusted @nogc nothrow
{
    return ITB_GetMaxWorkers();
}

/// Sets the nonce width for new encryptors. Accepts 128, 256, or 512.
/// Other values raise `ITBError` with status `Status.BadInput`.
void setNonceBits(int n) @trusted
{
    check(ITB_SetNonceBits(n));
}

int getNonceBits() @trusted @nogc nothrow
{
    return ITB_GetNonceBits();
}

/// Sets the barrier-fill factor. Accepts 1, 2, 4, 8, 16, 32. Other
/// values raise `ITBError` with status `Status.BadInput`.
void setBarrierFill(int n) @trusted
{
    check(ITB_SetBarrierFill(n));
}

int getBarrierFill() @trusted @nogc nothrow
{
    return ITB_GetBarrierFill();
}
