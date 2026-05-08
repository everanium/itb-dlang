/// Native-Blob wrapper over the libitb C ABI.
///
/// Provides the `Blob128` / `Blob256` / `Blob512` width-specific
/// containers that pack the low-level encryptor material (per-seed
/// hash key + components + optional dedicated lockSeed + optional MAC
/// key + name) plus the captured process-wide configuration into one
/// self-describing JSON blob. Intended for the low-level encrypt /
/// decrypt path where each seed slot may carry a different primitive —
/// the high-level [`itb.encryptor.Encryptor`] wraps a narrower
/// one-primitive-per-encryptor surface.
///
/// Quick start (sender, Single Ouroboros + Areion-SoEM-512 + KMAC256):
///
/// ---
/// import itb;
///
/// ubyte[32] macKey = 0x11;
/// auto ns = Seed("areion512", 2048);
/// auto ds = Seed("areion512", 2048);
/// auto ss = Seed("areion512", 2048);
/// auto mac = MAC("kmac256", macKey[]);
/// auto ct = encryptAuth(ns, ds, ss, mac, plaintext);
/// auto b = Blob512();
/// b.setKey(BlobSlot.N, ns.hashKey());
/// b.setComponents(BlobSlot.N, ns.components());
/// b.setKey(BlobSlot.D, ds.hashKey());
/// b.setComponents(BlobSlot.D, ds.components());
/// b.setKey(BlobSlot.S, ss.hashKey());
/// b.setComponents(BlobSlot.S, ss.components());
/// b.setMACKey(macKey[]);
/// b.setMACName("kmac256");
/// auto blobBytes = b.exportToBytes(BlobOpt.MAC);
/// // ... persist blobBytes ...
/// ---
///
/// Receiver:
///
/// ---
/// auto b2 = Blob512();
/// b2.importFromBytes(blobBytes);
/// auto comps = b2.getComponents(BlobSlot.N);
/// auto key = b2.getKey(BlobSlot.N);
/// auto ns2 = Seed.fromComponents("areion512", comps, key);
/// // ... wire ds, ss the same way; rebuild MAC; decryptAuth ...
/// ---
///
/// The blob is mode-discriminated: [`exportToBytes`] packs Single
/// material, [`exportTriple`] packs Triple material;
/// [`importFromBytes`] and [`importTriple`] are the corresponding
/// receivers. A blob built under one mode rejects the wrong importer
/// with `ITBBlobModeMismatchError`.
///
/// Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
/// into the blob at export time and applied process-wide on import via
/// the existing [`itb.registry.setNonceBits`] /
/// [`itb.registry.setBarrierFill`] / [`itb.registry.setBitSoup`] /
/// [`itb.registry.setLockSoup`] setters. The worker count and the
/// global LockSeed flag are not serialised — the former is a deployment
/// knob, the latter is irrelevant on the native path which consults
/// [`itb.seed.Seed.attachLockSeed`] directly.
module itb.blob;

import std.string : toStringz;

import itb.errors : check, ITBError, raiseFor, readBytes, readString;
import itb.status : Status;
import itb.sys;

// --------------------------------------------------------------------
// Slot identifiers — must mirror the BlobSlot* constants in
// cmd/cshared/internal/capi/blob_handles.go.
// --------------------------------------------------------------------

/// Typed enumeration of the blob slot identifiers. The numeric values
/// match the Go-side `BlobSlot*` constants in
/// `cmd/cshared/internal/capi/blob_handles.go` bit-identically: `N = 0`,
/// `D = 1`, `S = 2`, `L = 3`, `D1..D3 = 4..6`, `S1..S3 = 7..9`. The
/// enum is implicitly convertible to `int` for the FFI call sites.
enum BlobSlot : int
{
    /// Noise seed (Single Ouroboros).
    N = 0,
    /// Data seed (Single Ouroboros).
    D = 1,
    /// Start seed (Single Ouroboros).
    S = 2,
    /// Dedicated lockSeed.
    L = 3,
    /// Triple Ouroboros — data seed 1.
    D1 = 4,
    /// Triple Ouroboros — data seed 2.
    D2 = 5,
    /// Triple Ouroboros — data seed 3.
    D3 = 6,
    /// Triple Ouroboros — start seed 1.
    S1 = 7,
    /// Triple Ouroboros — start seed 2.
    S2 = 8,
    /// Triple Ouroboros — start seed 3.
    S3 = 9,
}

// --------------------------------------------------------------------
// Export option bitmask — must mirror BlobOpt* in blob_handles.go.
// --------------------------------------------------------------------

/// Export option bitmask. Combine via the bitwise-or operator: e.g.
/// `BlobOpt.LockSeed | BlobOpt.MAC`. The values match the Go-side
/// `BlobOpt*` constants in
/// `cmd/cshared/internal/capi/blob_handles.go` bit-identically.
///
/// `LockSeed` opts the `l` slot's KeyL + components into the exported
/// blob. `MAC` opts the MAC key + name. Both must be non-empty on the
/// handle for the corresponding section to be emitted.
enum BlobOpt : int
{
    /// Default — no optional sections emitted.
    None = 0,
    /// Emit the `l` slot's lockSeed material (KeyL + components).
    LockSeed = 1,
    /// Emit the MAC key + name. Both must be non-empty on the handle.
    MAC = 2,
    /// Convenience alias for `LockSeed | MAC`.
    All = 3,
}

/// Resolves a slot identifier from a case-insensitive string name —
/// `"n"`, `"d"`, `"s"`, `"l"`, `"d1"`..`"d3"`, `"s1"`..`"s3"`. Throws
/// `ITBError` with `Status.BadInput` for any other input.
BlobSlot slotFromName(string name) @trusted
{
    import std.string : toLower;

    string lower = name.toLower;
    switch (lower)
    {
        case "n":  return BlobSlot.N;
        case "d":  return BlobSlot.D;
        case "s":  return BlobSlot.S;
        case "l":  return BlobSlot.L;
        case "d1": return BlobSlot.D1;
        case "d2": return BlobSlot.D2;
        case "d3": return BlobSlot.D3;
        case "s1": return BlobSlot.S1;
        case "s2": return BlobSlot.S2;
        case "s3": return BlobSlot.S3;
        default:
            throw new ITBError(Status.BadInput,
                "unknown blob slot name: " ~ name);
    }
}

// --------------------------------------------------------------------
// Width-typed wrapper structs — Blob128, Blob256, Blob512.
// --------------------------------------------------------------------

/// 128-bit width Blob — covers `siphash24` and `aescmac` primitives.
/// Hash key length is variable: empty for siphash24 (no internal fixed
/// key), 16 bytes for aescmac. The 128-bit width is reserved for
/// testing and below-spec stress controls; for production traffic
/// prefer [`Blob256`] or [`Blob512`].
struct Blob128
{
    mixin BlobImpl!128;
}

/// 256-bit width Blob — covers `areion256`, `blake2s`, `blake2b256`,
/// `blake3`, `chacha20`. Hash key length is fixed at 32 bytes.
struct Blob256
{
    mixin BlobImpl!256;
}

/// 512-bit width Blob — covers `areion512` (via the SoEM-512
/// construction) and `blake2b512`. Hash key length is fixed at 64
/// bytes.
struct Blob512
{
    mixin BlobImpl!512;
}

// --------------------------------------------------------------------
// Shared method body — instantiated once per width-typed struct.
// --------------------------------------------------------------------

// Rationale for the mixin-template choice. The three width-typed
// wrappers (`Blob128` / `Blob256` / `Blob512`) share 13 methods with
// bodies that differ only in the constructor's choice of
// `ITB_Blob{128,256,512}_New`. Inlining the bodies into three separate
// struct definitions would duplicate ~250 LOC of FFI wiring per width;
// a single mixin template instantiated three times keeps the surface
// strictly one-source-of-truth. The `static if (Width == 128/256/512)`
// arms in `opCall` switch to the matching libitb constructor; every
// other method body is width-agnostic.
private mixin template BlobImpl(int Width)
{
    private size_t _handle;

    @disable this(this);

    /// Constructs a fresh Blob handle of the matching width.
    static typeof(this) opCall() @trusted
    {
        size_t handle = 0;
        int rc;
        static if (Width == 128)
            rc = ITB_Blob128_New(&handle);
        else static if (Width == 256)
            rc = ITB_Blob256_New(&handle);
        else static if (Width == 512)
            rc = ITB_Blob512_New(&handle);
        else
            static assert(false, "unsupported Blob width");
        check(rc);
        typeof(this) b;
        b._handle = handle;
        return b;
    }

    /// Destructor — releases the underlying libitb handle if held.
    /// Idempotent; errors are swallowed (no path to surface them from
    /// a destructor).
    ~this() @trusted
    {
        if (_handle != 0)
        {
            cast(void) ITB_Blob_Free(_handle);
            _handle = 0;
        }
    }

    /// Returns the raw libitb handle (an opaque uintptr_t token). Used
    /// for diagnostics; consumers should not rely on its numerical
    /// value.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// Returns the native hash width — 128, 256, or 512. Pinned at
    /// construction time and stable for the lifetime of the handle.
    int width() const @trusted
    {
        int st = 0;
        int w = ITB_Blob_Width(_handle, &st);
        check(st);
        return w;
    }

    /// Returns the blob mode field — `0` = unset (freshly constructed
    /// handle), `1` = Single Ouroboros, `3` = Triple Ouroboros. Updated
    /// by [`importFromBytes`] / [`importTriple`] from the parsed blob's
    /// mode discriminator.
    int mode() const @trusted
    {
        int st = 0;
        int m = ITB_Blob_Mode(_handle, &st);
        check(st);
        return m;
    }

    /// Stores the hash key bytes for the given slot. The 256 / 512
    /// widths require exactly 32 / 64 bytes; the 128 width accepts
    /// variable lengths (empty for siphash24 — no internal fixed key —
    /// or 16 bytes for aescmac).
    void setKey(BlobSlot slot, const(ubyte)[] key) @trusted
    {
        void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
        int rc = ITB_Blob_SetKey(_handle, cast(int) slot, keyPtr, key.length);
        check(rc);
    }

    /// Returns a fresh copy of the hash key bytes from the given slot.
    /// Returns an empty slice for an unset slot or siphash24's
    /// no-internal-key path (callers distinguish by `length == 0` and
    /// the slot they queried).
    ubyte[] getKey(BlobSlot slot) const @trusted
    {
        size_t h = _handle;
        int s = cast(int) slot;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Blob_GetKey(h, s, cast(void*) buf, cap, outLen));
    }

    /// Stores the seed components (slice of unsigned 64-bit integers)
    /// for the given slot. Component count must satisfy the
    /// 8..MaxKeyBits/64 multiple-of-8 invariants — same rules as
    /// [`itb.seed.Seed.fromComponents`]. Validation is deferred to
    /// [`exportToBytes`] / [`importFromBytes`] time.
    void setComponents(BlobSlot slot, const(ulong)[] comps) @trusted
    {
        ulong* compsPtr = comps.length == 0 ? null : cast(ulong*) comps.ptr;
        int rc = ITB_Blob_SetComponents(_handle, cast(int) slot, compsPtr, comps.length);
        check(rc);
    }

    /// Returns the seed components stored at the given slot. Returns
    /// an empty slice for an unset slot.
    ulong[] getComponents(BlobSlot slot) const @trusted
    {
        size_t h = _handle;
        int s = cast(int) slot;
        size_t outCount = 0;
        int rc = ITB_Blob_GetComponents(h, s, null, 0, &outCount);
        if (rc != Status.OK && rc != Status.BufferTooSmall)
            raiseFor(rc);
        if (outCount == 0)
            return [];
        ulong[] buf = new ulong[outCount];
        rc = ITB_Blob_GetComponents(h, s, buf.ptr, outCount, &outCount);
        check(rc);
        return buf[0 .. outCount];
    }

    /// Stores the optional MAC key bytes. Pass an empty slice to clear
    /// a previously-set key. The MAC section is only emitted by
    /// [`exportToBytes`] / [`exportTriple`] when `BlobOpt.MAC` is in
    /// the opts mask AND the MAC key on the handle is non-empty.
    void setMACKey(const(ubyte)[] key) @trusted
    {
        void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
        int rc = ITB_Blob_SetMACKey(_handle, keyPtr, key.length);
        check(rc);
    }

    /// Returns a fresh copy of the MAC key bytes from the handle, or
    /// an empty slice if no MAC is associated.
    ubyte[] getMACKey() const @trusted
    {
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Blob_GetMACKey(h, cast(void*) buf, cap, outLen));
    }

    /// Stores the optional MAC name on the handle (e.g. `"kmac256"`,
    /// `"hmac-blake3"`). Pass an empty string to clear a previously-set
    /// name.
    void setMACName(string name) @trusted
    {
        if (name.length == 0)
        {
            int rc = ITB_Blob_SetMACName(_handle, null, 0);
            check(rc);
            return;
        }
        const(char)* cname = toStringz(name);
        int rc = ITB_Blob_SetMACName(_handle, cast(char*) cname, name.length);
        check(rc);
    }

    /// Returns the MAC name from the handle, or an empty string if no
    /// MAC is associated. The trailing NUL libitb counts in the output
    /// length is stripped uniformly so the returned D string never
    /// carries the C-side terminator.
    string getMACName() const @trusted
    {
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Blob_GetMACName(h, buf, cap, outLen));
    }

    /// Serialises the handle's Single-Ouroboros state into a JSON blob.
    /// `opts` is a bitmask of [`BlobOpt`] flags: `LockSeed` opts the
    /// `l` slot's KeyL + components into the blob; `MAC` opts the MAC
    /// key + name (both must be non-empty on the handle).
    ubyte[] exportToBytes(BlobOpt opts = BlobOpt.None) const @trusted
    {
        return exportImpl(cast(int) opts, false);
    }

    /// Serialises the handle's Triple-Ouroboros state into a JSON blob.
    /// See [`exportToBytes`] for the `opts` flag semantics.
    ubyte[] exportTriple(BlobOpt opts = BlobOpt.None) const @trusted
    {
        return exportImpl(cast(int) opts, true);
    }

    /// Parses a Single-Ouroboros JSON blob, populates the handle's
    /// slots, and applies the captured globals via the process-wide
    /// setters.
    ///
    /// Throws `ITBBlobModeMismatchError` when the blob is Triple-mode,
    /// `ITBBlobMalformedError` on parse / shape failure,
    /// `ITBBlobVersionTooNewError` on a version field higher than this
    /// build supports.
    void importFromBytes(const(ubyte)[] blob) @trusted
    {
        void* inPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
        int rc = ITB_Blob_Import(_handle, inPtr, blob.length);
        check(rc);
    }

    /// Triple-Ouroboros counterpart of [`importFromBytes`]. Same error
    /// contract.
    void importTriple(const(ubyte)[] blob) @trusted
    {
        void* inPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
        int rc = ITB_Blob_Import3(_handle, inPtr, blob.length);
        check(rc);
    }

    // ----- Internals --------------------------------------------------

    private ubyte[] exportImpl(int opts, bool triple) const @trusted
    {
        size_t outLen = 0;
        int rc;
        if (triple)
            rc = ITB_Blob_Export3(_handle, opts, null, 0, &outLen);
        else
            rc = ITB_Blob_Export(_handle, opts, null, 0, &outLen);
        if (rc != Status.OK && rc != Status.BufferTooSmall)
            raiseFor(rc);
        if (outLen == 0)
            return [];
        ubyte[] buf = new ubyte[outLen];
        if (triple)
            rc = ITB_Blob_Export3(_handle, opts, cast(void*) buf.ptr, outLen, &outLen);
        else
            rc = ITB_Blob_Export(_handle, opts, cast(void*) buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }
}
