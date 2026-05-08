/// ITB seed handle.
///
/// Provides a thin RAII wrapper over `ITB_NewSeed` / `ITB_FreeSeed`
/// plus the introspection accessors (`width`, `hashName`, `hashKey`,
/// `components`) and the deterministic-rebuild path
/// `Seed.fromComponents`.
///
/// Lifecycle. The struct is non-copyable (`@disable this(this);`) so
/// each `Seed` has a unique owner. The destructor calls
/// `ITB_FreeSeed` at scope exit. To pass a seed across function
/// boundaries without releasing the handle, take it by `ref` (the
/// canonical borrow idiom in D — the callee observes the seed without
/// taking ownership). To transfer ownership, use
/// `std.algorithm.mutation.move`.
///
/// Concurrency. A `Seed` handle is safe to share across threads only
/// when the threads cooperate to ensure the destructor does not run
/// while another thread holds a `ref` — D does not statically enforce
/// borrow lifetimes. The libitb FFI layer itself is thread-safe.
module itb.seed;

import std.string : toStringz;

import itb.errors : check, ITBError, raiseFor, readBytes, readString;
import itb.status : Status;
import itb.sys;

/// A handle to one ITB seed.
///
/// Construct via the regular constructor for a CSPRNG-keyed seed or
/// via [`Seed.fromComponents`] for a deterministic rebuild from
/// caller-supplied uint64 components and an optional fixed hash key.
///
/// All three seeds passed to `encrypt` / `decrypt` must share the
/// same hash name (or at least the same native hash width); mixing
/// widths surfaces as `ITBError` with `Status.SeedWidthMix`.
struct Seed
{
    private size_t _handle;
    private string _hashName;

    @disable this(this);

    /// Constructs a fresh seed with CSPRNG-generated keying material.
    ///
    /// `hashName` is a canonical hash name from `listHashes` (e.g.
    /// `"blake3"`, `"areion256"`). `keyBits` is the ITB key width in
    /// bits — 512, 1024, or 2048 (multiple of 64).
    this(string hashName, int keyBits) @trusted
    {
        size_t handle = 0;
        const(char)* cname = toStringz(hashName);
        int rc = ITB_NewSeed(cast(char*) cname, keyBits, &handle);
        check(rc);
        this._handle = handle;
        this._hashName = hashName;
    }

    /// Builds a seed deterministically from caller-supplied uint64
    /// components and an optional fixed hash key. Use this on the
    /// persistence-restore path (encrypt today, decrypt tomorrow);
    /// pass an empty `hashKey` to request a CSPRNG-generated key
    /// (still useful when only the components need to be
    /// deterministic).
    ///
    /// `components` length must be 8..=32 (multiple of 8).
    /// `hashKey` length, when non-empty, must match the primitive's
    /// native fixed-key size: 16 (`aescmac`), 32 (`areion256` /
    /// `blake2{s,b256}` / `blake3` / `chacha20`), 64 (`areion512` /
    /// `blake2b512`). Pass an empty slice for `siphash24` (no internal
    /// fixed key).
    static Seed fromComponents(
        string hashName,
        const(ulong)[] components,
        const(ubyte)[] hashKey) @trusted
    {
        if (components.length > int.max)
            throw new ITBError(Status.BadInput, "components length exceeds int.max");
        if (hashKey.length > int.max)
            throw new ITBError(Status.BadInput, "hashKey length exceeds int.max");

        size_t handle = 0;
        const(char)* cname = toStringz(hashName);
        ulong* compsPtr = components.length == 0 ? null : cast(ulong*) components.ptr;
        ubyte* keyPtr = hashKey.length == 0 ? null : cast(ubyte*) hashKey.ptr;
        int rc = ITB_NewSeedFromComponents(
            cast(char*) cname,
            compsPtr,
            cast(int) components.length,
            keyPtr,
            cast(int) hashKey.length,
            &handle);
        check(rc);

        Seed s;
        s._handle = handle;
        s._hashName = hashName;
        return s;
    }

    /// Destructor — releases the underlying libitb handle if held.
    /// Idempotent; errors are swallowed (no path to surface them from
    /// a destructor).
    ~this() @trusted
    {
        if (_handle != 0)
        {
            cast(void) ITB_FreeSeed(_handle);
            _handle = 0;
        }
    }

    /// Returns the raw libitb handle (an opaque uintptr_t token).
    /// Used by the low-level `encrypt` / `decrypt` free functions and
    /// by [`attachLockSeed`].
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// Returns the canonical hash name this seed was constructed with.
    string hashName() const @safe @nogc nothrow pure
    {
        return _hashName;
    }

    /// Returns the seed's native hash width in bits (128 / 256 / 512).
    int width() const @trusted
    {
        int st = 0;
        int w = ITB_SeedWidth(_handle, &st);
        check(st);
        return w;
    }

    /// Returns the fixed key the underlying hash closure is bound to
    /// (16 / 32 / 64 bytes depending on the primitive). Save these
    /// bytes alongside [`components`] for cross-process persistence —
    /// the pair fully reconstructs the seed via [`fromComponents`].
    ///
    /// `siphash24` returns an empty slice since SipHash-2-4 has no
    /// internal fixed key (its keying material is the seed components
    /// themselves).
    ubyte[] hashKey() const @trusted
    {
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_GetSeedHashKey(h, buf, cap, outLen));
    }

    /// Returns the seed's underlying uint64 components (8..=32
    /// elements). Save these alongside [`hashKey`] for cross-process
    /// persistence — the pair fully reconstructs the seed via
    /// [`fromComponents`].
    ulong[] components() const @trusted
    {
        int outLen = 0;
        int rc = ITB_GetSeedComponents(_handle, null, 0, &outLen);
        if (rc != Status.BufferTooSmall)
        {
            // libitb's GetSeedComponents probe always reports
            // BUFFER_TOO_SMALL when capCount = 0 and outLen > 0, since
            // there is always at least one component to write. Anything
            // else is a real error.
            raiseFor(rc);
        }
        auto buf = new ulong[outLen];
        rc = ITB_GetSeedComponents(_handle, buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }

    /// Returns the canonical hash name reported by libitb (round-trip
    /// of the constructor argument). Equivalent to [`hashName`] for
    /// seeds constructed through this binding; the introspection path
    /// queries libitb directly rather than returning the cached field.
    string hashNameIntrospect() const @trusted
    {
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_SeedHashName(h, buf, cap, outLen));
    }

    /// Wires a dedicated lockSeed onto this noise seed. The per-chunk
    /// PRF closure for the bit-permutation overlay captures BOTH the
    /// lockSeed's components AND its hash function — keying-material
    /// isolation plus algorithm diversity (the lockSeed primitive may
    /// legitimately differ from the noise-seed primitive within the
    /// same native hash width) for defence-in-depth on the overlay
    /// channel. Both seeds must share the same native hash width.
    ///
    /// The dedicated lockSeed has no observable effect on the wire
    /// output unless the bit-permutation overlay is engaged via
    /// `setBitSoup(1)` or `setLockSoup(1)` before the first encrypt /
    /// decrypt call. The Go-side build-PRF guard panics on encrypt-
    /// time when an attach is present without either flag, surfacing
    /// as `ITBError`.
    ///
    /// Misuse paths surface as `ITBError` with `Status.BadInput`:
    /// self-attach (passing the same seed twice), component-array
    /// aliasing (two distinct Seed handles whose components share the
    /// same backing array — only reachable via raw FFI), and
    /// post-encrypt switching (calling `attachLockSeed` on a noise
    /// seed that has already produced ciphertext). Width mismatch
    /// surfaces as `ITBError` with `Status.SeedWidthMix`.
    ///
    /// The dedicated lockSeed remains owned by the caller — attach
    /// only records the pointer on the noise seed, so keep the
    /// lockSeed alive for the lifetime of the noise seed (do not let
    /// the lockSeed go out of scope before encrypt finishes).
    void attachLockSeed(ref const Seed lockSeed) @trusted
    {
        int rc = ITB_AttachLockSeed(_handle, lockSeed._handle);
        check(rc);
    }
}
