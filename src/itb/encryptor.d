/// High-level Encryptor wrapper over the libitb C ABI.
///
/// Mirrors the `github.com/everanium/itb/easy` Go sub-package: one
/// constructor call replaces the lower-level seven-line setup ceremony
/// (hash factory, three or seven seeds, MAC closure, container-config
/// wiring) and returns an `Encryptor` value that owns its own
/// per-instance configuration. Two encryptors with different settings
/// can be used in parallel without cross-contamination of the
/// process-wide ITB configuration.
///
/// Quick start (Single Ouroboros + HMAC-BLAKE3):
///
/// ---
/// import itb;
///
/// auto enc = Encryptor("blake3", 1024);
/// auto ct = enc.encryptAuth(cast(const(ubyte)[]) "hello world");
/// auto pt = enc.decryptAuth(ct);
/// assert(pt == cast(const(ubyte)[]) "hello world");
/// ---
///
/// Triple Ouroboros (7 seeds, mode = 3):
///
/// ---
/// auto enc = Encryptor("areion512", 2048, "kmac256", 3);
/// auto ct = enc.encrypt(big);
/// auto pt = enc.decrypt(ct);
/// ---
///
/// Cross-process persistence (encrypt today / decrypt tomorrow):
///
/// ---
/// auto blob = enc.exportState();
/// // ... save blob to disk / KMS / wire ...
/// auto cfg = peekConfig(blob);
/// auto dec = Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);
/// dec.importState(blob);
/// ---
///
/// Streaming. Chunking lives on the binding side (same pattern as the
/// lower-level API): slice the plaintext into chunks of `chunk_size`
/// bytes and call `encrypt` per chunk; on the decrypt side walk the
/// concatenated stream by reading the chunk header, calling
/// `parseChunkLen`, and feeding the chunk to `decrypt`. The
/// encryptor's chunk-size knob (set via `setChunkSize`) is consumed
/// only by the Go-side `EncryptStream` entry point; Single Message
/// `encrypt` honours the container-cap heuristic in `itb.ChunkSize`.
///
/// Output-buffer cache. The cipher methods reuse a per-encryptor
/// `ubyte[]` slice to avoid the per-call allocation cost; the buffer
/// grows on demand and survives between calls. Each cipher call
/// returns a slice over the cache covering the current result, so the
/// cache IS exposed to the caller — call `.dup` to detach the bytes
/// when their lifetime needs to outlast the next cipher call. The
/// cached bytes (the most recent ciphertext or plaintext) sit in heap
/// memory until the next cipher call overwrites them or `close` /
/// `~this` zeroes them. Callers handling sensitive plaintext under a
/// heap-scan threat model should call `close` immediately after the
/// last decrypt rather than relying on destruction-time zeroisation
/// at the end of scope.
///
/// Lifecycle. `Encryptor` is a non-copyable struct; the destructor
/// calls `ITB_Easy_Free` and wipes the output cache best-effort.
/// `close` is the explicit zeroing path (wipes PRF / MAC / seed
/// material on the Go side and wipes the per-instance output cache on
/// the D side); the destructor's `Free` call subsumes `close` on the
/// Go side, so manual `close` is only needed when the working set
/// must be zeroed earlier than scope exit.
module itb.encryptor;

import std.conv : to;
import std.string : toStringz;

import itb.errors : check, ITBError, ITBStreamAfterFinalError,
    ITBStreamTruncatedError, raiseFor, readBytes, readLastMismatchField,
    readString;
import itb.status : Status;
import itb.sys;

/// Parsed metadata returned by `peekConfig`. Carries the
/// `(primitive, keyBits, mode, macName)` quadruple as named fields for
/// readable call sites.
struct EasyConfig
{
    string primitive;
    int keyBits;
    int mode;
    string macName;
}

/// Reads the offending JSON field name from the most recent
/// `ITB_Easy_Import` call that returned `Status.EasyMismatch` on this
/// thread. Empty string when the most recent failure was not a
/// mismatch.
///
/// The `Encryptor.importState` method already attaches this name to
/// the thrown `ITBEasyMismatchError.field`; this free function is
/// exposed for callers that need to read the field independently of
/// the exception path. Module-level alias for
/// `itb.errors.readLastMismatchField`.
string lastMismatchField() @trusted nothrow
{
    return readLastMismatchField();
}

/// Parses a state blob's metadata `(primitive, keyBits, mode,
/// macName)` without performing full validation, allowing a caller to
/// inspect a saved blob before constructing a matching encryptor.
///
/// Returns the four-field `EasyConfig` on success; throws
/// `ITBError(Status.EasyMalformed)` on JSON parse failure / kind
/// mismatch / too-new version / unknown mode value.
EasyConfig peekConfig(const(ubyte)[] blob) @trusted
{
    void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;

    // Probe both string sizes first.
    size_t primLen = 0;
    size_t macLen = 0;
    int kbOut = 0;
    int modeOut = 0;
    int rc = ITB_Easy_PeekConfig(
        blobPtr, blob.length,
        null, 0, &primLen,
        &kbOut, &modeOut,
        null, 0, &macLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
        raiseFor(rc);

    char[] primBuf = primLen == 0 ? null : new char[primLen];
    char[] macBuf = macLen == 0 ? null : new char[macLen];
    rc = ITB_Easy_PeekConfig(
        blobPtr, blob.length,
        primBuf.ptr, primLen, &primLen,
        &kbOut, &modeOut,
        macBuf.ptr, macLen, &macLen);
    check(rc);

    EasyConfig cfg;
    cfg.keyBits = kbOut;
    cfg.mode = modeOut;
    // Strip the trailing NUL libitb counts in the *Len out-params.
    cfg.primitive = primLen <= 1 ? "" : (cast(string) primBuf[0 .. primLen - 1]).idup;
    cfg.macName = macLen <= 1 ? "" : (cast(string) macBuf[0 .. macLen - 1]).idup;
    return cfg;
}

/// High-level Encryptor over the libitb C ABI.
///
/// Construction is the heavy step — generates fresh PRF keys, fresh
/// seed components, and a fresh MAC key from `/dev/urandom`. Reusing
/// one `Encryptor` value across many encrypt / decrypt calls
/// amortises the cost across the lifetime of a session.
///
/// Lifecycle is RAII: the destructor calls `ITB_Easy_Free`
/// best-effort. `close` is the explicit zeroing path that wipes PRF /
/// MAC / seed material on the Go side and wipes the per-instance
/// output cache on the D side.
///
/// Auto-coupling. (1) `setLockSoup(1)` cascades to `setBitSoup(1)` on
/// this encryptor (Lock Soup overlay layers on top of bit soup; the
/// reverse direction does not auto-cascade — `setBitSoup(1)` alone
/// activates the Single dispatcher's keyed bit-permutation path via
/// the OR-gate but leaves `cfg.LockSoup` at 0). (2) `setLockSeed(1)`
/// cascades to both `setLockSoup(1)` and `setBitSoup(1)` and lazily
/// allocates a dedicated lockSeed wired onto the noiseSeed slot.
/// (3) Off-direction coercion while LockSeed active: while
/// `cfg.LockSeed == 1`, `setBitSoup(0)` and `setLockSoup(0)` are
/// silently coerced to 1 to keep the overlay engaged on the
/// dedicated lockSeed channel; drop the lockSeed via `setLockSeed(0)`
/// first to fully disengage. The auto-coupling lives entirely on the
/// Go side; the D forwarder pushes the requested mode and reads back
/// post-cascade values via `bitSoup` / `lockSoup` getters.
///
/// Concurrency. Cipher methods (`encrypt` / `decrypt` / `encryptAuth`
/// / `decryptAuth`) write into the per-instance output-buffer cache
/// and are **not safe** to invoke concurrently against the same
/// encryptor. Sharing one `Encryptor` value across threads requires
/// external synchronisation. Per-instance configuration setters
/// (`setNonceBits` / `setBarrierFill` / `setBitSoup` / `setLockSoup`
/// / `setLockSeed` / `setChunkSize`) and persistence (`exportState`
/// / `importState`) likewise require external synchronisation when
/// invoked against the same encryptor from multiple threads.
/// Distinct `Encryptor` values, each owned by one thread, run
/// independently against the libitb worker pool.
struct Encryptor
{
    private size_t _handle;
    /// Per-encryptor output buffer cache. Grows on demand;
    /// `close` / destructor wipe it before drop.
    private ubyte[] _outCache;
    /// Tracks the closed / freed state independently of the handle
    /// field so the preflight in `_checkOpen` can surface
    /// `Status.EasyClosed` after `close` / destructor without
    /// relying on the libitb-side handle-id lookup (which would
    /// surface `Status.BadHandle` once the destructor has cleared
    /// the handle slot).
    private bool _closed;

    @disable this(this);

    /// Constructs a fresh encryptor.
    ///
    /// `primitive` is a canonical hash name from `listHashes` —
    /// `"areion256"`, `"areion512"`, `"siphash24"`, `"aescmac"`,
    /// `"blake2b256"`, `"blake2b512"`, `"blake2s"`, `"blake3"`,
    /// `"chacha20"`. Empty / `null` selects the libitb default
    /// (`"areion512"`).
    ///
    /// `keyBits` is the ITB key width in bits (512, 1024, 2048;
    /// multiple of the primitive's native hash width). Pass `0` to
    /// select the libitb default (1024).
    ///
    /// `macName` is a canonical MAC name from `listMACs` —
    /// `"kmac256"`, `"hmac-sha256"`, or `"hmac-blake3"`. Both `null`
    /// and the empty string `""` trigger a binding-side override to
    /// `"hmac-blake3"` rather than forwarding NULL through to libitb's
    /// own default (`"kmac256"`); HMAC-BLAKE3 measures the lightest
    /// MAC overhead in the Easy Mode bench surface, so the
    /// constructor-without-MAC path picks the lowest-cost
    /// authenticated MAC by default.
    ///
    /// `mode` is 1 (Single Ouroboros, 3 seeds — noise / data / start)
    /// or 3 (Triple Ouroboros, 7 seeds — noise + 3 pairs of data /
    /// start). Other values throw `ITBError(Status.BadInput)`.
    this(string primitive, int keyBits, string macName = null, int mode = 1) @trusted
    {
        // Binding-side default override: when the caller passes
        // `macName=null` the binding picks `hmac-blake3` rather than
        // forwarding NULL through to libitb's own default.
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* primPtr = (primitive is null) ? null : toStringz(primitive);
        const(char)* macPtr = toStringz(effectiveMac);

        size_t handle = 0;
        int rc = ITB_Easy_New(
            cast(char*) primPtr, keyBits, cast(char*) macPtr, mode, &handle);
        check(rc);
        this._handle = handle;
    }

    // ─── Mixed-mode constructors ──────────────────────────────────────

    /// Constructs a Single-Ouroboros encryptor with per-slot PRF
    /// primitive selection.
    ///
    /// `primN` / `primD` / `primS` cover the noise / data / start
    /// slots; `primL` (default `null`) is the optional dedicated
    /// lockSeed primitive — when provided non-null and non-empty, a
    /// 4th seed slot is allocated under that primitive and BitSoup +
    /// LockSoup are auto-coupled on the on-direction.
    ///
    /// All four primitive names must resolve to the same native hash
    /// width via the libitb registry; mixed widths throw `ITBError`
    /// with the panic message captured in `readLastError`.
    static Encryptor newMixed(
        string primN,
        string primD,
        string primS,
        string primL,
        int keyBits,
        string macName = null) @trusted
    {
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* nPtr = toStringz(primN);
        const(char)* dPtr = toStringz(primD);
        const(char)* sPtr = toStringz(primS);
        const(char)* macPtr = toStringz(effectiveMac);
        const(char)* lPtr = (primL is null || primL.length == 0)
            ? null : toStringz(primL);

        size_t handle = 0;
        int rc = ITB_Easy_NewMixed(
            cast(char*) nPtr,
            cast(char*) dPtr,
            cast(char*) sPtr,
            cast(char*) lPtr,
            keyBits,
            cast(char*) macPtr,
            &handle);
        check(rc);

        Encryptor e;
        e._handle = handle;
        return e;
    }

    /// Triple-Ouroboros counterpart of `Encryptor.newMixed`. Accepts
    /// seven per-slot primitive names (noise + 3 data + 3 start) plus
    /// the optional `primL` lockSeed primitive. See
    /// `Encryptor.newMixed` for the construction contract.
    static Encryptor newMixed3(
        string primN,
        string primD1,
        string primD2,
        string primD3,
        string primS1,
        string primS2,
        string primS3,
        string primL,
        int keyBits,
        string macName = null) @trusted
    {
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* nPtr = toStringz(primN);
        const(char)* d1Ptr = toStringz(primD1);
        const(char)* d2Ptr = toStringz(primD2);
        const(char)* d3Ptr = toStringz(primD3);
        const(char)* s1Ptr = toStringz(primS1);
        const(char)* s2Ptr = toStringz(primS2);
        const(char)* s3Ptr = toStringz(primS3);
        const(char)* macPtr = toStringz(effectiveMac);
        const(char)* lPtr = (primL is null || primL.length == 0)
            ? null : toStringz(primL);

        size_t handle = 0;
        int rc = ITB_Easy_NewMixed3(
            cast(char*) nPtr,
            cast(char*) d1Ptr,
            cast(char*) d2Ptr,
            cast(char*) d3Ptr,
            cast(char*) s1Ptr,
            cast(char*) s2Ptr,
            cast(char*) s3Ptr,
            cast(char*) lPtr,
            keyBits,
            cast(char*) macPtr,
            &handle);
        check(rc);

        Encryptor e;
        e._handle = handle;
        return e;
    }

    /// Destructor — wipes the output cache, then releases the
    /// underlying libitb handle if held. Idempotent; errors are
    /// swallowed (no path to surface them from a destructor).
    ~this() @trusted
    {
        _wipeCache();
        if (_handle != 0)
        {
            cast(void) ITB_Easy_Free(_handle);
            _handle = 0;
        }
        _closed = true;
    }

    // ─── Read-only field accessors ────────────────────────────────────

    /// Opaque libitb handle id (uintptr). Useful for diagnostics and
    /// FFI-level interop; bindings should not rely on its numerical
    /// value.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// Returns the canonical primitive name bound at construction.
    string primitive() @trusted
    {
        _checkOpen();
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_Primitive(h, buf, cap, outLen));
    }

    /// Returns the canonical hash primitive name bound to the given
    /// seed slot index.
    ///
    /// Slot ordering is canonical — 0 = noiseSeed, then
    /// dataSeed{,1..3}, then startSeed{,1..3}, with the optional
    /// dedicated lockSeed at the trailing slot. For single-primitive
    /// encryptors every slot returns the same `primitive` value; for
    /// encryptors built via `newMixed` / `newMixed3` each slot
    /// returns its independently-chosen primitive name.
    string primitiveAt(int slot) @trusted
    {
        _checkOpen();
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_PrimitiveAt(h, slot, buf, cap, outLen));
    }

    /// Returns the ITB key width in bits.
    int keyBits() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_KeyBits(_handle, &st);
        check(st);
        return v;
    }

    /// Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros).
    int mode() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_Mode(_handle, &st);
        check(st);
        return v;
    }

    /// Returns `true` when the encryptor was constructed via
    /// `newMixed` / `newMixed3` (per-slot primitive selection);
    /// `false` for single-primitive encryptors built via the regular
    /// constructor.
    bool isMixed() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_IsMixed(_handle, &st);
        check(st);
        return v != 0;
    }

    /// Returns the canonical MAC name bound at construction.
    string macName() @trusted
    {
        _checkOpen();
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_MACName(h, buf, cap, outLen));
    }

    /// Number of seed slots: 3 (Single without LockSeed),
    /// 4 (Single with LockSeed), 7 (Triple without LockSeed),
    /// 8 (Triple with LockSeed).
    int seedCount() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_SeedCount(_handle, &st);
        check(st);
        return v;
    }

    /// Returns the nonce size in bits configured for this encryptor —
    /// either the value from the most recent `setNonceBits` call, or
    /// the process-wide `getNonceBits` reading at construction time
    /// when no per-instance override has been issued. Reads the live
    /// `cfg.NonceBits` via `ITB_Easy_NonceBits` so a setter call on
    /// the Go side is reflected immediately.
    int nonceBits() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_NonceBits(_handle, &st);
        check(st);
        return v;
    }

    /// Returns the per-instance ciphertext-chunk header size in bytes
    /// (nonce + 2-byte width + 2-byte height).
    ///
    /// Tracks this encryptor's own `nonceBits`, NOT the process-wide
    /// `headerSize` reading — important when the encryptor has called
    /// `setNonceBits` to override the default. Use this when slicing
    /// a chunk header off the front of a ciphertext stream produced
    /// by this encryptor or when sizing a tamper region for an
    /// authenticated-decrypt test.
    int easyHeaderSize() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_HeaderSize(_handle, &st);
        check(st);
        return v;
    }

    /// `true` when the encryptor's primitive uses fixed PRF keys per
    /// seed slot (every shipped primitive except `siphash24`).
    bool hasPRFKeys() @trusted
    {
        _checkOpen();
        int st = 0;
        int v = ITB_Easy_HasPRFKeys(_handle, &st);
        check(st);
        return v != 0;
    }

    /// Per-instance counterpart of `itb.registry.parseChunkLen`.
    /// Inspects a chunk header (the fixed-size
    /// `[nonce(N) || width(2) || height(2)]` prefix where `N` comes
    /// from this encryptor's `nonceBits`) and returns the total chunk
    /// length on the wire.
    ///
    /// Use this when walking a concatenated chunk stream produced by
    /// this encryptor: read `easyHeaderSize` bytes from the wire,
    /// call `enc.parseChunkLen(buf[0 .. enc.easyHeaderSize()])`, read
    /// the remaining `chunkLen - easyHeaderSize` bytes, and feed the
    /// full chunk to `decrypt` / `decryptAuth`.
    ///
    /// The buffer must contain at least `easyHeaderSize` bytes; only
    /// the header is consulted, the body bytes do not need to be
    /// present. Throws `ITBError(Status.BadInput)` on too-short
    /// buffer, zero dimensions, or width × height overflow against
    /// the container pixel cap.
    size_t parseChunkLen(const(ubyte)[] header) @trusted
    {
        _checkOpen();
        void* hdrPtr = header.length == 0 ? null : cast(void*) header.ptr;
        size_t out_ = 0;
        int rc = ITB_Easy_ParseChunkLen(_handle, hdrPtr, header.length, &out_);
        check(rc);
        return out_;
    }

    // ─── Material getters (defensive copies) ──────────────────────────

    /// Returns the uint64 components of one seed slot (defensive
    /// copy).
    ///
    /// Slot index follows the canonical ordering: Single =
    /// `[noise, data, start]`; Triple = `[noise, data1, data2,
    /// data3, start1, start2, start3]`; the dedicated lockSeed slot,
    /// when present, is appended at the trailing index (index 3 for
    /// Single, index 7 for Triple). Bindings can consult `seedCount`
    /// to determine the valid slot range for the active mode +
    /// lockSeed configuration.
    ulong[] seedComponents(int slot) @trusted
    {
        _checkOpen();
        int outLen = 0;
        // Probe call — out=NULL / capCount=0 returns
        // BufferTooSmall with the required size in *outLen.
        // BadInput here would signal an out-of-range slot.
        int rc = ITB_Easy_SeedComponents(_handle, slot, null, 0, &outLen);
        if (rc == Status.OK)
            return [];
        if (rc != Status.BufferTooSmall)
            raiseFor(rc);
        auto buf = new ulong[outLen];
        rc = ITB_Easy_SeedComponents(_handle, slot, buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }

    /// Returns the fixed PRF key bytes for one seed slot (defensive
    /// copy). Throws `ITBError(Status.BadInput)` when the primitive
    /// has no fixed PRF keys (`siphash24` — caller should consult
    /// `hasPRFKeys` first) or when `slot` is out of range.
    ubyte[] prfKey(int slot) @trusted
    {
        _checkOpen();
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_PRFKey(h, slot, buf, cap, outLen));
    }

    /// Returns a defensive copy of the encryptor's bound MAC fixed
    /// key. Save these bytes alongside the seed material for
    /// cross-process restore via `exportState` / `importState`.
    ubyte[] macKey() @trusted
    {
        _checkOpen();
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_MACKey(h, buf, cap, outLen));
    }

    // ─── Cipher entry points ─────────────────────────────────────────

    /// Encrypts `plaintext` using the encryptor's configured primitive
    /// / keyBits / mode and per-instance Config snapshot.
    ///
    /// Plain mode — does not attach a MAC tag; for authenticated
    /// encryption use `encryptAuth`.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] encrypt(const(ubyte)[] plaintext) @trusted
    {
        return _cipherCall(&ITB_Easy_Encrypt, plaintext);
    }

    /// Decrypts ciphertext produced by `encrypt` under the same
    /// encryptor.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] decrypt(const(ubyte)[] ciphertext) @trusted
    {
        return _cipherCall(&ITB_Easy_Decrypt, ciphertext);
    }

    /// Encrypts `plaintext` and attaches a MAC tag using the
    /// encryptor's bound MAC closure.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] encryptAuth(const(ubyte)[] plaintext) @trusted
    {
        return _cipherCall(&ITB_Easy_EncryptAuth, plaintext);
    }

    /// Verifies and decrypts ciphertext produced by `encryptAuth`.
    /// Throws `ITBError(Status.MACFailure)` on tampered ciphertext or
    /// wrong MAC key.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] decryptAuth(const(ubyte)[] ciphertext) @trusted
    {
        return _cipherCall(&ITB_Easy_DecryptAuth, ciphertext);
    }

    /// Reads plaintext from `reader` until EOF, encrypts in chunks of
    /// `chunkSize` under the encryptor's bound config + MAC, and
    /// writes the 32-byte CSPRNG `stream_id` prefix followed by
    /// concatenated authenticated chunks via `writer`.
    ///
    /// Closed-state preflight: throws `ITBError(Status.EasyClosed)`
    /// when the encryptor has been closed / freed.
    void encryptStreamAuth(
        scope size_t delegate(ubyte[]) @trusted reader,
        scope void delegate(const(ubyte)[]) @trusted writer,
        size_t chunkSize) @trusted
    {
        _checkOpen();
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (reader is null)
            throw new ITBError(Status.BadInput, "reader delegate must be non-null");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");

        ubyte[STREAM_AUTH_ID_LEN] streamID = _easyGenerateStreamID();
        size_t hsz = cast(size_t) easyHeaderSize();
        writer(streamID[]);

        ulong cum = 0;
        ubyte[] buf;
        ubyte[] readBuf = new ubyte[chunkSize];
        bool eof = false;
        // Deferred-final pattern: drain reads until buf > chunkSize,
        // emit one non-terminal chunk; on EOF emit residual as
        // terminal (possibly empty).
        while (!eof)
        {
            while (buf.length <= chunkSize && !eof)
            {
                size_t n = reader(readBuf);
                if (n == 0)
                {
                    eof = true;
                    break;
                }
                buf ~= readBuf[0 .. n];
            }
            if (buf.length > chunkSize)
            {
                // Pass the slice into `buf` directly to the FFI (skip
                // the `.dup` materialisation): the FFI copies the
                // plaintext into its output buffer during the cipher
                // pass, so wiping the prefix AFTER the FFI returns
                // preserves the no-residue invariant without paying for
                // a per-chunk owned copy. The wipe ordering swap is
                // safe because the FFI does not retain a pointer to the
                // input slice after returning.
                ubyte[] chunk = buf[0 .. chunkSize];
                ubyte[] ct = _easyEmitChunkAuth(chunk, streamID, cum, false);
                chunk[] = 0;
                buf = buf[chunkSize .. $];
                if (ct.length >= hsz)
                {
                    size_t w = (cast(size_t) ct[hsz - 4] << 8) | cast(size_t) ct[hsz - 3];
                    size_t h = (cast(size_t) ct[hsz - 2] << 8) | cast(size_t) ct[hsz - 1];
                    cum += cast(ulong) w * cast(ulong) h;
                }
                writer(ct);
            }
        }
        // Residual (possibly empty) as terminating chunk. Same .dup
        // elimination as the non-terminal branch — pass the residual
        // slice directly, wipe AFTER the FFI returns.
        ubyte[] tailChunk = buf;
        ubyte[] tailCt = _easyEmitChunkAuth(tailChunk, streamID, cum, true);
        tailChunk[] = 0;
        writer(tailCt);
        readBuf[] = 0;
    }

    /// Reads an authenticated stream transcript from `reader` and
    /// writes the recovered plaintext via `writer`. Throws
    /// `ITBStreamTruncatedError` when input exhausts without a
    /// terminating chunk, `ITBStreamAfterFinalError` when bytes
    /// follow a terminator, and `ITBError(Status.MACFailure)` on
    /// tampered transcript.
    void decryptStreamAuth(
        scope size_t delegate(ubyte[]) @trusted reader,
        scope void delegate(const(ubyte)[]) @trusted writer,
        size_t readSize) @trusted
    {
        _checkOpen();
        if (readSize == 0)
            throw new ITBError(Status.BadInput, "readSize must be positive");
        if (reader is null)
            throw new ITBError(Status.BadInput, "reader delegate must be non-null");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");

        size_t hsz = cast(size_t) easyHeaderSize();
        ubyte[] accum;
        ubyte[] readBuf = new ubyte[readSize];
        ubyte[STREAM_AUTH_ID_LEN] streamID;
        size_t sidHave = 0;
        ulong cum = 0;
        bool seenFinal = false;

        void drain() @trusted
        {
            while (true)
            {
                if (seenFinal)
                {
                    if (accum.length > 0)
                        throw new ITBStreamAfterFinalError(Status.StreamAfterFinal,
                            "auth stream: trailing bytes after terminator");
                    return;
                }
                if (accum.length < hsz)
                    return;
                // Per-instance parseChunkLen — uses this encryptor's
                // configured nonceBits.
                size_t chunkLen = this.parseChunkLen(accum[0 .. hsz]);
                if (accum.length < chunkLen)
                    return;
                size_t w = (cast(size_t) accum[hsz - 4] << 8) | cast(size_t) accum[hsz - 3];
                size_t h = (cast(size_t) accum[hsz - 2] << 8) | cast(size_t) accum[hsz - 1];
                ulong pixels = cast(ulong) w * cast(ulong) h;
                // Pass the slice into `accum` directly to the FFI (skip
                // the per-chunk `.dup`): the FFI copies the recovered
                // plaintext into the per-encryptor output cache during
                // its decrypt pass, so wiping the consumed prefix and
                // advancing the accumulator AFTER the FFI returns
                // preserves the no-residue invariant without paying for
                // a per-chunk owned copy.
                ubyte[] chunk = accum[0 .. chunkLen];
                bool ff = false;
                ubyte[] pt = _easyConsumeChunkAuth(chunk, streamID, cum, ff);
                writer(pt);
                pt[] = 0;
                chunk[] = 0;
                accum = accum[chunkLen .. $];
                cum += pixels;
                if (ff)
                    seenFinal = true;
            }
        }

        while (true)
        {
            size_t n = reader(readBuf);
            if (n == 0)
                break;
            size_t off = 0;
            if (sidHave < STREAM_AUTH_ID_LEN)
            {
                size_t need = STREAM_AUTH_ID_LEN - sidHave;
                size_t take = n < need ? n : need;
                streamID[sidHave .. sidHave + take] = readBuf[0 .. take];
                sidHave += take;
                off = take;
            }
            if (off < n)
                accum ~= readBuf[off .. n];
            if (sidHave == STREAM_AUTH_ID_LEN)
                drain();
        }
        if (sidHave < STREAM_AUTH_ID_LEN)
        {
            readBuf[] = 0;
            throw new ITBError(Status.BadInput,
                "auth stream: 32-byte stream prefix incomplete");
        }
        drain();
        readBuf[] = 0;
        if (!seenFinal)
            throw new ITBStreamTruncatedError(Status.StreamTruncated,
                "auth stream: terminator never observed");
    }

    // ─── Per-instance configuration setters ──────────────────────────

    /// Override the nonce size for this encryptor's subsequent
    /// encrypt / decrypt calls. Valid values: 128, 256, 512.
    ///
    /// Mutates only this encryptor's Config copy; process-wide
    /// `setNonceBits` is unaffected. The `nonceBits` /
    /// `easyHeaderSize` accessors read through to the live Go-side
    /// `cfg.NonceBits`, so they reflect the new value automatically
    /// on the next access.
    void setNonceBits(int n) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetNonceBits(_handle, n));
    }

    /// Override the CSPRNG barrier-fill margin for this encryptor.
    /// Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
    /// not need the same value as sender.
    void setBarrierFill(int n) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetBarrierFill(_handle, n));
    }

    /// 0 = byte-level split (default); non-zero = bit-level Bit Soup
    /// split. In Single Ouroboros, mode 1 alone activates the
    /// dispatcher's keyed bit-permutation overlay (Single OR-gates
    /// the two flags). While `cfg.LockSeed == 1` mode 0 is silently
    /// coerced to 1 to keep the dedicated lockSeed channel engaged;
    /// drop the lockSeed via `setLockSeed(0)` first to fully
    /// disengage.
    void setBitSoup(int mode) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetBitSoup(_handle, mode));
    }

    /// 0 = off (default); non-zero = on. Auto-couples `BitSoup=1` on
    /// this encryptor.
    void setLockSoup(int mode) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetLockSoup(_handle, mode));
    }

    /// 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
    /// bit-permutation overlay through it; auto-couples
    /// `LockSoup=1 + BitSoup=1` on this encryptor). Calling after the
    /// first encrypt throws
    /// `ITBError(Status.EasyLockSeedAfterEncrypt)`.
    void setLockSeed(int mode) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetLockSeed(_handle, mode));
    }

    /// Per-instance streaming chunk-size override (0 = auto-detect
    /// via `itb.ChunkSize` on the Go side).
    void setChunkSize(int n) @trusted
    {
        _checkOpen();
        check(ITB_Easy_SetChunkSize(_handle, n));
    }

    // ─── State serialization ─────────────────────────────────────────

    /// Serialises the encryptor's full state (PRF keys, seed
    /// components, MAC key, dedicated lockSeed material when active)
    /// as a JSON blob. The caller saves the bytes as it sees fit
    /// (disk, KMS, wire) and later passes them back to `importState`
    /// on a fresh encryptor to reconstruct the exact state.
    ///
    /// Per-instance configuration knobs (NonceBits, BarrierFill,
    /// BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
    /// — both sides communicate them via deployment config.
    /// LockSeed is carried because activating it changes the
    /// structural seed count.
    ubyte[] exportState() @trusted
    {
        _checkOpen();
        size_t outLen = 0;
        int rc = ITB_Easy_Export(_handle, null, 0, &outLen);
        if (rc == Status.OK)
            return [];
        if (rc != Status.BufferTooSmall)
            raiseFor(rc);
        auto buf = new ubyte[outLen];
        rc = ITB_Easy_Export(_handle, cast(void*) buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }

    /// Replaces the encryptor's PRF keys, seed components, MAC key,
    /// and (optionally) dedicated lockSeed material with the values
    /// carried in a JSON blob produced by a prior `exportState` call.
    ///
    /// On any failure the encryptor's pre-import state is unchanged
    /// (the underlying Go-side `Encryptor.Import` is transactional).
    /// Mismatch on primitive / keyBits / mode / mac throws
    /// `ITBEasyMismatchError`; the offending JSON field name is
    /// available on the exception's `.field` member and is also
    /// retrievable via `lastMismatchField`.
    void importState(const(ubyte)[] blob) @trusted
    {
        _checkOpen();
        void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
        int rc = ITB_Easy_Import(_handle, blobPtr, blob.length);
        check(rc);
    }

    // ─── Lifecycle ───────────────────────────────────────────────────

    /// Zeroes the encryptor's PRF keys, MAC key, and seed components
    /// on the Go side, and marks the encryptor as closed. Idempotent
    /// — multiple `close` calls return without error. Also wipes the
    /// per-encryptor output cache so the last ciphertext / plaintext
    /// does not linger in heap memory after the encryptor's working
    /// set has been zeroed on the Go side.
    void close() @trusted
    {
        // Wipe the cached output buffer regardless of close state —
        // repeated close calls keep the cache wiped without racing
        // the Go-side close.
        _wipeCache();
        if (_closed || _handle == 0)
        {
            // Idempotent — already closed.
            _closed = true;
            return;
        }
        int rc = ITB_Easy_Close(_handle);
        _closed = true;
        check(rc);
    }

    // ─── Internals ───────────────────────────────────────────────────

    private alias FnEasyCipher = extern (C) int function(
        size_t, void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

    /// Direct-call buffer-convention dispatcher with a per-encryptor
    /// output cache. Skips the size-probe round-trip the lower-level
    /// FFI helpers use: pre-allocates output capacity from a 1.25×
    /// upper bound (the empirical ITB ciphertext-expansion factor
    /// measured at ≤ 1.155 across every primitive / mode / nonce /
    /// payload-size combination) and falls through to an explicit
    /// grow-and-retry only on the rare under-shoot. Reuses the buffer
    /// across calls; `close` / destructor wipe it before drop.
    ///
    /// The current `Easy_Encrypt` / `Easy_Decrypt` C ABI does the
    /// full crypto on every call regardless of out-buffer capacity
    /// (it computes the result internally, then returns
    /// `BufferTooSmall` without exposing the work) — so the
    /// pre-allocation here avoids paying for a duplicate encrypt /
    /// decrypt on each D call.
    private ubyte[] _cipherCall(FnEasyCipher fn, const(ubyte)[] payload) @trusted
    {
        _checkOpen();
        // 1.25× + 4 KiB headroom comfortably exceeds the 1.155 max
        // expansion factor observed across the primitive / mode /
        // nonce-bits matrix; floor at 4 KiB so the very-small payload
        // case still gets a usable buffer. Saturating arithmetic
        // protects against `size_t` wrap on 32-bit targets at very
        // large payload sizes — under wrap the grow-and-retry path
        // would still recover, but only at the cost of an extra
        // round-trip; saturating to `size_t.max` keeps the first call
        // big enough on any host.
        size_t cap = _saturatingExpansion(payload.length);
        _ensureCache(cap);

        void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;

        size_t outLen = 0;
        int rc = fn(
            _handle,
            inPtr, payload.length,
            cast(void*) _outCache.ptr, _outCache.length,
            &outLen);
        if (rc == Status.BufferTooSmall)
        {
            // Pre-allocation was too tight (extremely rare given the
            // 1.25× safety margin) — grow exactly to the required
            // size and retry. The first call already paid for the
            // underlying crypto via the current C ABI's
            // full-encrypt-on-every-call contract, so the retry runs
            // the work again; this is strictly the fallback path and
            // not the hot loop.
            _ensureCache(outLen);
            rc = fn(
                _handle,
                inPtr, payload.length,
                cast(void*) _outCache.ptr, _outCache.length,
                &outLen);
        }
        check(rc);
        return _outCache[0 .. outLen];
    }

    /// Computes the saturating output-cache capacity estimate for a
    /// payload of size `n`. Caps at `size_t.max` on overflow rather
    /// than wrapping, so the first cipher call never under-allocates
    /// silently on pathologically large payloads. The 128 KiB
    /// constant (1.25x multiplier + 128 KiB pad + 128 KiB floor)
    /// absorbs the residual expansion from non-default barrier-fill
    /// values up to 32, where the absolute ratio reaches ~1.346
    /// around the 1 MiB payload region; it also acts as the floor
    /// for very-small payloads (Triple + auth-MAC + bf=32 at ptlen=1
    /// expands to ~35 KiB).
    private static size_t _saturatingExpansion(size_t n) @safe @nogc nothrow pure
    {
        // n * 5 / 4 with overflow-safe arithmetic.
        size_t mul;
        if (n > size_t.max / 5)
            mul = size_t.max;
        else
            mul = (n * 5) / 4;
        size_t add;
        if (mul > size_t.max - 131072)
            add = size_t.max;
        else
            add = mul + 131072;
        return add < 131072 ? 131072 : add;
    }

    /// Ensures the output cache has at least `need` bytes of
    /// capacity. Wipe-on-grow: zeroes the OLD slice before discarding
    /// the reference, so the previous-call ciphertext does not linger
    /// in heap garbage waiting for GC.
    private void _ensureCache(size_t need) @trusted
    {
        if (_outCache.length >= need)
            return;
        if (_outCache.length > 0)
            _outCache[] = 0;
        size_t cap = need < 131072 ? 131072 : need;
        _outCache = new ubyte[cap];
    }

    /// Zeroes and drops the output cache. Used by `close` and the
    /// destructor.
    private void _wipeCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }

    /// Preflight rejection for closed / freed encryptors. Throws
    /// `ITBError(Status.EasyClosed)` before any libitb FFI call so
    /// callers see the canonical "encryptor has been closed" code
    /// regardless of whether the underlying handle slot has merely
    /// been zeroed (post-`close`) or has been released back to libitb
    /// (post-destructor).
    private void _checkOpen() @safe pure
    {
        if (_closed || _handle == 0)
            throw new ITBError(Status.EasyClosed, "encryptor has been closed");
    }

    // ─── Streaming AEAD helpers ─────────────────────────────────────

    private enum size_t STREAM_AUTH_ID_LEN = 32;

    /// Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
    /// piggybacking on libitb's CSPRNG.
    private ubyte[STREAM_AUTH_ID_LEN] _easyGenerateStreamID() @trusted
    {
        import std.string : toStringz;
        ubyte[STREAM_AUTH_ID_LEN] out_;
        ulong[8] comps = [1, 2, 3, 4, 5, 6, 7, 8];
        size_t handle = 0;
        const(char)* cname = toStringz("blake3");
        int rc = ITB_NewSeedFromComponents(
            cast(char*) cname,
            comps.ptr, cast(int) comps.length,
            null, 0,
            &handle);
        check(rc);
        size_t got = 0;
        rc = ITB_GetSeedHashKey(handle, out_.ptr, STREAM_AUTH_ID_LEN, &got);
        int freeRc = ITB_FreeSeed(handle);
        check(rc);
        if (freeRc != Status.OK)
            raiseFor(freeRc);
        if (got != STREAM_AUTH_ID_LEN)
            throw new ITBError(Status.Internal,
                "stream_id CSPRNG draw returned wrong byte count");
        return out_;
    }

    private ubyte[] _easyEmitChunkAuth(
        const(ubyte)[] plaintext,
        ref ubyte[STREAM_AUTH_ID_LEN] streamID,
        ulong cumPixels,
        bool finalFlag) @trusted
    {
        void* inPtr = plaintext.length == 0 ? null : cast(void*) plaintext.ptr;
        int ff = finalFlag ? 1 : 0;
        size_t cap = _saturatingExpansion(plaintext.length);
        // Reuse the per-encryptor output cache instead of a fresh GC
        // alloc per chunk. Same grow-on-demand + wipe-on-grow shape as
        // `_cipherCall`; the streaming driver's hot loop benefits from
        // amortising the allocation across every chunk just like the
        // Single Message Easy Mode path does.
        _ensureCache(cap);
        size_t written = 0;
        int rc = ITB_Easy_EncryptStreamAuth(
            _handle,
            inPtr, plaintext.length,
            streamID.ptr, cumPixels, ff,
            cast(void*) _outCache.ptr, _outCache.length, &written);
        if (rc == Status.BufferTooSmall)
        {
            _ensureCache(written);
            rc = ITB_Easy_EncryptStreamAuth(
                _handle,
                inPtr, plaintext.length,
                streamID.ptr, cumPixels, ff,
                cast(void*) _outCache.ptr, _outCache.length, &written);
        }
        check(rc);
        return _outCache[0 .. written];
    }

    private ubyte[] _easyConsumeChunkAuth(
        const(ubyte)[] ciphertext,
        ref ubyte[STREAM_AUTH_ID_LEN] streamID,
        ulong cumPixels,
        out bool finalFlagOut) @trusted
    {
        void* inPtr = ciphertext.length == 0 ? null : cast(void*) ciphertext.ptr;
        int ff = 0;
        size_t cap = _saturatingExpansion(ciphertext.length);
        // Reuse the per-encryptor output cache (grow-on-demand +
        // wipe-on-grow), matching the cache wiring in the
        // encrypt-side dispatcher above.
        _ensureCache(cap);
        size_t written = 0;
        int rc = ITB_Easy_DecryptStreamAuth(
            _handle,
            inPtr, ciphertext.length,
            streamID.ptr, cumPixels,
            cast(void*) _outCache.ptr, _outCache.length, &written, &ff);
        if (rc == Status.BufferTooSmall)
        {
            _ensureCache(written);
            rc = ITB_Easy_DecryptStreamAuth(
                _handle,
                inPtr, ciphertext.length,
                streamID.ptr, cumPixels,
                cast(void*) _outCache.ptr, _outCache.length, &written, &ff);
        }
        check(rc);
        finalFlagOut = ff != 0;
        return _outCache[0 .. written];
    }
}
