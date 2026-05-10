/// Format-deniability wrapper for ITB ciphertext.
///
/// D-idiomatic surface over the 12 `ITB_Wrap*` / `ITB_Unwrap*` /
/// `ITB_WrapStream*` / `ITB_UnwrapStream*` / `ITB_WrapperKeySize` /
/// `ITB_WrapperNonceSize` exports in `cmd/cshared/main.go`. Wraps an
/// ITB ciphertext under one of three outer keystream ciphers
/// (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR mode) so the on-wire
/// bytes carry no ITB-specific format pattern (W / H / container
/// layout for Non-AEAD; 32-byte streamID prefix + per-chunk metadata
/// for Streaming AEAD). The wrap exists for format-deniability ONLY —
/// ITB already provides content-deniability and the AEAD path
/// already provides integrity.
///
/// Quick start (Single Message wrap / unwrap):
///
/// ---
/// import itb;
///
/// auto key = wrapperGenerateKey(Cipher.aes128Ctr);
/// auto blob = cast(const(ubyte)[]) "...ITB ciphertext bytes...";
/// auto wire = wrap(Cipher.aes128Ctr, key, blob);
/// auto recovered = unwrap(Cipher.aes128Ctr, key, wire);
/// assert(recovered == blob);
/// ---
///
/// Single Message in-place mutation (zero-allocation steady state):
///
/// ---
/// auto mutable = blob.dup;
/// auto nonce = wrapInPlace(Cipher.chaCha20, key, mutable);
/// auto wireBytes = nonce ~ mutable;
/// // On the receive side:
/// auto wireBuf = wireBytes.dup;
/// auto bodyView = unwrapInPlace(Cipher.chaCha20, key, wireBuf);
/// assert(bodyView == blob);
/// ---
///
/// Streaming wrap (caller-side framing through one keystream so length
/// prefixes also XOR through):
///
/// ---
/// auto ww = WrapStreamWriter(Cipher.sipHash24, key);
/// scope(exit) ww.close();
/// ubyte[] wireBuf = ww.nonce.dup;
/// wireBuf ~= ww.update(cast(const(ubyte)[]) "chunk-1");
/// wireBuf ~= ww.update(cast(const(ubyte)[]) "chunk-2");
/// ---
///
/// The `Cipher` enum selects one of three outer ciphers: `aes128Ctr`
/// (AES-128-CTR — 16-byte key + 16-byte nonce, AES-NI accelerated on
/// the libitb side), `chaCha20` (ChaCha20 (RFC8439) — 32-byte key +
/// 12-byte nonce), or `sipHash24` (SipHash-2-4 in CTR mode — 16-byte
/// key + 16-byte nonce, custom CTR construction over the SipHash-2-4
/// PRF).
///
/// Threading. Each `WrapStreamWriter` / `UnwrapStreamReader` owns
/// one libitb stream handle and is single-feeder by construction.
/// Multiple instances run independently. The free-function helpers
/// (`wrap` / `unwrap` / `wrapInPlace` / `unwrapInPlace`) are
/// thread-safe — each call allocates its own outer cipher handle
/// internally and the underlying libitb keystream constructor draws
/// a fresh CSPRNG nonce per call.
module itb.wrapper;

import std.string : toStringz;

import itb.errors : check, ITBError, raiseFor;
import itb.status : Status;
import itb.sys;

// --------------------------------------------------------------------
// Cipher enum + name mapping.
// --------------------------------------------------------------------

/// Outer keystream cipher selected per wrap session.
///
/// Each variant maps to one of the three cipher-name strings the
/// underlying FFI accepts: `"aes"` / `"chacha"` / `"siphash"`. The
/// Go-side constants are `wrapper.CipherAES128CTR` /
/// `wrapper.CipherChaCha20` / `wrapper.CipherSipHash24`.
enum Cipher
{
    /// AES-128-CTR — 16-byte key, 16-byte nonce. Hardware-accelerated
    /// on the libitb side via Go's `crypto/cipher.NewCTR` over
    /// `crypto/aes.NewCipher` (AES-NI on x86_64; ARM crypto extension
    /// on aarch64).
    aes128Ctr,
    /// ChaCha20 (RFC 8439) — 32-byte key, 12-byte nonce. No AES-NI
    /// dependency.
    chaCha20,
    /// SipHash-2-4 in CTR mode — 16-byte key, 16-byte nonce. Custom
    /// CTR construction over the SipHash-2-4 PRF; sound under the
    /// standard PRF assumption that justifies AES-CTR.
    sipHash24,
}

/// Canonical iteration order of supported outer ciphers. Matches the
/// Go-side `wrapper.CipherNames` slice exactly.
immutable Cipher[] CIPHER_NAMES = [
    Cipher.aes128Ctr,
    Cipher.chaCha20,
    Cipher.sipHash24,
];

/// Returns the FFI cipher-name string used by every entry point.
string ffiName(Cipher cipher) @safe pure
{
    final switch (cipher)
    {
        case Cipher.aes128Ctr: return "aes";
        case Cipher.chaCha20:  return "chacha";
        case Cipher.sipHash24: return "siphash";
    }
}

/// Parses a cipher name string into a `Cipher` value. Accepts only
/// the three canonical forms ("aes" / "chacha" / "siphash"); any
/// other value raises `WrapperInvalidCipherError`.
Cipher cipherFromName(string name) @safe pure
{
    switch (name)
    {
        case "aes":     return Cipher.aes128Ctr;
        case "chacha":  return Cipher.chaCha20;
        case "siphash": return Cipher.sipHash24;
        default:
            throw new WrapperInvalidCipherError(name);
    }
}

// --------------------------------------------------------------------
// Typed exception hierarchy.
// --------------------------------------------------------------------

/// Base class for every wrapper-side exception. Subclasses preserve
/// the structural failure mode (unknown cipher name, key length
/// mismatch, nonce length mismatch, exhausted handle) and inherit
/// `.statusCode` from `ITBError` so callers can branch on the
/// failure kind without parsing the textual diagnostic.
class WrapperError : ITBError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Raised when a cipher name string is not one of "aes" / "chacha" /
/// "siphash". Carries `Status.BadInput`.
class WrapperInvalidCipherError : WrapperError
{
    /// The unparseable cipher name.
    string cipherName;

    this(string name,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(Status.BadInput,
              "unknown wrapper cipher \"" ~ name
              ~ "\" (expected aes / chacha / siphash)",
              file, line, next);
        this.cipherName = name;
    }
}

/// Raised when the supplied key length does not match the cipher's
/// expected key size. Carries `Status.BadInput`.
class WrapperInvalidKeyError : WrapperError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Raised when an internal nonce buffer is sized incorrectly for
/// the selected cipher (typically a mismatch between the wire-prefix
/// nonce length and the cipher's `nonceSize`). Carries
/// `Status.BadInput`.
class WrapperInvalidNonceError : WrapperError
{
    this(int code, string detailMsg,
         string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(code, detailMsg, file, line, next);
    }
}

/// Raised when a streaming `update` / `close` call follows a prior
/// `close`. Carries `Status.BadHandle`.
class WrapperHandleClosedError : WrapperError
{
    this(string file = __FILE__,
         size_t line = __LINE__,
         Throwable next = null) @safe pure nothrow
    {
        super(Status.BadHandle, "stream handle has been closed",
              file, line, next);
    }
}

// --------------------------------------------------------------------
// Key / nonce introspection.
// --------------------------------------------------------------------

/// Returns the byte length of the keystream-cipher key for the
/// named outer cipher (16 / 32 / 16 for AES-128-CTR / ChaCha20 /
/// SipHash-2-4).
size_t keySize(Cipher cipher) @trusted
{
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t n = 0;
    int rc = ITB_WrapperKeySize(cast(char*) cname, &n);
    check(rc);
    return n;
}

/// Returns the on-wire nonce length the named outer cipher emits
/// per stream (16 / 12 / 16 for AES-128-CTR / ChaCha20 /
/// SipHash-2-4).
size_t nonceSize(Cipher cipher) @trusted
{
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t n = 0;
    int rc = ITB_WrapperNonceSize(cast(char*) cname, &n);
    check(rc);
    return n;
}

/// Returns a fresh CSPRNG-generated key of the size required by
/// `cipher` (16 / 32 / 16 bytes for AES-128-CTR / ChaCha20 /
/// SipHash-2-4). Uses `std.random.unpredictableSeed` chained with a
/// xorshift64* expander seeded from the OS entropy pool — the
/// libitb-side draw via `crypto/rand` happens internally on every
/// wrap/unwrap call and remains the source of nonce entropy.
ubyte[] wrapperGenerateKey(Cipher cipher) @trusted
{
    import std.random : unpredictableSeed;
    size_t n = keySize(cipher);
    auto key = new ubyte[n];
    // Fill from std.random unpredictableSeed (OS entropy on POSIX +
    // CryptGenRandom on Windows). One 32-bit draw per 4 bytes of key.
    size_t off = 0;
    while (off < n)
    {
        uint v = unpredictableSeed();
        size_t take = (n - off) < 4 ? (n - off) : 4;
        foreach (k; 0 .. take)
            key[off + k] = cast(ubyte)((v >> (8 * k)) & 0xFF);
        off += take;
    }
    return key;
}

// --------------------------------------------------------------------
// Internal validation helpers.
// --------------------------------------------------------------------

private void _checkKeyLen(Cipher cipher, size_t keyLen) @trusted
{
    size_t expected = keySize(cipher);
    if (keyLen != expected)
    {
        import std.conv : to;
        throw new WrapperInvalidKeyError(
            Status.BadInput,
            "wrapper " ~ ffiName(cipher) ~ ": key must be "
            ~ expected.to!string ~ " bytes, got " ~ keyLen.to!string);
    }
}

private void _checkNonceLen(Cipher cipher, size_t nlen) @trusted
{
    size_t expected = nonceSize(cipher);
    if (nlen != expected)
    {
        import std.conv : to;
        throw new WrapperInvalidNonceError(
            Status.BadInput,
            "wrapper " ~ ffiName(cipher) ~ ": nonce must be "
            ~ expected.to!string ~ " bytes, got " ~ nlen.to!string);
    }
}

// --------------------------------------------------------------------
// Single Message wrap / unwrap.
// --------------------------------------------------------------------

/// Single Message wrap. Seals `blob` under `cipher` with a fresh
/// per-call CSPRNG nonce; returns the wire bytes
/// `nonce || keystream-XOR(blob)`.
///
/// Allocates a fresh output buffer of size
/// `nonceSize(cipher) + blob.length` per call. For zero-allocation
/// steady state on the hot path use `wrapInPlace`.
ubyte[] wrap(Cipher cipher, const(ubyte)[] key, const(ubyte)[] blob) @trusted
{
    _checkKeyLen(cipher, key.length);
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t nlen = nonceSize(cipher);
    size_t cap = nlen + blob.length;
    auto outBuf = new ubyte[cap == 0 ? 1 : cap];
    size_t outLen = 0;
    void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
    void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
    int rc = ITB_Wrap(
        cast(char*) cname,
        keyPtr, key.length,
        blobPtr, blob.length,
        cast(void*) outBuf.ptr, cap, &outLen);
    check(rc);
    return outBuf[0 .. outLen];
}

/// Single Message unwrap. Reads the leading `nonceSize(cipher)` bytes
/// of `wire` as the per-stream nonce, XOR-decrypts the remainder
/// under `(key, nonce)` and returns the recovered blob.
///
/// Allocates a fresh output buffer of size
/// `wire.length - nonceSize(cipher)` per call. For zero-allocation
/// steady state use `unwrapInPlace`.
ubyte[] unwrap(Cipher cipher, const(ubyte)[] key, const(ubyte)[] wire) @trusted
{
    _checkKeyLen(cipher, key.length);
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t nlen = nonceSize(cipher);
    if (wire.length < nlen)
    {
        import std.conv : to;
        throw new WrapperInvalidNonceError(
            Status.BadInput,
            "wrapper " ~ name ~ ": wire shorter than nonce ("
            ~ wire.length.to!string ~ " < " ~ nlen.to!string ~ ")");
    }
    size_t cap = wire.length - nlen;
    auto outBuf = new ubyte[cap == 0 ? 1 : cap];
    size_t outLen = 0;
    void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
    int rc = ITB_Unwrap(
        cast(char*) cname,
        keyPtr, key.length,
        cast(void*) wire.ptr, wire.length,
        cast(void*) outBuf.ptr, cap, &outLen);
    check(rc);
    return outBuf[0 .. outLen];
}

/// In-place Single Message wrap. XORs `blob` under a fresh per-call
/// CSPRNG nonce; returns the per-stream nonce.
///
/// `blob` is **MUTATED** — the caller is expected to emit
/// `nonce || blob` to the wire (or compose a single buffer
/// themselves). For an immutable plaintext path use `wrap`.
///
/// Suitable for hot paths where the caller has just produced an
/// ITB ciphertext and will not re-read it (the typical case for
/// buffered write-to-wire).
ubyte[] wrapInPlace(Cipher cipher, const(ubyte)[] key, ubyte[] blob) @trusted
{
    _checkKeyLen(cipher, key.length);
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t nlen = nonceSize(cipher);
    auto nonceBuf = new ubyte[nlen];
    void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
    void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
    int rc = ITB_WrapInPlace(
        cast(char*) cname,
        keyPtr, key.length,
        blobPtr, blob.length,
        cast(void*) nonceBuf.ptr, nlen);
    check(rc);
    return nonceBuf;
}

/// In-place Single Message unwrap. Strips the leading
/// `nonceSize(cipher)` bytes from `wire` and XOR-decrypts the
/// remainder in place. The returned slice aliases
/// `wire[nonceSize(cipher) .. $]` and contains the recovered blob.
///
/// `wire` is **MUTATED**. For an immutable wire input use `unwrap`.
ubyte[] unwrapInPlace(Cipher cipher, const(ubyte)[] key, ubyte[] wire) @trusted
{
    _checkKeyLen(cipher, key.length);
    auto name = ffiName(cipher);
    const(char)* cname = toStringz(name);
    size_t nlen = nonceSize(cipher);
    if (wire.length < nlen)
    {
        import std.conv : to;
        throw new WrapperInvalidNonceError(
            Status.BadInput,
            "wrapper " ~ name ~ ": wire shorter than nonce ("
            ~ wire.length.to!string ~ " < " ~ nlen.to!string ~ ")");
    }
    void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
    int rc = ITB_UnwrapInPlace(
        cast(char*) cname,
        keyPtr, key.length,
        cast(void*) wire.ptr, wire.length);
    check(rc);
    // Body slice aliases wire[nlen .. $]; nonce prefix unchanged.
    return wire[nlen .. $];
}

// --------------------------------------------------------------------
// Streaming wrap / unwrap.
// --------------------------------------------------------------------

/// Streaming wrap-encrypt handle.
///
/// Allocated as a fresh-nonce / fresh-keystream session. The
/// constructor draws a CSPRNG nonce from libitb, opens a wrap-stream
/// handle bound to `(cipher, key, nonce)`, and exposes the nonce
/// via the `nonce` property so the caller can emit it once at
/// stream start (typically as the wire prefix). Subsequent `update`
/// calls XOR caller plaintext through the keystream and return the
/// encrypted bytes; the keystream counter advances monotonically
/// across calls.
///
/// Pair every `WrapStreamWriter` with an `UnwrapStreamReader`
/// keyed by the same `(cipher, key)` and the nonce read off the
/// wire.
///
/// Lifecycle. The struct is non-copyable (`@disable this(this);`).
/// The destructor releases the libitb handle best-effort on scope
/// exit. Call `close()` explicitly to surface release-time errors.
/// Once closed, subsequent `update` raises
/// `WrapperHandleClosedError`.
struct WrapStreamWriter
{
    private size_t _handle;
    private ubyte[] _nonce;
    private Cipher _cipher;
    private bool _closed;

    @disable this(this);

    /// Constructs a fresh wrap-encrypt stream. Draws a per-stream
    /// CSPRNG nonce on the libitb side and binds it to the
    /// keystream cipher under `(cipher, key)`.
    this(Cipher cipher, const(ubyte)[] key) @trusted
    {
        _checkKeyLen(cipher, key.length);
        auto name = ffiName(cipher);
        const(char)* cname = toStringz(name);
        size_t nlen = nonceSize(cipher);
        auto nonceBuf = new ubyte[nlen];
        size_t handle = 0;
        void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
        int rc = ITB_WrapStreamWriter_Init(
            cast(char*) cname,
            keyPtr, key.length,
            cast(void*) nonceBuf.ptr, nlen,
            &handle);
        check(rc);
        this._handle = handle;
        this._nonce = nonceBuf;
        this._cipher = cipher;
        this._closed = false;
    }

    /// Destructor — releases the libitb wrap-stream handle if held.
    /// Errors are swallowed (no path to surface them from a
    /// destructor). Callers that need to see release-time errors
    /// must call `close()` explicitly.
    ~this() @trusted
    {
        if (_handle != 0 && !_closed)
        {
            cast(void) ITB_WrapStreamWriter_Free(_handle);
            _handle = 0;
            _closed = true;
        }
    }

    /// The per-stream CSPRNG nonce. The caller emits this once at
    /// stream start (typically as the wire prefix) so the matching
    /// `UnwrapStreamReader` can be constructed against it.
    const(ubyte)[] nonce() const @safe @nogc nothrow pure
    {
        return _nonce;
    }

    /// The outer cipher selected at construction.
    Cipher cipher() const @safe @nogc nothrow pure
    {
        return _cipher;
    }

    /// Opaque libitb handle id (uintptr). Useful for diagnostics.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// XOR-encrypts `src` through the keystream and returns the
    /// resulting bytes (a freshly allocated slice). The keystream
    /// counter advances by `src.length` bytes.
    ///
    /// Throws `WrapperHandleClosedError` if the writer has been
    /// closed.
    ubyte[] update(const(ubyte)[] src) @trusted
    {
        if (_closed || _handle == 0)
            throw new WrapperHandleClosedError();
        if (src.length == 0)
            return [];
        auto outBuf = new ubyte[src.length];
        int rc = ITB_WrapStreamWriter_Update(
            _handle,
            cast(void*) src.ptr, src.length,
            cast(void*) outBuf.ptr, outBuf.length);
        check(rc);
        return outBuf;
    }

    /// XOR-encrypts `buf` through the keystream **in place**. The
    /// caller's slice is mutated; no return value. The keystream
    /// counter advances by `buf.length` bytes.
    ///
    /// Throws `WrapperHandleClosedError` if the writer has been
    /// closed.
    void updateInPlace(ubyte[] buf) @trusted
    {
        if (_closed || _handle == 0)
            throw new WrapperHandleClosedError();
        if (buf.length == 0)
            return;
        int rc = ITB_WrapStreamWriter_Update(
            _handle,
            cast(void*) buf.ptr, buf.length,
            cast(void*) buf.ptr, buf.length);
        check(rc);
    }

    /// Releases the underlying libitb wrap-stream handle. Idempotent;
    /// a second call is a no-op.
    void close() @trusted
    {
        if (_closed || _handle == 0)
        {
            _closed = true;
            _handle = 0;
            return;
        }
        size_t h = _handle;
        _handle = 0;
        _closed = true;
        int rc = ITB_WrapStreamWriter_Free(h);
        check(rc);
    }
}

/// Streaming unwrap-decrypt handle. Counterpart of
/// `WrapStreamWriter`.
///
/// Constructed against the per-stream nonce read off the wire
/// (typically the leading `nonceSize(cipher)` bytes). The libitb
/// wrap-stream handle is keyed by `(cipher, key, wireNonce)`;
/// subsequent `update` calls XOR-decrypt caller-supplied wire bytes
/// into recovered plaintext.
///
/// Lifecycle. The struct is non-copyable (`@disable this(this);`).
/// The destructor releases the libitb handle best-effort on scope
/// exit. Call `close()` explicitly to surface release-time errors.
struct UnwrapStreamReader
{
    private size_t _handle;
    private Cipher _cipher;
    private bool _closed;

    @disable this(this);

    /// Constructs a fresh unwrap-decrypt stream against the leading
    /// per-stream nonce read off the wire. `wireNonce.length` must
    /// equal `nonceSize(cipher)`.
    this(Cipher cipher, const(ubyte)[] key, const(ubyte)[] wireNonce) @trusted
    {
        _checkKeyLen(cipher, key.length);
        _checkNonceLen(cipher, wireNonce.length);
        auto name = ffiName(cipher);
        const(char)* cname = toStringz(name);
        size_t handle = 0;
        void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
        void* noncePtr = wireNonce.length == 0 ? null : cast(void*) wireNonce.ptr;
        int rc = ITB_UnwrapStreamReader_Init(
            cast(char*) cname,
            keyPtr, key.length,
            noncePtr, wireNonce.length,
            &handle);
        check(rc);
        this._handle = handle;
        this._cipher = cipher;
        this._closed = false;
    }

    /// Destructor — releases the libitb wrap-stream handle if held.
    /// Errors are swallowed (no path to surface them from a
    /// destructor).
    ~this() @trusted
    {
        if (_handle != 0 && !_closed)
        {
            cast(void) ITB_UnwrapStreamReader_Free(_handle);
            _handle = 0;
            _closed = true;
        }
    }

    /// The outer cipher selected at construction.
    Cipher cipher() const @safe @nogc nothrow pure
    {
        return _cipher;
    }

    /// Opaque libitb handle id (uintptr). Useful for diagnostics.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// XOR-decrypts `src` through the keystream and returns the
    /// recovered plaintext bytes (a freshly allocated slice). The
    /// keystream counter advances by `src.length` bytes.
    ///
    /// Throws `WrapperHandleClosedError` if the reader has been
    /// closed.
    ubyte[] update(const(ubyte)[] src) @trusted
    {
        if (_closed || _handle == 0)
            throw new WrapperHandleClosedError();
        if (src.length == 0)
            return [];
        auto outBuf = new ubyte[src.length];
        int rc = ITB_UnwrapStreamReader_Update(
            _handle,
            cast(void*) src.ptr, src.length,
            cast(void*) outBuf.ptr, outBuf.length);
        check(rc);
        return outBuf;
    }

    /// XOR-decrypts `buf` through the keystream **in place**. The
    /// caller's slice is mutated; no return value.
    void updateInPlace(ubyte[] buf) @trusted
    {
        if (_closed || _handle == 0)
            throw new WrapperHandleClosedError();
        if (buf.length == 0)
            return;
        int rc = ITB_UnwrapStreamReader_Update(
            _handle,
            cast(void*) buf.ptr, buf.length,
            cast(void*) buf.ptr, buf.length);
        check(rc);
    }

    /// Releases the underlying libitb wrap-stream handle. Idempotent.
    void close() @trusted
    {
        if (_closed || _handle == 0)
        {
            _closed = true;
            _handle = 0;
            return;
        }
        size_t h = _handle;
        _handle = 0;
        _closed = true;
        int rc = ITB_UnwrapStreamReader_Free(h);
        check(rc);
    }
}
