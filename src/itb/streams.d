/// File-like streaming wrappers over the Single Message ITB Encrypt /
/// Decrypt API.
///
/// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
/// container size limit). Streaming larger payloads simply means
/// slicing the input into chunks at the binding layer, encrypting
/// each chunk through the regular FFI path, and concatenating the
/// results. The reverse operation walks a concatenated chunk stream
/// by reading the chunk header, calling [`itb.registry.parseChunkLen`]
/// to learn the chunk's body length, reading that many bytes, and
/// decrypting the single chunk.
///
/// Both struct-based wrappers ([`StreamEncryptor`], [`StreamDecryptor`]
/// and their Triple counterparts) and free-function convenience
/// wrappers ([`encryptStream`], [`decryptStream`], plus Triple
/// variants) are provided. Memory peak is bounded by `chunkSize`
/// (default 16 MB), regardless of the total payload length.
///
/// The Triple-Ouroboros (7-seed) variants share the same I/O contract
/// and only differ in the seed list passed to the constructor.
///
/// Output sink. The struct constructors accept a `void delegate(const
/// (ubyte)[])` writer delegate that receives each emitted chunk;
/// the free functions additionally take a `size_t delegate(ubyte[])`
/// reader delegate that fills its buffer argument with the next slice
/// of input bytes and returns the number of bytes read (zero on EOF).
/// The delegate-based shape lets callers route bytes through any
/// source / sink — sockets, files, in-memory buffers — without
/// committing the streaming wrappers to a specific I/O abstraction.
///
/// Warning. Do not call [`itb.registry.setNonceBits`] between writes
/// on the same stream. The chunks are encrypted under the active
/// nonce-size at the moment each chunk is flushed; switching
/// nonce-bits mid-stream produces a chunk header layout the paired
/// decryptor (which snapshots [`itb.registry.headerSize`] at
/// construction) cannot parse.
module itb.streams;

import itb.cipher : decrypt, decryptTriple, encrypt, encryptTriple;
import itb.errors : check, ITBError, ITBStreamAfterFinalError,
    ITBStreamTruncatedError, raiseFor;
import itb.registry : headerSize, parseChunkLen;
import itb.seed : Seed;
import itb.status : Status;
import itb.sys;

/// Default chunk size — matches `itb.DefaultChunkSize` on the Go side
/// (16 MB), the size at which ITB's barrier-encoded container layout
/// stays well within the per-chunk pixel cap.
enum size_t DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

// --------------------------------------------------------------------
// Single Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Chunked encrypt writer: buffers plaintext until at least
/// `chunkSize` bytes are available, then encrypts and emits one chunk
/// to the output writer delegate. The trailing partial buffer is
/// flushed as a final chunk on [`StreamEncryptor.close`] (so the
/// on-the-wire chunk count is `ceil(total / chunkSize)`).
///
/// Usage:
///
/// ---
/// import itb;
///
/// auto n = Seed("blake3", 1024);
/// auto d = Seed("blake3", 1024);
/// auto s = Seed("blake3", 1024);
/// ubyte[] sink;
/// auto enc = StreamEncryptor(n, d, s,
///     (const(ubyte)[] chunk) { sink ~= chunk; },
///     1 << 16);
/// enc.write(cast(const(ubyte)[]) "chunk one");
/// enc.write(cast(const(ubyte)[]) "chunk two");
/// enc.close();
/// ---
struct StreamEncryptor
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's encrypt() call. D does not statically enforce
    // borrow lifetimes, so the **caller MUST keep the original Seed
    // values alive for the entire StreamEncryptor lifetime** — letting
    // a Seed go out of scope before close() finishes triggers
    // use-after-free in the FFI call. These pointers are load-bearing,
    // not diagnostic.
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;

    @disable this(this);

    /// Constructs a fresh stream encryptor wrapping the given output
    /// writer delegate. `chunkSize` must be positive.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied `noise` / `data` / `start` Seed values. The caller
    /// MUST keep all three Seeds alive for the entire stream
    /// lifetime — until the destructor or `close()` returns. Letting
    /// any Seed go out of scope before then is undefined behaviour
    /// (use-after-free in the FFI call).
    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
    }

    /// Destructor — best-effort flush. Errors during destruction are
    /// swallowed because there is no path to surface them. Callers
    /// that need to see close-time errors must call `close()`
    /// explicitly.
    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunkSize`-sized slice that becomes available.
    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed, "write on closed StreamEncryptor");
        _buf ~= data;
        while (_buf.length >= _chunkSize)
        {
            ubyte[] chunk = _buf[0 .. _chunkSize].dup;
            // Zero the consumed prefix in the source slice so plaintext
            // does not linger before the GC reclaims it.
            _buf[0 .. _chunkSize] = 0;
            _buf = _buf[_chunkSize .. $];
            ubyte[] ct = encrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(ct);
            chunk[] = 0;
        }
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            ubyte[] chunk = _buf;
            _buf = [];
            ubyte[] ct = encrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(ct);
            chunk[] = 0;
        }
        _closed = true;
    }
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Chunked decrypt reader: accumulates ciphertext bytes via
/// [`StreamDecryptor.feed`] until a full chunk (header + body) is
/// available, then decrypts the chunk and writes the plaintext to the
/// output writer delegate. Multiple full chunks in one feed call are
/// processed sequentially.
///
/// Usage:
///
/// ---
/// import itb;
///
/// auto n = Seed("blake3", 1024);
/// auto d = Seed("blake3", 1024);
/// auto s = Seed("blake3", 1024);
/// ubyte[] sink;
/// auto dec = StreamDecryptor(n, d, s,
///     (const(ubyte)[] pt) { sink ~= pt; });
/// dec.feed(ciphertext);
/// dec.close();
/// ---
struct StreamDecryptor
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private size_t _headerSize;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's decrypt() call. D does not statically enforce
    // borrow lifetimes, so the **caller MUST keep the original Seed
    // values alive for the entire StreamDecryptor lifetime** — until
    // the destructor or `close()` returns. Letting any Seed go out of
    // scope before then triggers use-after-free in the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;

    @disable this(this);

    /// Constructs a fresh stream decryptor wrapping the given output
    /// writer delegate. The chunk-header size is snapshotted at
    /// construction so the decryptor uses the same header layout the
    /// matching encryptor saw — changing
    /// [`itb.registry.setNonceBits`] mid-stream would break decoding
    /// anyway.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied `noise` / `data` / `start` Seed values. The caller
    /// MUST keep all three Seeds alive for the entire stream
    /// lifetime — until the destructor or `close()` returns. Letting
    /// any Seed go out of scope before then is undefined behaviour
    /// (use-after-free in the FFI call).
    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._headerSize = cast(size_t) headerSize();
    }

    /// Destructor — marks the decryptor closed without raising on
    /// partial input. Callers who need to detect a half-chunk tail
    /// must call `close()` explicitly.
    ~this() @safe
    {
        _closed = true;
    }

    /// Appends `data` to the internal buffer and drains every complete
    /// chunk that has become available, calling the writer delegate
    /// with the decrypted plaintext.
    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed, "feed on closed StreamDecryptor");
        _buf ~= data;
        drain();
    }

    /// Finalises the decryptor. Throws `ITBError` with `Status.BadInput`
    /// when leftover bytes do not form a complete chunk — streaming
    /// ITB ciphertext cannot have a half-chunk tail.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            import std.conv : to;
            throw new ITBError(Status.BadInput,
                "StreamDecryptor: trailing " ~ _buf.length.to!string
                ~ " bytes do not form a complete chunk");
        }
        _closed = true;
    }

    private void drain() @trusted
    {
        while (true)
        {
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            ubyte[] chunk = _buf[0 .. chunkLen].dup;
            _buf = _buf[chunkLen .. $];
            ubyte[] pt = decrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(pt);
            // Zero recovered plaintext after the writer delegate has
            // returned; the writer is expected to consume / copy
            // immediately.
            pt[] = 0;
        }
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamEncryptor`].
struct StreamEncryptor3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's encryptTriple() call. D does not statically
    // enforce borrow lifetimes, so the **caller MUST keep all seven
    // original Seed values alive for the entire StreamEncryptor3
    // lifetime** — until the destructor or `close()` returns. Letting
    // any Seed go out of scope before then triggers use-after-free in
    // the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;

    @disable this(this);

    /// Constructs a fresh Triple-Ouroboros stream encryptor.
    /// `chunkSize` must be positive.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied seven Seed values. The caller MUST keep all seven
    /// Seeds alive for the entire stream lifetime — until the
    /// destructor or `close()` returns. Letting any Seed go out of
    /// scope before then is undefined behaviour (use-after-free in
    /// the FFI call).
    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
    }

    /// Destructor — best-effort flush; errors swallowed.
    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunkSize`-sized slice that becomes available.
    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed, "write on closed StreamEncryptor3");
        _buf ~= data;
        while (_buf.length >= _chunkSize)
        {
            ubyte[] chunk = _buf[0 .. _chunkSize].dup;
            _buf[0 .. _chunkSize] = 0;
            _buf = _buf[_chunkSize .. $];
            ubyte[] ct = encryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(ct);
            chunk[] = 0;
        }
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            ubyte[] chunk = _buf;
            _buf = [];
            ubyte[] ct = encryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(ct);
            chunk[] = 0;
        }
        _closed = true;
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamDecryptor`].
struct StreamDecryptor3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private size_t _headerSize;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's decryptTriple() call. D does not statically
    // enforce borrow lifetimes, so the **caller MUST keep all seven
    // original Seed values alive for the entire StreamDecryptor3
    // lifetime** — until the destructor or `close()` returns. Letting
    // any Seed go out of scope before then triggers use-after-free in
    // the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;

    @disable this(this);

    /// Constructs a fresh Triple-Ouroboros stream decryptor.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied seven Seed values. The caller MUST keep all seven
    /// Seeds alive for the entire stream lifetime — until the
    /// destructor or `close()` returns. Letting any Seed go out of
    /// scope before then is undefined behaviour (use-after-free in
    /// the FFI call).
    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._headerSize = cast(size_t) headerSize();
    }

    /// Destructor — marks the decryptor closed without raising on
    /// partial input.
    ~this() @safe
    {
        _closed = true;
    }

    /// Appends `data` to the internal buffer and drains every complete
    /// chunk that has become available.
    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed, "feed on closed StreamDecryptor3");
        _buf ~= data;
        drain();
    }

    /// Finalises the decryptor. Throws `ITBError` with `Status.BadInput`
    /// when leftover bytes do not form a complete chunk.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            import std.conv : to;
            throw new ITBError(Status.BadInput,
                "StreamDecryptor3: trailing " ~ _buf.length.to!string
                ~ " bytes do not form a complete chunk");
        }
        _closed = true;
    }

    private void drain() @trusted
    {
        while (true)
        {
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            ubyte[] chunk = _buf[0 .. chunkLen].dup;
            _buf = _buf[chunkLen .. $];
            ubyte[] pt = decryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(pt);
            pt[] = 0;
        }
    }
}

// --------------------------------------------------------------------
// Functional convenience wrappers.
// --------------------------------------------------------------------

/// Reads plaintext from `reader` until EOF, encrypts in chunks of
/// `chunkSize`, and writes concatenated ITB chunks to `writer`.
///
/// `reader` is a delegate that fills its buffer argument with the
/// next slice of input bytes and returns the number of bytes read
/// (zero on EOF). `writer` is a delegate that consumes each emitted
/// ciphertext chunk.
void encryptStream(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto enc = StreamEncryptor(noise, data, start, writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
    buf[] = 0;
}

/// Reads concatenated ITB chunks from `reader` until EOF and writes
/// the recovered plaintext to `writer`.
///
/// `readSize` controls the size of the staging buffer used to pull
/// ciphertext bytes from `reader`; it must be positive but does not
/// have to match the encrypter's chunk size. The decryptor
/// re-assembles full chunks internally by inspecting each chunk's
/// header.
void decryptStream(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto dec = StreamDecryptor(noise, data, start, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}

/// Triple-Ouroboros (7-seed) counterpart of [`encryptStream`].
void encryptStreamTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto enc = StreamEncryptor3(
        noise, data1, data2, data3, start1, start2, start3,
        writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
    buf[] = 0;
}

/// Triple-Ouroboros (7-seed) counterpart of [`decryptStream`].
void decryptStreamTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto dec = StreamDecryptor3(
        noise, data1, data2, data3, start1, start2, start3, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}

// --------------------------------------------------------------------
// Streaming AEAD: 32-byte stream prefix + per-chunk MAC under
// (stream_id, cumulative_pixel_offset, final_flag) binding.
// --------------------------------------------------------------------
//
// The Streaming AEAD wrappers extend the plain streaming surface with
// an authentication binding tuple — `(stream_id, cumulative_pixel_offset,
// final_flag)` — that closes chunk reorder, replay within stream,
// cross-stream replay, truncate-tail, and after-final attack vectors.
//
// On wire: a 32-byte CSPRNG `stream_id` prefix is written once at
// stream start, followed by a sequence of standard ITB chunks. The
// `final_flag` byte is appended to the encrypted body inside the
// container (deniable layout; not externally visible). The
// `cumulative_pixel_offset` is recomputed by both sides from each
// chunk's on-wire `W` * `H` header, so it never appears as a wire
// field. Tampered transcript surfaces as `Status.MACFailure` on the
// affected chunk; missing terminator surfaces as
// `Status.StreamTruncated`; trailing bytes after the terminator
// surface as `Status.StreamAfterFinal`.

import itb.mac : MAC;

private enum size_t STREAM_ID_LEN = 32;

/// Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
/// piggybacking on libitb's own CSPRNG: `ITB_NewSeedFromComponents`
/// with hash_key=NULL triggers a CSPRNG draw on the Go side, and
/// `ITB_GetSeedHashKey` reads back the 32-byte fixed key under the
/// blake3 primitive. The seed handle is freed before this returns;
/// only the 32 random bytes survive.
private ubyte[STREAM_ID_LEN] _generateStreamID() @trusted
{
    import std.string : toStringz;
    ubyte[STREAM_ID_LEN] out_;
    // Eight nonzero placeholder components — values are immaterial:
    // the CSPRNG-generated hash key is what becomes the stream_id.
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
    rc = ITB_GetSeedHashKey(handle, out_.ptr, STREAM_ID_LEN, &got);
    int freeRc = ITB_FreeSeed(handle);
    check(rc);
    if (freeRc != Status.OK)
        raiseFor(freeRc);
    if (got != STREAM_ID_LEN)
        throw new ITBError(Status.Internal,
            "stream_id CSPRNG draw returned wrong byte count");
    return out_;
}

private size_t _readBE16(const(ubyte)[] p) @safe @nogc nothrow pure
{
    return (cast(size_t) p[0] << 8) | cast(size_t) p[1];
}

/// Resolves the per-chunk encrypt-side ABI export for a given native
/// hash width (Single Ouroboros, 3 seeds + MAC).
private alias FnEncAuthSingle = extern (C) int function(
    size_t, size_t, size_t, size_t,
    void*, size_t,
    ubyte*, ulong, int,
    void*, size_t, size_t*) @system nothrow @nogc;

private alias FnDecAuthSingle = extern (C) int function(
    size_t, size_t, size_t, size_t,
    void*, size_t,
    ubyte*, ulong,
    void*, size_t, size_t*, int*) @system nothrow @nogc;

private alias FnEncAuthTriple = extern (C) int function(
    size_t,
    size_t, size_t, size_t,
    size_t, size_t, size_t,
    size_t,
    void*, size_t,
    ubyte*, ulong, int,
    void*, size_t, size_t*) @system nothrow @nogc;

private alias FnDecAuthTriple = extern (C) int function(
    size_t,
    size_t, size_t, size_t,
    size_t, size_t, size_t,
    size_t,
    void*, size_t,
    ubyte*, ulong,
    void*, size_t, size_t*, int*) @system nothrow @nogc;

private FnEncAuthSingle _encAuthSingleForWidth(int width) @trusted
{
    switch (width)
    {
        case 128: return &ITB_EncryptStreamAuthenticated128;
        case 256: return &ITB_EncryptStreamAuthenticated256;
        case 512: return &ITB_EncryptStreamAuthenticated512;
        default:
            throw new ITBError(Status.SeedWidthMix,
                "unsupported native hash width");
    }
}

private FnDecAuthSingle _decAuthSingleForWidth(int width) @trusted
{
    switch (width)
    {
        case 128: return &ITB_DecryptStreamAuthenticated128;
        case 256: return &ITB_DecryptStreamAuthenticated256;
        case 512: return &ITB_DecryptStreamAuthenticated512;
        default:
            throw new ITBError(Status.SeedWidthMix,
                "unsupported native hash width");
    }
}

private FnEncAuthTriple _encAuthTripleForWidth(int width) @trusted
{
    switch (width)
    {
        case 128: return &ITB_EncryptStreamAuthenticated3x128;
        case 256: return &ITB_EncryptStreamAuthenticated3x256;
        case 512: return &ITB_EncryptStreamAuthenticated3x512;
        default:
            throw new ITBError(Status.SeedWidthMix,
                "unsupported native hash width");
    }
}

private FnDecAuthTriple _decAuthTripleForWidth(int width) @trusted
{
    switch (width)
    {
        case 128: return &ITB_DecryptStreamAuthenticated3x128;
        case 256: return &ITB_DecryptStreamAuthenticated3x256;
        case 512: return &ITB_DecryptStreamAuthenticated3x512;
        default:
            throw new ITBError(Status.SeedWidthMix,
                "unsupported native hash width");
    }
}

/// Saturating output capacity estimate matching the per-encryptor
/// output cache in `itb.encryptor`. Pre-allocates from a 1.25×
/// multiplier + 128 KiB pad + 128 KiB floor so the first cipher call
/// avoids the size-probe round-trip; an explicit retry-on-
/// BufferTooSmall path remains as the safety net for non-default
/// barrier-fill values that lift expansion above the formula.
private size_t _streamSaturatingExpansion(size_t n) @safe @nogc nothrow pure
{
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

/// Grow-on-demand + wipe-on-grow helper for the per-stream output
/// cache. Mirrors `Encryptor._ensureCache` shape: zeroes the OLD slice
/// before discarding the reference so the previous-chunk ciphertext /
/// plaintext does not linger in heap garbage waiting for GC.
private void _ensureStreamCache(ref ubyte[] cache, size_t need) @trusted
{
    if (cache.length >= need)
        return;
    if (cache.length > 0)
        cache[] = 0;
    size_t cap = need < 131072 ? 131072 : need;
    cache = new ubyte[cap];
}

private ubyte[] _emitChunkAuthSingle(
    int width,
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac,
    const(ubyte)[] plaintext,
    ref ubyte[STREAM_ID_LEN] streamID,
    ulong cumPixels,
    bool finalFlag,
    ref ubyte[] outCache) @trusted
{
    auto fn = _encAuthSingleForWidth(width);
    void* inPtr = plaintext.length == 0 ? null : cast(void*) plaintext.ptr;
    int ff = finalFlag ? 1 : 0;
    size_t cap = _streamSaturatingExpansion(plaintext.length);
    // Reuse the per-stream output cache instead of a fresh GC alloc
    // per chunk. Same pattern as the Easy Mode dispatchers.
    _ensureStreamCache(outCache, cap);
    size_t written = 0;
    int rc = fn(
        noise.handle, data.handle, start.handle, mac.handle,
        inPtr, plaintext.length,
        streamID.ptr, cumPixels, ff,
        cast(void*) outCache.ptr, outCache.length, &written);
    if (rc == Status.BufferTooSmall)
    {
        _ensureStreamCache(outCache, written);
        rc = fn(
            noise.handle, data.handle, start.handle, mac.handle,
            inPtr, plaintext.length,
            streamID.ptr, cumPixels, ff,
            cast(void*) outCache.ptr, outCache.length, &written);
    }
    check(rc);
    return outCache[0 .. written];
}

private ubyte[] _emitChunkAuthTriple(
    int width,
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac,
    const(ubyte)[] plaintext,
    ref ubyte[STREAM_ID_LEN] streamID,
    ulong cumPixels,
    bool finalFlag,
    ref ubyte[] outCache) @trusted
{
    auto fn = _encAuthTripleForWidth(width);
    void* inPtr = plaintext.length == 0 ? null : cast(void*) plaintext.ptr;
    int ff = finalFlag ? 1 : 0;
    size_t cap = _streamSaturatingExpansion(plaintext.length);
    _ensureStreamCache(outCache, cap);
    size_t written = 0;
    int rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        mac.handle,
        inPtr, plaintext.length,
        streamID.ptr, cumPixels, ff,
        cast(void*) outCache.ptr, outCache.length, &written);
    if (rc == Status.BufferTooSmall)
    {
        _ensureStreamCache(outCache, written);
        rc = fn(
            noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle,
            inPtr, plaintext.length,
            streamID.ptr, cumPixels, ff,
            cast(void*) outCache.ptr, outCache.length, &written);
    }
    check(rc);
    return outCache[0 .. written];
}

private struct ConsumeAuthResult
{
    ubyte[] plaintext;
    bool finalFlag;
}

private ConsumeAuthResult _consumeChunkAuthSingle(
    int width,
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac,
    const(ubyte)[] ciphertext,
    ref ubyte[STREAM_ID_LEN] streamID,
    ulong cumPixels,
    ref ubyte[] outCache) @trusted
{
    auto fn = _decAuthSingleForWidth(width);
    void* inPtr = ciphertext.length == 0 ? null : cast(void*) ciphertext.ptr;
    int ff = 0;
    size_t cap = _streamSaturatingExpansion(ciphertext.length);
    _ensureStreamCache(outCache, cap);
    size_t written = 0;
    int rc = fn(
        noise.handle, data.handle, start.handle, mac.handle,
        inPtr, ciphertext.length,
        streamID.ptr, cumPixels,
        cast(void*) outCache.ptr, outCache.length, &written, &ff);
    if (rc == Status.BufferTooSmall)
    {
        _ensureStreamCache(outCache, written);
        rc = fn(
            noise.handle, data.handle, start.handle, mac.handle,
            inPtr, ciphertext.length,
            streamID.ptr, cumPixels,
            cast(void*) outCache.ptr, outCache.length, &written, &ff);
    }
    check(rc);
    return ConsumeAuthResult(outCache[0 .. written], ff != 0);
}

private ConsumeAuthResult _consumeChunkAuthTriple(
    int width,
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac,
    const(ubyte)[] ciphertext,
    ref ubyte[STREAM_ID_LEN] streamID,
    ulong cumPixels,
    ref ubyte[] outCache) @trusted
{
    auto fn = _decAuthTripleForWidth(width);
    void* inPtr = ciphertext.length == 0 ? null : cast(void*) ciphertext.ptr;
    int ff = 0;
    size_t cap = _streamSaturatingExpansion(ciphertext.length);
    _ensureStreamCache(outCache, cap);
    size_t written = 0;
    int rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        mac.handle,
        inPtr, ciphertext.length,
        streamID.ptr, cumPixels,
        cast(void*) outCache.ptr, outCache.length, &written, &ff);
    if (rc == Status.BufferTooSmall)
    {
        _ensureStreamCache(outCache, written);
        rc = fn(
            noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle,
            inPtr, ciphertext.length,
            streamID.ptr, cumPixels,
            cast(void*) outCache.ptr, outCache.length, &written, &ff);
    }
    check(rc);
    return ConsumeAuthResult(outCache[0 .. written], ff != 0);
}

// --------------------------------------------------------------------
// StreamEncryptorAuth — Single Ouroboros + MAC, RAII writer.
// --------------------------------------------------------------------

/// Authenticated chunked encrypt writer (Single Ouroboros + MAC).
/// Buffers plaintext until at least `chunkSize` bytes are available,
/// then drains one full chunk per FFI call. Each chunk is bound to
/// the running `(stream_id, cumulative_pixel_offset, final_flag)`
/// tuple inside the MAC closure; the 32-byte `stream_id` prefix is
/// emitted at the first `write` / `close` call, and the terminating
/// chunk carries `final_flag = true`.
///
/// Closed-state preflight is enforced: any `write` / `close` after
/// `close` (or after `~this`) surfaces `Status.EasyClosed`.
struct StreamEncryptorAuth
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    private bool _prefixEmitted;
    private int _width;
    private size_t _headerSize;
    private ulong _cumPixels;
    private ubyte[STREAM_ID_LEN] _streamID;
    // Raw pointers to caller-supplied Seed / MAC values, dereferenced
    // on every chunk's encrypt call. The caller MUST keep all four
    // values alive for the entire stream lifetime — until the
    // destructor or `close()` returns.
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;
    private const(MAC)* _macRef;
    /// Per-stream output buffer cache. Grows on demand; `close` /
    /// destructor wipe it before drop. Same Bonus 1 shape as the
    /// per-encryptor cache on `Encryptor` — the streaming class owns
    /// its own cache because the helper free functions have no
    /// encryptor instance to attach to.
    private ubyte[] _outCache;

    @disable this(this);

    /// Constructs a fresh authenticated stream encryptor.
    /// `chunkSize` must be positive. The 32-byte CSPRNG `stream_id`
    /// prefix is generated inside the constructor and emitted to the
    /// writer on the first `write` / `close` call.
    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         ref const MAC mac,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._macRef = &mac;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
        this._prefixEmitted = false;
        this._width = noise.width;
        this._headerSize = cast(size_t) headerSize();
        this._cumPixels = 0;
        this._streamID = _generateStreamID();
    }

    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
        _wipeOutCache();
    }

    private void _emitPrefix() @trusted
    {
        if (!_prefixEmitted)
        {
            _writer(_streamID[]);
            _prefixEmitted = true;
        }
    }

    private void _wipeOutCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }

    private void _emitOne(size_t plaintextLen, bool finalFlag) @trusted
    {
        // Pass the slice into `_buf` directly to the FFI (skip the
        // per-chunk `.dup`): the FFI copies the plaintext into the
        // per-stream output cache during the cipher pass, so wiping
        // the consumed prefix and advancing the buffer AFTER the FFI
        // returns preserves the no-residue invariant without paying
        // for a per-chunk owned copy.
        ubyte[] chunk = _buf[0 .. plaintextLen];
        ubyte[] ct = _emitChunkAuthSingle(
            _width, *_noiseRef, *_dataRef, *_startRef, *_macRef,
            chunk, _streamID, _cumPixels, finalFlag, _outCache);
        chunk[] = 0;
        _buf = _buf[plaintextLen .. $];
        if (ct.length >= _headerSize)
        {
            size_t w = _readBE16(ct[_headerSize - 4 .. _headerSize - 2]);
            size_t h = _readBE16(ct[_headerSize - 2 .. _headerSize]);
            _cumPixels += cast(ulong) w * cast(ulong) h;
        }
        _writer(ct);
    }

    /// Appends `data` to the internal buffer. Drains every
    /// completed-but-not-final chunk to the writer. The terminating
    /// chunk is emitted only by `close()`.
    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed,
                "write on closed StreamEncryptorAuth");
        _emitPrefix();
        _buf ~= data;
        // Keep at least one chunk's worth buffered until close() so
        // the deferred-final pattern can flip final_flag = true on
        // the last chunk. Drain non-terminal chunks while strictly
        // more than one chunk is buffered.
        while (_buf.length > _chunkSize)
        {
            _emitOne(_chunkSize, false);
        }
    }

    /// Emits the residual buffer as the terminating chunk. Idempotent.
    void close() @trusted
    {
        if (_closed)
            return;
        _emitPrefix();
        size_t remaining = _buf.length;
        _emitOne(remaining, true);
        _closed = true;
        _wipeOutCache();
    }
}

// --------------------------------------------------------------------
// StreamDecryptorAuth — Single Ouroboros + MAC, RAII reader.
// --------------------------------------------------------------------

/// Authenticated chunked decrypt reader (Single Ouroboros + MAC).
/// Reads the 32-byte `stream_id` prefix once, then drains every
/// complete chunk available in the internal buffer. Each chunk is
/// verified under the running cumulative pixel offset and recovered
/// final_flag; missing terminator surfaces as
/// `ITBStreamTruncatedError`, trailing bytes after the terminator
/// surface as `ITBStreamAfterFinalError`.
struct StreamDecryptorAuth
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private bool _seenFinal;
    private int _width;
    private size_t _headerSize;
    private ulong _cumPixels;
    private ubyte[STREAM_ID_LEN] _streamID;
    private size_t _sidHave;
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;
    private const(MAC)* _macRef;
    /// Per-stream output buffer cache. Same Bonus 1 shape as the
    /// encrypt-side counterpart; reused across every chunk's decrypt
    /// dispatch instead of a fresh GC alloc per chunk.
    private ubyte[] _outCache;

    @disable this(this);

    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         ref const MAC mac,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._macRef = &mac;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._seenFinal = false;
        this._width = noise.width;
        this._headerSize = cast(size_t) headerSize();
        this._cumPixels = 0;
        this._sidHave = 0;
    }

    ~this() @trusted
    {
        _closed = true;
        _wipeOutCache();
    }

    private void _wipeOutCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk that has become available.
    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed,
                "feed on closed StreamDecryptorAuth");
        size_t off = 0;
        if (_sidHave < STREAM_ID_LEN)
        {
            size_t need = STREAM_ID_LEN - _sidHave;
            size_t take = data.length < need ? data.length : need;
            _streamID[_sidHave .. _sidHave + take] = data[0 .. take];
            _sidHave += take;
            off = take;
        }
        if (off < data.length)
            _buf ~= data[off .. $];
        if (_sidHave == STREAM_ID_LEN)
            _drain();
    }

    /// Finalises the decryptor. Surfaces `ITBStreamTruncatedError`
    /// on missing terminator or `ITBStreamAfterFinalError` on
    /// trailing bytes after the terminator.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_sidHave < STREAM_ID_LEN)
        {
            _closed = true;
            _wipeOutCache();
            throw new ITBError(Status.BadInput,
                "auth stream: 32-byte stream prefix incomplete");
        }
        _drain();
        _closed = true;
        _wipeOutCache();
        if (!_seenFinal)
            throw new ITBStreamTruncatedError(Status.StreamTruncated,
                "auth stream: terminator never observed");
    }

    private void _drain() @trusted
    {
        while (true)
        {
            if (_seenFinal)
            {
                if (_buf.length > 0)
                    throw new ITBStreamAfterFinalError(Status.StreamAfterFinal,
                        "auth stream: trailing bytes after terminator");
                return;
            }
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            size_t w = _readBE16(_buf[_headerSize - 4 .. _headerSize - 2]);
            size_t h = _readBE16(_buf[_headerSize - 2 .. _headerSize]);
            ulong pixels = cast(ulong) w * cast(ulong) h;
            // Pass the slice into `_buf` directly to the FFI (skip
            // `.dup`): the FFI copies the recovered plaintext into the
            // per-stream output cache, so wiping the consumed prefix
            // and advancing AFTER the FFI returns preserves the
            // no-residue invariant without a per-chunk owned copy.
            ubyte[] chunk = _buf[0 .. chunkLen];
            auto r = _consumeChunkAuthSingle(
                _width, *_noiseRef, *_dataRef, *_startRef, *_macRef,
                chunk, _streamID, _cumPixels, _outCache);
            _writer(r.plaintext);
            r.plaintext[] = 0;
            chunk[] = 0;
            _buf = _buf[chunkLen .. $];
            _cumPixels += pixels;
            if (r.finalFlag)
                _seenFinal = true;
        }
    }
}

// --------------------------------------------------------------------
// StreamEncryptorAuth3 / StreamDecryptorAuth3 — Triple + MAC.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`StreamEncryptorAuth`].
struct StreamEncryptorAuth3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    private bool _prefixEmitted;
    private int _width;
    private size_t _headerSize;
    private ulong _cumPixels;
    private ubyte[STREAM_ID_LEN] _streamID;
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;
    private const(MAC)* _macRef;
    /// Per-stream output buffer cache (Triple variant). Same Bonus 1
    /// shape as the Single counterpart.
    private ubyte[] _outCache;

    @disable this(this);

    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         ref const MAC mac,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._macRef = &mac;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
        this._prefixEmitted = false;
        this._width = noise.width;
        this._headerSize = cast(size_t) headerSize();
        this._cumPixels = 0;
        this._streamID = _generateStreamID();
    }

    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
        _wipeOutCache();
    }

    private void _emitPrefix() @trusted
    {
        if (!_prefixEmitted)
        {
            _writer(_streamID[]);
            _prefixEmitted = true;
        }
    }

    private void _wipeOutCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }

    private void _emitOne(size_t plaintextLen, bool finalFlag) @trusted
    {
        // Pass the slice into `_buf` directly to the FFI (skip
        // `.dup`): the FFI copies the plaintext into the per-stream
        // output cache during the cipher pass, so wiping the consumed
        // prefix and advancing AFTER the FFI returns preserves the
        // no-residue invariant without a per-chunk owned copy.
        ubyte[] chunk = _buf[0 .. plaintextLen];
        ubyte[] ct = _emitChunkAuthTriple(
            _width, *_noiseRef,
            *_data1Ref, *_data2Ref, *_data3Ref,
            *_start1Ref, *_start2Ref, *_start3Ref,
            *_macRef,
            chunk, _streamID, _cumPixels, finalFlag, _outCache);
        chunk[] = 0;
        _buf = _buf[plaintextLen .. $];
        if (ct.length >= _headerSize)
        {
            size_t w = _readBE16(ct[_headerSize - 4 .. _headerSize - 2]);
            size_t h = _readBE16(ct[_headerSize - 2 .. _headerSize]);
            _cumPixels += cast(ulong) w * cast(ulong) h;
        }
        _writer(ct);
    }

    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed,
                "write on closed StreamEncryptorAuth3");
        _emitPrefix();
        _buf ~= data;
        while (_buf.length > _chunkSize)
        {
            _emitOne(_chunkSize, false);
        }
    }

    void close() @trusted
    {
        if (_closed)
            return;
        _emitPrefix();
        size_t remaining = _buf.length;
        _emitOne(remaining, true);
        _closed = true;
        _wipeOutCache();
    }
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`StreamDecryptorAuth`].
struct StreamDecryptorAuth3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private bool _seenFinal;
    private int _width;
    private size_t _headerSize;
    private ulong _cumPixels;
    private ubyte[STREAM_ID_LEN] _streamID;
    private size_t _sidHave;
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;
    private const(MAC)* _macRef;
    /// Per-stream output buffer cache (Triple variant). Same Bonus 1
    /// shape as the Single counterpart.
    private ubyte[] _outCache;

    @disable this(this);

    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         ref const MAC mac,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._macRef = &mac;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._seenFinal = false;
        this._width = noise.width;
        this._headerSize = cast(size_t) headerSize();
        this._cumPixels = 0;
        this._sidHave = 0;
    }

    ~this() @trusted
    {
        _closed = true;
        _wipeOutCache();
    }

    private void _wipeOutCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }

    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.EasyClosed,
                "feed on closed StreamDecryptorAuth3");
        size_t off = 0;
        if (_sidHave < STREAM_ID_LEN)
        {
            size_t need = STREAM_ID_LEN - _sidHave;
            size_t take = data.length < need ? data.length : need;
            _streamID[_sidHave .. _sidHave + take] = data[0 .. take];
            _sidHave += take;
            off = take;
        }
        if (off < data.length)
            _buf ~= data[off .. $];
        if (_sidHave == STREAM_ID_LEN)
            _drain();
    }

    void close() @trusted
    {
        if (_closed)
            return;
        if (_sidHave < STREAM_ID_LEN)
        {
            _closed = true;
            _wipeOutCache();
            throw new ITBError(Status.BadInput,
                "auth stream: 32-byte stream prefix incomplete");
        }
        _drain();
        _closed = true;
        _wipeOutCache();
        if (!_seenFinal)
            throw new ITBStreamTruncatedError(Status.StreamTruncated,
                "auth stream: terminator never observed");
    }

    private void _drain() @trusted
    {
        while (true)
        {
            if (_seenFinal)
            {
                if (_buf.length > 0)
                    throw new ITBStreamAfterFinalError(Status.StreamAfterFinal,
                        "auth stream: trailing bytes after terminator");
                return;
            }
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            size_t w = _readBE16(_buf[_headerSize - 4 .. _headerSize - 2]);
            size_t h = _readBE16(_buf[_headerSize - 2 .. _headerSize]);
            ulong pixels = cast(ulong) w * cast(ulong) h;
            // Pass the slice into `_buf` directly to the FFI (skip
            // `.dup`): the FFI copies the recovered plaintext into the
            // per-stream output cache, so wiping the consumed prefix
            // and advancing AFTER the FFI returns preserves the
            // no-residue invariant without a per-chunk owned copy.
            ubyte[] chunk = _buf[0 .. chunkLen];
            auto r = _consumeChunkAuthTriple(
                _width, *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                *_macRef,
                chunk, _streamID, _cumPixels, _outCache);
            _writer(r.plaintext);
            r.plaintext[] = 0;
            chunk[] = 0;
            _buf = _buf[chunkLen .. $];
            _cumPixels += pixels;
            if (r.finalFlag)
                _seenFinal = true;
        }
    }
}

// --------------------------------------------------------------------
// Free-function authenticated stream helpers.
// --------------------------------------------------------------------

/// Reads plaintext from `reader` until EOF, encrypts in chunks of
/// `chunkSize` under Single Ouroboros + MAC, and writes the 32-byte
/// stream prefix followed by concatenated authenticated chunks via
/// `writer`.
void encryptStreamAuth(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");
    auto enc = StreamEncryptorAuth(noise, data, start, mac, writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
    buf[] = 0;
}

/// Reads an authenticated stream transcript from `reader` and writes
/// the recovered plaintext via `writer`. Surfaces
/// `ITBStreamTruncatedError` on missing terminator,
/// `ITBStreamAfterFinalError` on trailing bytes, and `ITBError` with
/// `Status.MACFailure` on tampered transcript.
void decryptStreamAuth(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");
    auto dec = StreamDecryptorAuth(noise, data, start, mac, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`encryptStreamAuth`].
void encryptStreamAuthTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");
    auto enc = StreamEncryptorAuth3(
        noise, data1, data2, data3, start1, start2, start3, mac,
        writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
    buf[] = 0;
}

/// Triple-Ouroboros (7-seed) authenticated counterpart of
/// [`decryptStreamAuth`].
void decryptStreamAuthTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");
    auto dec = StreamDecryptorAuth3(
        noise, data1, data2, data3, start1, start2, start3, mac, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}
