/// Malloc-backed output buffers for the cipher hot path.
///
/// Cipher outputs (Single Message wires, one-shot stream wires, pump
/// results) are large and short-lived; allocating them on the D GC
/// heap makes the collector scan tens of megabytes per call and
/// dominates throughput at bench scale. [BorrowedBytes] carries such
/// an output on the C heap (`core.stdc.stdlib.malloc`) and frees it
/// deterministically in its destructor — no GC involvement on the hot
/// path. The struct is move-only (`@disable this(this)`); it converts
/// implicitly to `ubyte[]` via `alias this`, so slicing, indexing,
/// equality against arrays, `.dup`, and passing to `const(ubyte)[]`
/// parameters all work as with a plain slice. Taking a copy that
/// outlives the owner requires an explicit `.dup`.
module itb.buffer;

import core.exception : onOutOfMemoryError;
import core.stdc.stdlib : free, malloc, realloc;
import core.stdc.string : memcpy;

/// A move-only, malloc-backed byte buffer. Owns its allocation; the
/// destructor releases it. Slices obtained through `opSlice` (or the
/// implicit `alias this` conversion) borrow the storage and must not
/// outlive the owning value.
struct BorrowedBytes
{
    @disable this(this);

    private ubyte* raw;
    private size_t length_;

    /// Takes ownership of `r` (a malloc-family pointer of at least
    /// `n` bytes); the destructor frees it.
    package(itb) this(ubyte* r, size_t n) @system @nogc nothrow
    {
        raw = r;
        length_ = n;
    }

    ~this() @trusted @nogc nothrow
    {
        if (raw !is null)
        {
            free(raw);
            raw = null;
        }
        length_ = 0;
    }

    /// Number of valid bytes.
    @property size_t length() const @safe @nogc nothrow pure
    {
        return length_;
    }

    /// Raw pointer to the storage (null when empty and unallocated).
    @property inout(ubyte)* ptr() inout @system @nogc nothrow pure
    {
        return raw;
    }

    /// Borrowing view over the valid bytes.
    inout(ubyte)[] opSlice() inout @trusted @nogc nothrow
    {
        return raw is null ? null : raw[0 .. length_];
    }

    /// Implicit conversion to `ubyte[]` wherever a slice is expected.
    alias opSlice this;
}

/// Growable malloc-backed byte accumulator for the stream pump
/// loops. Append with [put], then transfer ownership of the result
/// via [take]; the destructor frees anything not taken.
package(itb) struct OwnedBuilder
{
    @disable this(this);

    private ubyte* raw;
    private size_t length_;
    private size_t cap;

    ~this() @trusted @nogc nothrow
    {
        if (raw !is null)
        {
            free(raw);
            raw = null;
        }
        length_ = 0;
        cap = 0;
    }

    /// Pre-sizes the backing store to at least `n` bytes.
    void reserve(size_t n) @trusted @nogc nothrow
    {
        if (n > cap)
            grow(n);
    }

    /// Appends `src` to the accumulated bytes.
    void put(scope const(ubyte)[] src) @trusted @nogc nothrow
    {
        if (src.length == 0)
            return;
        immutable need = length_ + src.length;
        if (need > cap)
        {
            // Double-or-exact growth keeps the amortized copy cost
            // linear while honouring a one-off oversized append.
            immutable doubled = cap * 2;
            grow(need > doubled ? need : doubled);
        }
        memcpy(raw + length_, &src[0], src.length);
        length_ += src.length;
    }

    /// Transfers ownership of the accumulated bytes to the returned
    /// [BorrowedBytes]; the builder is left empty and reusable.
    BorrowedBytes take() @trusted @nogc nothrow
    {
        auto owned = BorrowedBytes(raw, length_);
        raw = null;
        length_ = 0;
        cap = 0;
        return owned;
    }

    private void grow(size_t n) @trusted @nogc nothrow
    {
        enum size_t floorCap = 4096;
        immutable newCap = n < floorCap ? floorCap : n;
        auto p = cast(ubyte*) realloc(raw, newCap);
        if (p is null)
            onOutOfMemoryError();
        raw = p;
        cap = newCap;
    }
}
