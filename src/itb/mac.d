/// ITB MAC handle.
///
/// Provides a thin RAII wrapper over `ITB_NewMAC` / `ITB_FreeMAC`
/// for use with the authenticated encrypt / decrypt entry points.
///
/// Lifecycle. Non-copyable (`@disable this(this);`); deterministic
/// destructor at scope exit. Pass by `ref` to share without releasing.
module itb.mac;

import std.string : toStringz;

import itb.errors : check, ITBError;
import itb.sys;

/// A handle to one keyed MAC.
///
/// Construct from a canonical MAC name from `listMACs`: `"kmac256"`,
/// `"hmac-sha256"`, or `"hmac-blake3"`.
///
/// Key length must meet the primitive's `minKeyBytes` requirement
/// (16 for `kmac256` / `hmac-sha256`, 32 for `hmac-blake3`).
struct MAC
{
    private size_t _handle;
    private string _name;

    @disable this(this);

    /// Constructs a fresh MAC handle.
    this(string macName, const(ubyte)[] key) @trusted
    {
        size_t handle = 0;
        const(char)* cname = toStringz(macName);
        void* keyPtr = key.length == 0 ? null : cast(void*) key.ptr;
        int rc = ITB_NewMAC(cast(char*) cname, keyPtr, key.length, &handle);
        check(rc);
        this._handle = handle;
        this._name = macName;
    }

    /// Destructor — releases the underlying libitb handle if held.
    /// Idempotent; errors are swallowed.
    ~this() @trusted
    {
        if (_handle != 0)
        {
            cast(void) ITB_FreeMAC(_handle);
            _handle = 0;
        }
    }

    /// Returns the raw libitb handle.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// Returns the canonical MAC name this handle was constructed with.
    string name() const @safe @nogc nothrow pure
    {
        return _name;
    }
}
