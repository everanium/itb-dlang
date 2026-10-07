/// Plaintext content: the payload modes, the seeded per-worker
/// generator, and the buffer fill from the operating-system CSPRNG.
module loop.payload;

import loop.state : PayloadMode;

/// D-specific. druntime carries no binding for the `getrandom`
/// syscall, so the libc entry is declared here. Reading /dev/urandom
/// instead would be a different mechanism with a descriptor and a
/// read loop of its own.
private extern (C) ptrdiff_t getrandom(void* buf, size_t buflen, uint flags) @system nothrow @nogc;

/// Payload mode selector values for the --payload-mode flag.
///
///   - fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
///     all 0xFF) probing minimum-entropy plaintext handling.
///   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
private static immutable string[] payloadNames = [
    "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
];

string payloadModeName(PayloadMode mode) @safe nothrow
{
    return payloadNames[cast(size_t) mode];
}

bool parsePayloadMode(string s, out PayloadMode outMode) @safe nothrow
{
    foreach (i, name; payloadNames)
        if (s == name)
        {
            outMode = cast(PayloadMode) i;
            return true;
        }
    return false;
}

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
ulong seedWorker(ulong seed, int workerId) @safe nothrow @nogc
{
    return seed + cast(ulong) workerId + 1;
}

private ulong splitmix64(ref ulong state) @safe nothrow @nogc
{
    state += 0x9E3779B97F4A7C15UL;
    ulong z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
    return z ^ (z >> 31);
}

/// Fills `buf` from the operating-system CSPRNG. The syscall returns
/// at most ~33 MiB per call and may return short on a signal, so the
/// fill loops until every byte is in place.
bool fillRandom(scope ubyte[] buf) @trusted nothrow @nogc
{
    size_t off = 0;
    while (off < buf.length)
    {
        immutable r = getrandom(&buf[off], buf.length - off, 0);
        if (r <= 0)
            return false;
        off += cast(size_t) r;
    }
    return true;
}

/// Writes one plaintext buffer according to the payload mode. The
/// fixed and rotating modes draw from the seeded generator when the
/// run is seeded and from the OS CSPRNG otherwise; the pattern modes
/// are deterministic regardless of the seed. Returns false when the
/// CSPRNG fails.
bool fillPayload(PayloadMode mode, bool seeded, ref ulong rng,
        scope ubyte[] buf) @trusted nothrow @nogc
{
    final switch (mode)
    {
    case PayloadMode.fixed:
    case PayloadMode.rotating:
        if (!seeded)
            return fillRandom(buf);
        for (size_t i = 0; i < buf.length; i += 8)
        {
            immutable v = splitmix64(rng);
            immutable take = buf.length - i < 8 ? buf.length - i : 8;
            auto src = (cast(const(ubyte)*)&v)[0 .. take];
            buf[i .. i + take] = src[];
        }
        return true;
    case PayloadMode.patternZero:
        buf[] = 0x00;
        return true;
    case PayloadMode.patternFF:
        buf[] = 0xFF;
        return true;
    case PayloadMode.patternAscii:
        foreach (i, ref b; buf)
            b = cast(ubyte)('A' + (i % 26));
        return true;
    }
}
