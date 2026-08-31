/// URL-query builder for the opts pass-through string.
///
/// The builder performs no validation — every key and value is
/// rendered into a percent-encoded query string and passed through to
/// Go verbatim; libitb rejects unknown keys or bad values with a
/// diagnostic surfaced via [itb.error.ItbException]. Primitive / MAC /
/// cipher / palette names are opaque strings.
module itb.opts;

@safe:

/// Value-type builder producing the URL-query-encoded opts string
/// consumed by [itb.pipeline.Pipeline.create],
/// [itb.pipeline.Pipeline.open], and
/// [itb.pipeline.registerProfile]. Every setter returns a fresh copy,
/// so call chains on temporaries compose without aliasing.
struct Opts
{
    private string[2][] pairs;

    /// Hex-encodes the parallax master override (`pm`).
    Opts withPermMaster(scope const(ubyte)[] master) const
    {
        return withRaw("pm", hex(master));
    }

    /// Hex-encodes the wrapper master override (`wm`).
    Opts withWrapMaster(scope const(ubyte)[] master) const
    {
        return withRaw("wm", hex(master));
    }

    Opts withParallax(bool on) const
    {
        return withRaw("withParallax", on ? "true" : "false");
    }

    Opts withWrapper(bool on) const
    {
        return withRaw("withWrapper", on ? "true" : "false");
    }

    Opts withMaxWorkers(long n) const
    {
        return withRaw("maxWorkers", dec(n));
    }

    Opts withNonceBits(long n) const
    {
        return withRaw("nonceBits", dec(n));
    }

    Opts withBarrierFill(long n) const
    {
        return withRaw("barrierFill", dec(n));
    }

    Opts withChunkSize(long n) const
    {
        return withRaw("chunkSize", dec(n));
    }

    Opts withKeyBits(long n) const
    {
        return withRaw("keyBits", dec(n));
    }

    Opts withParallaxSegmentSize(long n) const
    {
        return withRaw("parallaxSegmentSize", dec(n));
    }

    Opts withMacName(string name) const
    {
        return withRaw("macName", name);
    }

    Opts withInnerHash(string name) const
    {
        return withRaw("innerHash", name);
    }

    /// Per-call constellation override mirroring the Go-side
    /// `Opts.MixedHashes [8]string` field: the 8 slot names are
    /// comma-joined into the `innerHashes` pass-through key in the
    /// slot order `[noise, lock, data1, data2, data3, start1,
    /// start2, start3]`. Fail-fast validation surfaces at Init on
    /// the Go side; a typo'd slot or width mismatch surfaces with
    /// an error naming the offending slot. When both this and
    /// `withInnerHash` are set, the mixed override wins on the Go
    /// side.
    Opts withInnerHashes(scope const(string)[] names) const
    {
        import std.array : join;

        return withRaw("innerHashes", names.join(","));
    }

    Opts withOuterCipher(string name) const
    {
        return withRaw("outerCipher", name);
    }

    /// Comma-joins the palette names (`parallaxPalette`).
    Opts withParallaxPalette(scope const(string)[] names) const
    {
        import std.array : join;

        return withRaw("parallaxPalette", names.join(","));
    }

    /// Escape hatch appending a raw `key=value` pair. Covers every
    /// key the Go side accepts, including the register-profile
    /// grammar (`mode`, `width`, `innerHashes`, `parallaxOn`,
    /// `wrapperOn`, ...).
    Opts withRaw(string key, string value) const
    {
        Opts r;
        r.pairs = pairs.dup;
        r.pairs ~= [key, value];
        return r;
    }

    /// Renders the accumulated pairs as a query string (no NUL).
    string build() const
    {
        import std.array : join;

        string[] parts;
        parts.reserve(pairs.length);
        foreach (p; pairs)
            parts ~= enc(p[0]) ~ "=" ~ enc(p[1]);
        return parts.join("&");
    }
}

private string dec(long n)
{
    import std.conv : to;

    return n.to!string;
}

/// Minimal percent-encoding: the accepted values are ASCII names,
/// decimal integers, `true` / `false`, hex, and comma-separated
/// lists, so everything outside the URL-safe subset (plus `,`) is
/// escaped byte-wise.
private string enc(string s)
{
    import std.format : format;

    string outStr;
    outStr.reserve(s.length);
    foreach (char b; s)
    {
        if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
            || (b >= '0' && b <= '9')
            || b == '-' || b == '.' || b == '_' || b == '~' || b == ',')
            outStr ~= b;
        else
            outStr ~= format("%%%02X", cast(ubyte) b);
    }
    return outStr;
}

private string hex(scope const(ubyte)[] bytes)
{
    import std.format : format;

    string outStr;
    outStr.reserve(bytes.length * 2);
    foreach (b; bytes)
        outStr ~= format("%02x", b);
    return outStr;
}

@safe unittest
{
    // Typed setters render the expected keys in insertion order.
    auto q = Opts()
        .withPermMaster([0xab, 0x01])
        .withWrapMaster([0xcd, 0xef])
        .withParallax(true)
        .withWrapper(false)
        .withMaxWorkers(4)
        .withNonceBits(512)
        .withBarrierFill(4)
        .withChunkSize(4096)
        .withKeyBits(1024)
        .withParallaxSegmentSize(65_536)
        .withMacName("hmac-blake3")
        .withInnerHash("areion512")
        .withOuterCipher("chacha20")
        .withParallaxPalette(["aescmac", "chacha20", "blake3"])
        .build();
    assert(q == "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&"
        ~ "maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&"
        ~ "keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&"
        ~ "innerHash=areion512&outerCipher=chacha20&"
        ~ "parallaxPalette=aescmac,chacha20,blake3");
}

@safe unittest
{
    // Raw escape hatch percent-encodes everything outside the safe set.
    assert(Opts().withRaw("mode", "a b&c=d%").build() == "mode=a%20b%26c%3Dd%25");
    // Empty builder renders the empty query.
    assert(Opts().build() == "");
}
