/// The profile record — the JSON object libitb accepts in
/// [itb.pipeline.register], returns from [itb.pipeline.lookup] and
/// [itb.pipeline.inspect], and embeds in every blob.
///
/// The record is a plain data carrier: no field is validated on the D
/// side. Field rules (mode / width / hash-width agreement, MAC name,
/// palette contents, …) are enforced by libitb at `register` and
/// `load`; a rejected record surfaces as [itb.error.ItbException]
/// carrying the status code plus the `ITB_LastError` diagnostic.
module itb.profile;

import std.json : JSONType, JSONValue, parseJSON;

/// Resolved shape of a Triple Pipeline. Serialises to the libitb
/// profile JSON object (`name`, `mode`, `width`, `hash`, `hashes`,
/// `keybits`, `mac`, `tagstub`, `chunk`, `wrapper`, `outer`,
/// `parallax`, `palette`, `segment`); optional keys are omitted when
/// empty / zero and decode as their defaults when absent.
struct Profile
{
    /// Registry label. Empty on a record built by hand; filled by
    /// `lookup` / `inspect`. When non-empty it must equal the `name`
    /// argument of `register`.
    string name;
    /// Pipeline mode (`singlemsg-mac`, `singlemsg-nomac`,
    /// `streaming-aead`, `streaming-noaead`, `blob-only`).
    string mode;
    /// Inner hash width in bits (128 / 256 / 512).
    long width;
    /// Single inner-hash primitive name; empty on a mixed profile.
    string innerHash;
    /// Eight-slot inner-hash constellation for mixed profiles; empty
    /// on a single-primitive profile.
    string[] mixedHashes;
    /// Session key width in bits.
    long keyBits;
    /// MAC name; empty for No MAC modes.
    string macName;
    /// MAC tag stub size; 0 for the profile default.
    long tagStubSize;
    /// Streaming chunk size; 0 for the library default.
    long chunkSize;
    /// Whether the format-deniability wrapper layer is on.
    bool wrapper;
    /// Outer cipher name; empty when the wrapper layer is off.
    string outerCipher;
    /// Whether the parallax layer is on.
    bool parallax;
    /// Parallax palette; empty when the parallax layer is off.
    string[] parallaxPalette;
    /// Parallax segment size; 0 for the library default.
    long parallaxSegmentSize;

    /// Decodes a profile JSON object as returned by libitb.
    static Profile fromJson(string json) @safe
    {
        auto v = parseJSON(json);
        Profile p;
        p.name = str(v, "name");
        p.mode = str(v, "mode");
        p.width = num(v, "width");
        p.innerHash = str(v, "hash");
        p.mixedHashes = list(v, "hashes");
        p.keyBits = num(v, "keybits");
        p.macName = str(v, "mac");
        p.tagStubSize = num(v, "tagstub");
        p.chunkSize = num(v, "chunk");
        p.wrapper = flag(v, "wrapper");
        p.outerCipher = str(v, "outer");
        p.parallax = flag(v, "parallax");
        p.parallaxPalette = list(v, "palette");
        p.parallaxSegmentSize = num(v, "segment");
        return p;
    }

    /// Encodes the record as the profile JSON object libitb accepts.
    string toJson() const @safe
    {
        JSONValue v = JSONValue(string[string].init);
        if (name.length) v["name"] = name;
        v["mode"] = mode;
        v["width"] = width;
        if (innerHash.length) v["hash"] = innerHash;
        if (mixedHashes.length) v["hashes"] = JSONValue(mixedHashes.dup);
        v["keybits"] = keyBits;
        if (macName.length) v["mac"] = macName;
        if (tagStubSize) v["tagstub"] = tagStubSize;
        if (chunkSize) v["chunk"] = chunkSize;
        v["wrapper"] = wrapper;
        if (outerCipher.length) v["outer"] = outerCipher;
        v["parallax"] = parallax;
        if (parallaxPalette.length) v["palette"] = JSONValue(parallaxPalette.dup);
        if (parallaxSegmentSize) v["segment"] = parallaxSegmentSize;
        return v.toString();
    }

    private static string str(const ref JSONValue v, string key) @trusted
    {
        auto f = key in v.object;
        return (f !is null && f.type == JSONType.string) ? f.str : "";
    }

    private static long num(const ref JSONValue v, string key) @trusted
    {
        auto f = key in v.object;
        if (f is null)
            return 0;
        return f.type == JSONType.integer ? f.integer
            : (f.type == JSONType.uinteger ? cast(long) f.uinteger : 0);
    }

    private static bool flag(const ref JSONValue v, string key) @trusted
    {
        auto f = key in v.object;
        return f !is null && f.type == JSONType.true_;
    }

    private static string[] list(const ref JSONValue v, string key) @trusted
    {
        auto f = key in v.object;
        if (f is null || f.type != JSONType.array)
            return null;
        string[] out_;
        foreach (e; f.array)
            out_ ~= e.str;
        return out_;
    }
}

@safe unittest
{
    Profile p;
    p.mode = "singlemsg-nomac";
    p.width = 512;
    p.innerHash = "areion512";
    p.keyBits = 1024;
    auto back = Profile.fromJson(p.toJson());
    assert(back == p);
    assert(p.toJson().length > 0);
    // Mixed profiles carry exactly the eight-slot array and no `hash`.
    p.innerHash = "";
    p.mixedHashes = ["a", "b", "c", "d", "e", "f", "g", "h"];
    assert(Profile.fromJson(p.toJson()) == p);
}
