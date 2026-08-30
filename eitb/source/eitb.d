/// eitb — command-line demonstrator for the ITB D binding.
///
/// Subcommands:
///
///   eitb version                                   library + binding versions
///   eitb hashes                                    shipped hash primitive roster
///   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
///   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
///
/// `encrypt` prints the session blob to stderr as hex; feed that hex
/// back to `decrypt` on the receiving side.
module eitb;

import std.algorithm : startsWith;
import std.file : mkdirRecurse, read, write;
import std.format : format;
import std.path : dirName;
import std.stdio : stderr, writefln, writeln;

import itb;

int main(string[] args)
{
    // Go-runtime pacing caps applied up front so ad-hoc shell use of
    // large files stays under a bounded heap.
    cast(void) setMemoryLimit(512L * 1024 * 1024);
    cast(void) setGCPercent(20);

    try
    {
        if (args.length >= 2)
        {
            switch (args[1])
            {
            case "version":
                if (args.length == 2)
                    return cmdVersion();
                break;
            case "hashes":
                if (args.length == 2)
                    return cmdHashes();
                break;
            case "encrypt":
                if (args.length == 5)
                    return cmdEncrypt(args[2], args[3], args[4]);
                break;
            case "decrypt":
                if (args.length == 6)
                    return cmdDecrypt(args[2], args[3], args[4], args[5]);
                break;
            default:
                break;
            }
        }
    }
    catch (Exception e)
    {
        stderr.writeln("eitb: ", e.msg);
        return 1;
    }
    stderr.writeln("usage: eitb version\n"
        ~ "       eitb hashes\n"
        ~ "       eitb encrypt <profile> <in-file> <out-file>\n"
        ~ "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>");
    return 2;
}

int cmdVersion()
{
    writeln("libitb ", libitbVersion());
    writeln("itb-d ", bindingVersion);
    return 0;
}

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
bool isStreamingProfile(string profile) @safe pure nothrow
{
    return profile.startsWith("streaming-");
}

// Recursively create the parent directory of `path` (mkdir -p).
void ensureParentDir(string path)
{
    auto parent = dirName(path);
    if (parent.length > 0 && parent != ".")
        mkdirRecurse(parent);
}

int cmdEncrypt(string profile, string infile, string outfile)
{
    auto plain = cast(ubyte[]) read(infile);
    auto pipe = Pipeline.create(profile);
    auto wire = isStreamingProfile(profile)
        ? pipe.encryptStreamOneShot(plain)
        : pipe.encryptMessage(plain);
    ensureParentDir(outfile);
    write(outfile, wire);
    stderr.writeln(hexEncode(pipe.blob));
    writefln("encrypted %s -> %s (%d -> %d bytes)",
        infile, outfile, plain.length, wire.length);
    return 0;
}

int cmdDecrypt(string profile, string blobHex, string infile, string outfile)
{
    auto blob = hexDecode(blobHex);
    auto wire = cast(ubyte[]) read(infile);
    auto pipe = Pipeline.open(profile, blob);
    auto plain = isStreamingProfile(profile)
        ? pipe.decryptStreamOneShot(wire)
        : pipe.decryptMessage(wire);
    ensureParentDir(outfile);
    write(outfile, plain);
    writefln("decrypted %s -> %s (%d -> %d bytes)",
        infile, outfile, wire.length, plain.length);
    return 0;
}

string hexEncode(scope const(ubyte)[] bytes)
{
    string outStr;
    outStr.reserve(bytes.length * 2);
    foreach (b; bytes)
        outStr ~= format("%02x", b);
    return outStr;
}

ubyte[] hexDecode(string s)
{
    import std.conv : to;

    if (s.length % 2 != 0)
        throw new Exception("blob hex has odd length");
    auto outBuf = new ubyte[s.length / 2];
    foreach (i, ref b; outBuf)
        b = s[i * 2 .. i * 2 + 2].to!ubyte(16);
    return outBuf;
}

// ─── hashes — diagnostic registry iteration ────────────────────────
//
// The binding library deliberately exposes no primitive enumeration;
// this CLI diagnostic declares the three iteration symbols itself so
// the shipped roster can be inspected from the shell.

private extern (C) @system @nogc nothrow
{
    int ITB_HashCount();
    int ITB_HashName(int i, char* outBuf, size_t capBytes, size_t* outLen);
    int ITB_HashWidth(int i);
}

int cmdHashes() @trusted
{
    immutable n = ITB_HashCount();
    foreach (i; 0 .. n)
    {
        char[128] buf;
        size_t len = 0;
        immutable rc = ITB_HashName(i, &buf[0], buf.length, &len);
        if (rc != 0)
            throw new Exception(format("ITB_HashName(%d) failed with status %d", i, rc));
        // len includes the trailing NUL.
        immutable name = buf[0 .. len > 0 ? len - 1 : 0].idup;
        writefln("%2d  %-12s %d bits", i, name, ITB_HashWidth(i));
    }
    return 0;
}
