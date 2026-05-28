// Command eitb runs every wrapper example, also wrapping the ITB
// ciphertext in one of PRF-grade outer stream ciphers in CTR mode,
// so the on-wire bytes look like generic outer cipher output rather
// than ITB native output. Outer CTR mode cipher hides ITB nonce,
// WxH and 32-byte streamID prefix under AEAD mode.
//
// Mirrors github.com/everanium/itb/tools/eitb/main.go for the D
// binding. Each example produces a non-trivial random plaintext,
// wraps the ITB ciphertext under the chosen outer cipher, hands
// the wrapped bytes to a "receiver" path that unwraps and decrypts,
// and verifies sha256 + byte-equality of the recovered plaintext
// against the original plaintext.
//
// Usage:
//   ./eitb              # run every example × every cipher (72 cells)
//   ./eitb --help       # print help
//   ./eitb --example=message --cipher=aescmac
module eitb;

import std.algorithm.searching : canFind;
import std.bitmanip : nativeToLittleEndian, littleEndianToNative;
import std.digest.sha : SHA256, sha256Of, toHexString;
import std.format : format;
import std.getopt : config, defaultGetoptPrinter, getopt;
import std.range : chunks;
import std.stdio : writefln, writeln;

import itb;
import itb.cipher : encrypt, decrypt, encryptAuth, decryptAuth;
import itb.mac : MAC;
import itb.seed : Seed;
import itb.streams :
    DEFAULT_CHUNK_SIZE,
    encryptStreamAuth,
    decryptStreamAuth;

immutable size_t MSG_PLAINTEXT_LEN    = 1024;
immutable size_t STREAM_PLAINTEXT_LEN = 64 * 1024;
immutable size_t STREAM_CHUNK_SIZE    = 16 * 1024;

ubyte[] csprngBytes(size_t n) @trusted
{
    import std.random : unpredictableSeed;
    auto buf = new ubyte[n];
    size_t off = 0;
    while (off < n)
    {
        uint v = unpredictableSeed();
        size_t take = (n - off) < 4 ? (n - off) : 4;
        foreach (k; 0 .. take)
            buf[off + k] = cast(ubyte)((v >> (8 * k)) & 0xFF);
        off += take;
    }
    return buf;
}

string sha256Hex(const(ubyte)[] data) @trusted
{
    auto h = sha256Of(data);
    return cast(string) toHexString(h)[0 .. 16].idup;
}

// Result of one example × one cipher run.
struct Cell
{
    string exampleName;
    string cipherName;
    bool   ok;
    string err;
    size_t wireLen;
    size_t ptLen;
}

alias RunFn = Cell function(Cipher cipher, const(ubyte)[] plaintext) @trusted;

struct Example
{
    string name;
    string description;
    size_t plaintextLen;
    RunFn  run;
}

// ---------------------------------------------------------------------------
// 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)
//
// Sender uses Encryptor.encryptStreamAuth(reader, writer, chunk_size) — the
// 32-byte stream prefix + per-chunk wire flows out through the writer
// delegate. The format-deniability wrap intercepts via WrapStreamWriter:
// ITB writes its bytestream into the wrap-writer's update path, which
// prefixes a fresh outer cipher nonce on the wire and XOR-encrypts every
// byte under (key, nonce). Receiver reverses with UnwrapStreamReader feeding
// decryptStreamAuth.
// ---------------------------------------------------------------------------

Cell runAEADEasyIO(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "aead-easy-io";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        auto enc = Encryptor("areion512", 1024, "hmac-blake3", 1);
        scope(exit) enc.close();
        enc.setNonceBits(512);
        enc.setBarrierFill(4);
        enc.setBitSoup(1);
        enc.setLockSoup(1);
        enc.setLockBatch(1);

        auto outerKey = wrapperGenerateKey(cipher);

        // Sender — wrap writer flowing into wireBuf.
        ubyte[] wireBuf;
        {
            auto ww = WrapStreamWriter(cipher, outerKey);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;

            size_t readOff = 0;
            size_t reader(ubyte[] buf) @trusted
            {
                if (readOff >= plaintext.length) return 0;
                size_t take = (plaintext.length - readOff < buf.length)
                              ? plaintext.length - readOff : buf.length;
                buf[0 .. take] = plaintext[readOff .. readOff + take];
                readOff += take;
                return take;
            }

            void writer(const(ubyte)[] chunk) @trusted
            {
                wireBuf ~= ww.update(chunk);
            }

            enc.encryptStreamAuth(&reader, &writer, STREAM_CHUNK_SIZE);
        }
        c.wireLen = wireBuf.length;

        // Receiver — unwrap reader feeding decryptStreamAuth.
        size_t nlen = nonceSize(cipher);
        auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
        scope(exit) ur.close();

        ubyte[] decryptedAccum = ur.update(wireBuf[nlen .. $]);
        size_t readOff = 0;
        size_t reader(ubyte[] buf) @trusted
        {
            if (readOff >= decryptedAccum.length) return 0;
            size_t take = (decryptedAccum.length - readOff < buf.length)
                          ? decryptedAccum.length - readOff : buf.length;
            buf[0 .. take] = decryptedAccum[readOff .. readOff + take];
            readOff += take;
            return take;
        }
        ubyte[] recovered;
        void writer(const(ubyte)[] chunk) @trusted
        {
            recovered ~= chunk;
        }
        enc.decryptStreamAuth(&reader, &writer, STREAM_CHUNK_SIZE);

        c.ok = recovered == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(recovered) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
// ---------------------------------------------------------------------------

Cell runAEADLowLevelIO(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "aead-lowlevel-io";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        setNonceBits(512);
        setBarrierFill(4);
        setBitSoup(1);
        setLockSoup(1);
        setLockBatch(1);

        auto noise = Seed("areion512", 1024);
        auto data  = Seed("areion512", 1024);
        auto start = Seed("areion512", 1024);
        auto macKey = csprngBytes(32);
        auto mac = MAC("hmac-blake3", macKey);

        auto outerKey = wrapperGenerateKey(cipher);

        ubyte[] wireBuf;
        {
            auto ww = WrapStreamWriter(cipher, outerKey);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;

            size_t readOff = 0;
            size_t reader(ubyte[] buf) @trusted
            {
                if (readOff >= plaintext.length) return 0;
                size_t take = (plaintext.length - readOff < buf.length)
                              ? plaintext.length - readOff : buf.length;
                buf[0 .. take] = plaintext[readOff .. readOff + take];
                readOff += take;
                return take;
            }
            void writer(const(ubyte)[] chunk) @trusted
            {
                wireBuf ~= ww.update(chunk);
            }
            encryptStreamAuth(noise, data, start, mac,
                &reader, &writer, STREAM_CHUNK_SIZE);
        }
        c.wireLen = wireBuf.length;

        size_t nlen = nonceSize(cipher);
        auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
        scope(exit) ur.close();
        ubyte[] decryptedAccum = ur.update(wireBuf[nlen .. $]);
        size_t readOff = 0;
        size_t reader(ubyte[] buf) @trusted
        {
            if (readOff >= decryptedAccum.length) return 0;
            size_t take = (decryptedAccum.length - readOff < buf.length)
                          ? decryptedAccum.length - readOff : buf.length;
            buf[0 .. take] = decryptedAccum[readOff .. readOff + take];
            readOff += take;
            return take;
        }
        ubyte[] recovered;
        void writer(const(ubyte)[] chunk) @trusted
        {
            recovered ~= chunk;
        }
        decryptStreamAuth(noise, data, start, mac,
            &reader, &writer, STREAM_CHUNK_SIZE);

        c.ok = recovered == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(recovered) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 3. Streaming Easy (No MAC, User-Driven Loop)
//
// Per-chunk Encryptor.encrypt / decrypt with caller-side framing. Each chunk
// is emitted as `u32_LE_len || ct` through the wrap-writer's update; both
// the length prefix and the body XOR through the keystream so neither
// appears in cleartext on the wire.
// ---------------------------------------------------------------------------

Cell runNoAEADEasyUserLoop(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "noaead-easy-userloop";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        auto enc = Encryptor("areion512", 1024, null, 1);
        scope(exit) enc.close();
        enc.setNonceBits(512);
        enc.setBarrierFill(4);
        enc.setBitSoup(1);
        enc.setLockSoup(1);
        enc.setLockBatch(1);

        auto outerKey = wrapperGenerateKey(cipher);

        ubyte[] wireBuf;
        {
            auto ww = WrapStreamWriter(cipher, outerKey);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;

            size_t off = 0;
            while (off < plaintext.length)
            {
                size_t take = (plaintext.length - off < STREAM_CHUNK_SIZE)
                              ? plaintext.length - off : STREAM_CHUNK_SIZE;
                auto ct = enc.encrypt(plaintext[off .. off + take]).dup;
                ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
                wireBuf ~= ww.update(lenBytes[]);
                wireBuf ~= ww.update(ct);
                off += take;
            }
        }
        c.wireLen = wireBuf.length;

        // Receiver — unwrap entire wire, then walk u32_LE-prefixed chunks.
        size_t nlen = nonceSize(cipher);
        auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
        scope(exit) ur.close();
        auto decryptedAll = ur.update(wireBuf[nlen .. $]);

        ubyte[] recovered;
        size_t pos = 0;
        while (pos < decryptedAll.length)
        {
            ubyte[4] lenBytes = decryptedAll[pos .. pos + 4][0 .. 4];
            uint clen = littleEndianToNative!uint(lenBytes);
            pos += 4;
            auto ct = decryptedAll[pos .. pos + clen];
            pos += clen;
            recovered ~= enc.decrypt(ct).dup;
        }

        c.ok = recovered == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(recovered) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 4. Streaming Low-Level (No MAC, User-Driven Loop)
// ---------------------------------------------------------------------------

Cell runNoAEADLowLevelUserLoop(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "noaead-lowlevel-userloop";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        setNonceBits(512);
        setBarrierFill(4);
        setBitSoup(1);
        setLockSoup(1);
        setLockBatch(1);

        auto noise = Seed("areion512", 1024);
        auto data  = Seed("areion512", 1024);
        auto start = Seed("areion512", 1024);

        auto outerKey = wrapperGenerateKey(cipher);

        ubyte[] wireBuf;
        {
            auto ww = WrapStreamWriter(cipher, outerKey);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;

            size_t off = 0;
            while (off < plaintext.length)
            {
                size_t take = (plaintext.length - off < STREAM_CHUNK_SIZE)
                              ? plaintext.length - off : STREAM_CHUNK_SIZE;
                auto ct = encrypt(noise, data, start, plaintext[off .. off + take]);
                ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
                wireBuf ~= ww.update(lenBytes[]);
                wireBuf ~= ww.update(ct);
                off += take;
            }
        }
        c.wireLen = wireBuf.length;

        size_t nlen = nonceSize(cipher);
        auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
        scope(exit) ur.close();
        auto decryptedAll = ur.update(wireBuf[nlen .. $]);

        ubyte[] recovered;
        size_t pos = 0;
        while (pos < decryptedAll.length)
        {
            ubyte[4] lenBytes = decryptedAll[pos .. pos + 4][0 .. 4];
            uint clen = littleEndianToNative!uint(lenBytes);
            pos += 4;
            auto ct = decryptedAll[pos .. pos + clen];
            pos += clen;
            recovered ~= decrypt(noise, data, start, ct);
        }

        c.ok = recovered == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(recovered) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 5. Single Message — Easy: Areion-SoEM-512 (No MAC).
//
// One enc.encrypt() call → one ITB blob. wrapInPlace seals the whole blob
// in place: nonce || ks-XOR(blob). The commented `wrap` alternative
// allocates a fresh wire buffer (preserves immutability of `encrypted`).
// ---------------------------------------------------------------------------

Cell runMessageEasyNoMAC(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "message-easy-nomac";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        auto enc = Encryptor("areion512", 2048, null, 1);
        scope(exit) enc.close();
        enc.setNonceBits(512);
        enc.setBarrierFill(4);
        enc.setBitSoup(1);
        enc.setLockSoup(1);
        enc.setLockBatch(1);

        auto encrypted = enc.encrypt(plaintext).dup;

        auto outerKey = wrapperGenerateKey(cipher);

        // Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        // auto wire = wrap(cipher, outerKey, encrypted);
        auto nonce = wrapInPlace(cipher, outerKey, encrypted);
        ubyte[] wire;
        wire ~= nonce;
        wire ~= encrypted;
        c.wireLen = wire.length;

        // Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        // auto recovered = unwrap(cipher, outerKey, wire);
        auto recovered = unwrapInPlace(cipher, outerKey, wire);
        auto pt = enc.decrypt(recovered).dup;

        c.ok = pt == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(pt) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 6. Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated).
// ---------------------------------------------------------------------------

Cell runMessageEasyAuth(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "message-easy-auth";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        auto enc = Encryptor("areion512", 2048, "hmac-blake3", 1);
        scope(exit) enc.close();
        enc.setNonceBits(512);
        enc.setBarrierFill(4);
        enc.setBitSoup(1);
        enc.setLockSoup(1);
        enc.setLockBatch(1);

        auto encrypted = enc.encryptAuth(plaintext).dup;

        auto outerKey = wrapperGenerateKey(cipher);

        // Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
        // auto wire = wrap(cipher, outerKey, encrypted);
        auto nonce = wrapInPlace(cipher, outerKey, encrypted);
        ubyte[] wire;
        wire ~= nonce;
        wire ~= encrypted;
        c.wireLen = wire.length;

        // Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
        // auto recovered = unwrap(cipher, outerKey, wire);
        auto recovered = unwrapInPlace(cipher, outerKey, wire);
        auto pt = enc.decryptAuth(recovered).dup;

        c.ok = pt == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(pt) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 7. Single Message — Low-Level: Areion-SoEM-512 (No MAC).
// ---------------------------------------------------------------------------

Cell runMessageLowLevelNoMAC(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "message-lowlevel-nomac";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        setNonceBits(512);
        setBarrierFill(4);
        setBitSoup(1);
        setLockSoup(1);
        setLockBatch(1);

        auto noise = Seed("areion512", 2048);
        auto data  = Seed("areion512", 2048);
        auto start = Seed("areion512", 2048);

        auto encrypted = encrypt(noise, data, start, plaintext);

        auto outerKey = wrapperGenerateKey(cipher);

        // auto wire = wrap(cipher, outerKey, encrypted);
        auto nonce = wrapInPlace(cipher, outerKey, encrypted);
        ubyte[] wire;
        wire ~= nonce;
        wire ~= encrypted;
        c.wireLen = wire.length;

        // auto recovered = unwrap(cipher, outerKey, wire);
        auto recovered = unwrapInPlace(cipher, outerKey, wire);
        auto pt = decrypt(noise, data, start, recovered);

        c.ok = pt == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(pt) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 8. Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3
// (MAC Authenticated).
// ---------------------------------------------------------------------------

Cell runMessageLowLevelAuth(Cipher cipher, const(ubyte)[] plaintext) @trusted
{
    Cell c;
    c.exampleName = "message-lowlevel-auth";
    c.cipherName  = ffiName(cipher);
    c.ptLen       = plaintext.length;

    try
    {
        setNonceBits(512);
        setBarrierFill(4);
        setBitSoup(1);
        setLockSoup(1);
        setLockBatch(1);

        auto noise = Seed("areion512", 2048);
        auto data  = Seed("areion512", 2048);
        auto start = Seed("areion512", 2048);

        auto macKey = csprngBytes(32);
        auto mac = MAC("hmac-blake3", macKey);

        auto encrypted = encryptAuth(noise, data, start, mac, plaintext);

        auto outerKey = wrapperGenerateKey(cipher);

        // auto wire = wrap(cipher, outerKey, encrypted);
        auto nonce = wrapInPlace(cipher, outerKey, encrypted);
        ubyte[] wire;
        wire ~= nonce;
        wire ~= encrypted;
        c.wireLen = wire.length;

        // auto recovered = unwrap(cipher, outerKey, wire);
        auto recovered = unwrapInPlace(cipher, outerKey, wire);
        auto pt = decryptAuth(noise, data, start, mac, recovered);

        c.ok = pt == plaintext;
        if (!c.ok)
            c.err = "plaintext mismatch (sha256 pt="
                ~ sha256Hex(plaintext) ~ " rcv=" ~ sha256Hex(pt) ~ ")";
    }
    catch (Throwable t)
    {
        c.ok = false;
        c.err = t.msg;
    }
    return c;
}

void main(string[] args)
{
    string exampleFilter;
    string cipherFilter;
    bool   verbose;

    auto helpInfo = getopt(args,
        config.passThrough,
        "example",  "Run only examples whose name contains this substring.", &exampleFilter,
        "cipher",   "Run only the given outer cipher (one of CIPHER_NAMES).",  &cipherFilter,
        "v|verbose","Print per-run plaintext / recovered sha256 hashes.",     &verbose);

    if (helpInfo.helpWanted)
    {
        defaultGetoptPrinter("eitb — wrapper × cipher example matrix runner.", helpInfo.options);
        return;
    }

    setMaxWorkers(0);

    Example[] examples = [
        Example("aead-easy-io",
            "Streaming AEAD Easy (MAC Authenticated, IO-Driven)",
            STREAM_PLAINTEXT_LEN, &runAEADEasyIO),
        Example("aead-lowlevel-io",
            "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)",
            STREAM_PLAINTEXT_LEN, &runAEADLowLevelIO),
        Example("noaead-easy-userloop",
            "Streaming Easy (No MAC, User-Driven Loop)",
            STREAM_PLAINTEXT_LEN, &runNoAEADEasyUserLoop),
        Example("noaead-lowlevel-userloop",
            "Streaming Low-Level (No MAC, User-Driven Loop)",
            STREAM_PLAINTEXT_LEN, &runNoAEADLowLevelUserLoop),
        Example("message-easy-nomac",
            "Easy: Areion-SoEM-512 (No MAC, Single Message)",
            MSG_PLAINTEXT_LEN, &runMessageEasyNoMAC),
        Example("message-easy-auth",
            "Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
            MSG_PLAINTEXT_LEN, &runMessageEasyAuth),
        Example("message-lowlevel-nomac",
            "Low-Level: Areion-SoEM-512 (No MAC, Single Message)",
            MSG_PLAINTEXT_LEN, &runMessageLowLevelNoMAC),
        Example("message-lowlevel-auth",
            "Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)",
            MSG_PLAINTEXT_LEN, &runMessageLowLevelAuth),
    ];

    int pass = 0;
    int fail = 0;

    foreach (ref ex; examples)
    {
        if (exampleFilter.length > 0 && !canFind(ex.name, exampleFilter))
            continue;
        foreach (cipher; CIPHER_NAMES)
        {
            string cn = ffiName(cipher);
            if (cipherFilter.length > 0 && cn != cipherFilter)
                continue;

            auto plaintext = csprngBytes(ex.plaintextLen);
            auto cell = ex.run(cipher, plaintext);

            string tag = cell.ok ? "PASS" : "FAIL";
            string line = format("[%s] %-26s + %-8s   pt=%d wire=%d",
                tag, cell.exampleName, cell.cipherName, cell.ptLen, cell.wireLen);
            if (!cell.ok)
                line ~= "  err: " ~ cell.err;
            writeln(line);
            if (verbose && cell.ok)
            {
                writefln("       pt sha256:  %s", sha256Hex(plaintext));
            }

            if (cell.ok)
                pass++;
            else
                fail++;
        }
    }

    writeln();
    writefln("=== Summary: %d PASS, %d FAIL ===", pass, fail);

    import core.stdc.stdlib : exit;
    if (fail > 0)
        exit(1);
}
