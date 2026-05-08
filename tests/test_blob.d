// Phase-4 + Phase-5 mirror: Native Blob (Single + Triple) round-trip,
// width matrix, slot resolution, mode mismatch, malformed payload, and
// version-too-new rejection.
//
// Mirrors bindings/rust/tests/test_blob.rs file-for-file.
//
// Compile recipe: see top-level dub.json `cshared` rpath; or the dmd
// invocation pattern in `scratch/smoke_phase4.d`.
import std.algorithm.iteration : map;
import std.array : array;
import std.exception : collectException;
import std.range : iota;
import std.stdio : writeln;
import itb;

// --------------------------------------------------------------------
// with_globals — set non-default globals around the test body, then
// restore on exit. Mirrors the Rust binding's `with_globals` /
// `reset_globals` / `assert_globals_restored` helpers.
// --------------------------------------------------------------------

struct GlobalsSnapshot
{
    int nonceBits;
    int barrierFill;
    int bitSoup;
    int lockSoup;
}

GlobalsSnapshot snapshotGlobals()
{
    return GlobalsSnapshot(
        getNonceBits(), getBarrierFill(), getBitSoup(), getLockSoup());
}

void restoreGlobals(GlobalsSnapshot s)
{
    setNonceBits(s.nonceBits);
    setBarrierFill(s.barrierFill);
    setBitSoup(s.bitSoup);
    setLockSoup(s.lockSoup);
}

void engageNonDefaultGlobals()
{
    setNonceBits(512);
    setBarrierFill(4);
    setBitSoup(1);
    setLockSoup(1);
}

void resetGlobalsToDefaults()
{
    setNonceBits(128);
    setBarrierFill(1);
    setBitSoup(0);
    setLockSoup(0);
}

void assertGlobalsRestored(int nonce, int barrier, int bs, int ls)
{
    assert(getNonceBits() == nonce, "NonceBits not restored");
    assert(getBarrierFill() == barrier, "BarrierFill not restored");
    assert(getBitSoup() == bs, "BitSoup not restored");
    assert(getLockSoup() == ls, "LockSoup not restored");
}

// --------------------------------------------------------------------
// Phase-4 baseline tests — Blob256 single round-trip + slot helpers.
// --------------------------------------------------------------------

void testBlob256SingleExportImportRoundtrip()
{
    // Sender: stage hash keys + components into a fresh Blob256.
    auto sender = Blob256();

    ubyte[] keyN = iota(32).map!(i => cast(ubyte)(0xa0 ^ i)).array;
    ubyte[] keyD = iota(32).map!(i => cast(ubyte)(0xb0 ^ i)).array;
    ubyte[] keyS = iota(32).map!(i => cast(ubyte)(0xc0 ^ i)).array;
    ulong[] compsN = iota(16).map!(i => cast(ulong)(0x1000 + i)).array;
    ulong[] compsD = iota(16).map!(i => cast(ulong)(0x2000 + i)).array;
    ulong[] compsS = iota(16).map!(i => cast(ulong)(0x3000 + i)).array;
    ubyte[] macKey = iota(32).map!(i => cast(ubyte)(0xd0 ^ i)).array;

    sender.setKey(BlobSlot.N, keyN);
    sender.setComponents(BlobSlot.N, compsN);
    sender.setKey(BlobSlot.D, keyD);
    sender.setComponents(BlobSlot.D, compsD);
    sender.setKey(BlobSlot.S, keyS);
    sender.setComponents(BlobSlot.S, compsS);
    sender.setMACKey(macKey);
    sender.setMACName("kmac256");

    auto blobBytes = sender.exportToBytes(BlobOpt.MAC);
    assert(blobBytes.length > 0, "exported blob must be non-empty");

    // Receiver: a fresh Blob256 imports the bytes and the slot
    // contents must match the originals.
    auto receiver = Blob256();
    receiver.importFromBytes(blobBytes);

    assert(receiver.width() == 256);
    assert(receiver.mode() == 1, "mode must be Single after Single import");

    assert(receiver.getKey(BlobSlot.N) == keyN);
    assert(receiver.getKey(BlobSlot.D) == keyD);
    assert(receiver.getKey(BlobSlot.S) == keyS);
    assert(receiver.getComponents(BlobSlot.N) == compsN);
    assert(receiver.getComponents(BlobSlot.D) == compsD);
    assert(receiver.getComponents(BlobSlot.S) == compsS);
    assert(receiver.getMACKey() == macKey);
    assert(receiver.getMACName() == "kmac256",
        "MAC name must round-trip with NUL stripped");
}

void testBlob256FreshlyConstructedHasUnsetMode()
{
    auto b = Blob256();
    assert(b.width() == 256);
    assert(b.mode() == 0, "fresh Blob has mode == 0 (unset)");
}

void testBlobSlotFromNameRoundTrip()
{
    assert(slotFromName("n") == BlobSlot.N);
    assert(slotFromName("D") == BlobSlot.D);
    assert(slotFromName("S3") == BlobSlot.S3);
    auto err = collectException!ITBError(slotFromName("nope"));
    assert(err !is null, "slotFromName('nope') must throw");
    assert(err.statusCode == Status.BadInput);
}

void testBlobDropDoesNotPanic()
{
    foreach (i; 0 .. 16)
    {
        auto _b = Blob256();
    }
}

// --------------------------------------------------------------------
// Phase-5 extension — width matrix + full mode coverage.
// --------------------------------------------------------------------

void testConstructEachWidth()
{
    auto b1 = Blob128();
    assert(b1.width() == 128);
    assert(b1.mode() == 0);
    assert(b1.handle() != 0);

    auto b2 = Blob256();
    assert(b2.width() == 256);
    assert(b2.mode() == 0);
    assert(b2.handle() != 0);

    auto b3 = Blob512();
    assert(b3.width() == 512);
    assert(b3.mode() == 0);
    assert(b3.handle() != 0);
}

// ----- Blob512 Single full matrix (LockSeed × MAC) -----------------

void blob512SingleOne(const(ubyte)[] plaintext, bool withLS, bool withMAC)
{
    enum primitive = "areion512";
    enum keyBits = 2048;

    auto ns = Seed(primitive, keyBits);
    auto ds = Seed(primitive, keyBits);
    auto ss = Seed(primitive, keyBits);

    Seed ls;
    bool hasLS = false;
    if (withLS)
    {
        ls = Seed(primitive, keyBits);
        ns.attachLockSeed(ls);
        hasLS = true;
    }

    ubyte[] macKey = iota(32).map!(i => cast(ubyte)(0x55 ^ i)).array;
    ubyte[] ct;
    if (withMAC)
    {
        auto mac = MAC("kmac256", macKey);
        ct = encryptAuth(ns, ds, ss, mac, plaintext);
    }
    else
    {
        ct = encrypt(ns, ds, ss, plaintext);
    }

    auto src = Blob512();
    src.setKey(BlobSlot.N, ns.hashKey());
    src.setKey(BlobSlot.D, ds.hashKey());
    src.setKey(BlobSlot.S, ss.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D, ds.components());
    src.setComponents(BlobSlot.S, ss.components());
    if (hasLS)
    {
        src.setKey(BlobSlot.L, ls.hashKey());
        src.setComponents(BlobSlot.L, ls.components());
    }
    if (withMAC)
    {
        src.setMACKey(macKey);
        src.setMACName("kmac256");
    }

    BlobOpt opts = BlobOpt.None;
    if (withLS) opts = cast(BlobOpt) (opts | BlobOpt.LockSeed);
    if (withMAC) opts = cast(BlobOpt) (opts | BlobOpt.MAC);
    auto blob = src.exportToBytes(opts);

    resetGlobalsToDefaults();
    auto dst = Blob512();
    dst.importFromBytes(blob);
    assert(dst.mode() == 1, "Single import must yield mode == 1");
    assertGlobalsRestored(512, 4, 1, 1);

    auto ns2 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.N), dst.getKey(BlobSlot.N));
    auto ds2 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.D), dst.getKey(BlobSlot.D));
    auto ss2 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.S), dst.getKey(BlobSlot.S));

    Seed ls2;
    if (hasLS)
    {
        ls2 = Seed.fromComponents(primitive,
            dst.getComponents(BlobSlot.L), dst.getKey(BlobSlot.L));
        ns2.attachLockSeed(ls2);
    }

    ubyte[] pt;
    if (withMAC)
    {
        assert(dst.getMACName() == "kmac256");
        assert(dst.getMACKey() == macKey);
        auto mac2 = MAC("kmac256", dst.getMACKey());
        pt = decryptAuth(ns2, ds2, ss2, mac2, ct);
    }
    else
    {
        pt = decrypt(ns2, ds2, ss2, ct);
    }
    assert(pt == plaintext, "Single Blob512 roundtrip mismatch");
}

void testBlob512SingleFullMatrix()
{
    auto plaintext = cast(ubyte[]) "rs blob512 single round-trip payload".dup;
    auto orig = snapshotGlobals();
    foreach (withLS; [false, true])
    {
        foreach (withMAC; [false, true])
        {
            engageNonDefaultGlobals();
            blob512SingleOne(plaintext, withLS, withMAC);
            restoreGlobals(orig);
        }
    }
}

// ----- Blob512 Triple full matrix --------------------------------------

void blob512TripleOne(const(ubyte)[] plaintext, bool withLS, bool withMAC)
{
    enum primitive = "areion512";
    enum keyBits = 2048;

    auto ns = Seed(primitive, keyBits);
    auto ds1 = Seed(primitive, keyBits);
    auto ds2 = Seed(primitive, keyBits);
    auto ds3 = Seed(primitive, keyBits);
    auto ss1 = Seed(primitive, keyBits);
    auto ss2 = Seed(primitive, keyBits);
    auto ss3 = Seed(primitive, keyBits);

    Seed ls;
    bool hasLS = false;
    if (withLS)
    {
        ls = Seed(primitive, keyBits);
        ns.attachLockSeed(ls);
        hasLS = true;
    }

    ubyte[] macKey = iota(32).map!(i => cast(ubyte)(0x37 ^ i)).array;
    ubyte[] ct;
    if (withMAC)
    {
        auto mac = MAC("kmac256", macKey);
        ct = encryptAuthTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, mac, plaintext);
    }
    else
    {
        ct = encryptTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext);
    }

    auto src = Blob512();
    src.setKey(BlobSlot.N, ns.hashKey());
    src.setKey(BlobSlot.D1, ds1.hashKey());
    src.setKey(BlobSlot.D2, ds2.hashKey());
    src.setKey(BlobSlot.D3, ds3.hashKey());
    src.setKey(BlobSlot.S1, ss1.hashKey());
    src.setKey(BlobSlot.S2, ss2.hashKey());
    src.setKey(BlobSlot.S3, ss3.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D1, ds1.components());
    src.setComponents(BlobSlot.D2, ds2.components());
    src.setComponents(BlobSlot.D3, ds3.components());
    src.setComponents(BlobSlot.S1, ss1.components());
    src.setComponents(BlobSlot.S2, ss2.components());
    src.setComponents(BlobSlot.S3, ss3.components());
    if (hasLS)
    {
        src.setKey(BlobSlot.L, ls.hashKey());
        src.setComponents(BlobSlot.L, ls.components());
    }
    if (withMAC)
    {
        src.setMACKey(macKey);
        src.setMACName("kmac256");
    }

    BlobOpt opts = BlobOpt.None;
    if (withLS) opts = cast(BlobOpt) (opts | BlobOpt.LockSeed);
    if (withMAC) opts = cast(BlobOpt) (opts | BlobOpt.MAC);
    auto blob = src.exportTriple(opts);

    resetGlobalsToDefaults();
    auto dst = Blob512();
    dst.importTriple(blob);
    assert(dst.mode() == 3, "Triple import must yield mode == 3");
    assertGlobalsRestored(512, 4, 1, 1);

    auto ns2  = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.N),  dst.getKey(BlobSlot.N));
    auto ds12 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.D1), dst.getKey(BlobSlot.D1));
    auto ds22 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.D2), dst.getKey(BlobSlot.D2));
    auto ds32 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.D3), dst.getKey(BlobSlot.D3));
    auto ss12 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.S1), dst.getKey(BlobSlot.S1));
    auto ss22 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.S2), dst.getKey(BlobSlot.S2));
    auto ss32 = Seed.fromComponents(primitive,
        dst.getComponents(BlobSlot.S3), dst.getKey(BlobSlot.S3));

    Seed ls2;
    if (hasLS)
    {
        ls2 = Seed.fromComponents(primitive,
            dst.getComponents(BlobSlot.L), dst.getKey(BlobSlot.L));
        ns2.attachLockSeed(ls2);
    }

    ubyte[] pt;
    if (withMAC)
    {
        auto mac2 = MAC("kmac256", dst.getMACKey());
        pt = decryptAuthTriple(ns2, ds12, ds22, ds32,
            ss12, ss22, ss32, mac2, ct);
    }
    else
    {
        pt = decryptTriple(ns2, ds12, ds22, ds32, ss12, ss22, ss32, ct);
    }
    assert(pt == plaintext, "Triple Blob512 roundtrip mismatch");
}

void testBlob512TripleFullMatrix()
{
    auto plaintext = cast(ubyte[]) "rs blob512 triple round-trip payload".dup;
    auto orig = snapshotGlobals();
    foreach (withLS; [false, true])
    {
        foreach (withMAC; [false, true])
        {
            engageNonDefaultGlobals();
            blob512TripleOne(plaintext, withLS, withMAC);
            restoreGlobals(orig);
        }
    }
}

// ----- Blob256 Single + Triple short tests -----------------------------

void testBlob256Single()
{
    auto orig = snapshotGlobals();
    engageNonDefaultGlobals();
    auto plaintext = cast(ubyte[]) "rs blob256 single round-trip".dup;
    auto ns = Seed("blake3", 1024);
    auto ds = Seed("blake3", 1024);
    auto ss = Seed("blake3", 1024);
    auto ct = encrypt(ns, ds, ss, plaintext);

    auto src = Blob256();
    src.setKey(BlobSlot.N, ns.hashKey());
    src.setKey(BlobSlot.D, ds.hashKey());
    src.setKey(BlobSlot.S, ss.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D, ds.components());
    src.setComponents(BlobSlot.S, ss.components());
    auto blob = src.exportToBytes();

    resetGlobalsToDefaults();
    auto dst = Blob256();
    dst.importFromBytes(blob);
    assert(dst.mode() == 1);
    auto ns2 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.N), dst.getKey(BlobSlot.N));
    auto ds2 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.D), dst.getKey(BlobSlot.D));
    auto ss2 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.S), dst.getKey(BlobSlot.S));
    auto pt = decrypt(ns2, ds2, ss2, ct);
    assert(pt == plaintext, "Blob256 Single roundtrip mismatch");
    restoreGlobals(orig);
}

void testBlob256Triple()
{
    auto orig = snapshotGlobals();
    engageNonDefaultGlobals();
    auto plaintext = cast(ubyte[]) "rs blob256 triple round-trip".dup;
    auto s0 = Seed("blake3", 1024);
    auto s1 = Seed("blake3", 1024);
    auto s2 = Seed("blake3", 1024);
    auto s3 = Seed("blake3", 1024);
    auto s4 = Seed("blake3", 1024);
    auto s5 = Seed("blake3", 1024);
    auto s6 = Seed("blake3", 1024);
    auto ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);

    auto src = Blob256();
    src.setKey(BlobSlot.N,  s0.hashKey());
    src.setKey(BlobSlot.D1, s1.hashKey());
    src.setKey(BlobSlot.D2, s2.hashKey());
    src.setKey(BlobSlot.D3, s3.hashKey());
    src.setKey(BlobSlot.S1, s4.hashKey());
    src.setKey(BlobSlot.S2, s5.hashKey());
    src.setKey(BlobSlot.S3, s6.hashKey());
    src.setComponents(BlobSlot.N,  s0.components());
    src.setComponents(BlobSlot.D1, s1.components());
    src.setComponents(BlobSlot.D2, s2.components());
    src.setComponents(BlobSlot.D3, s3.components());
    src.setComponents(BlobSlot.S1, s4.components());
    src.setComponents(BlobSlot.S2, s5.components());
    src.setComponents(BlobSlot.S3, s6.components());
    auto blob = src.exportTriple();

    resetGlobalsToDefaults();
    auto dst = Blob256();
    dst.importTriple(blob);
    assert(dst.mode() == 3);
    auto ns2 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.N), dst.getKey(BlobSlot.N));
    auto d12 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.D1), dst.getKey(BlobSlot.D1));
    auto d22 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.D2), dst.getKey(BlobSlot.D2));
    auto d32 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.D3), dst.getKey(BlobSlot.D3));
    auto t12 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.S1), dst.getKey(BlobSlot.S1));
    auto t22 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.S2), dst.getKey(BlobSlot.S2));
    auto t32 = Seed.fromComponents("blake3",
        dst.getComponents(BlobSlot.S3), dst.getKey(BlobSlot.S3));
    auto pt = decryptTriple(ns2, d12, d22, d32, t12, t22, t32, ct);
    assert(pt == plaintext, "Blob256 Triple roundtrip mismatch");
    restoreGlobals(orig);
}

// ----- Blob128 single — siphash24 + aescmac --------------------------

void testBlob128SiphashSingle()
{
    auto orig = snapshotGlobals();
    engageNonDefaultGlobals();
    auto plaintext = cast(ubyte[]) "rs blob128 siphash round-trip".dup;
    auto ns = Seed("siphash24", 512);
    auto ds = Seed("siphash24", 512);
    auto ss = Seed("siphash24", 512);
    auto ct = encrypt(ns, ds, ss, plaintext);

    auto src = Blob128();
    src.setKey(BlobSlot.N, ns.hashKey()); // empty for siphash24
    src.setKey(BlobSlot.D, ds.hashKey());
    src.setKey(BlobSlot.S, ss.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D, ds.components());
    src.setComponents(BlobSlot.S, ss.components());
    auto blob = src.exportToBytes();

    resetGlobalsToDefaults();
    auto dst = Blob128();
    dst.importFromBytes(blob);
    auto ns2 = Seed.fromComponents("siphash24",
        dst.getComponents(BlobSlot.N), []);
    auto ds2 = Seed.fromComponents("siphash24",
        dst.getComponents(BlobSlot.D), []);
    auto ss2 = Seed.fromComponents("siphash24",
        dst.getComponents(BlobSlot.S), []);
    auto pt = decrypt(ns2, ds2, ss2, ct);
    assert(pt == plaintext, "Blob128 siphash24 roundtrip mismatch");
    restoreGlobals(orig);
}

void testBlob128AesCmacSingle()
{
    auto orig = snapshotGlobals();
    engageNonDefaultGlobals();
    auto plaintext = cast(ubyte[]) "rs blob128 aescmac round-trip".dup;
    auto ns = Seed("aescmac", 512);
    auto ds = Seed("aescmac", 512);
    auto ss = Seed("aescmac", 512);
    auto ct = encrypt(ns, ds, ss, plaintext);

    auto src = Blob128();
    src.setKey(BlobSlot.N, ns.hashKey());
    src.setKey(BlobSlot.D, ds.hashKey());
    src.setKey(BlobSlot.S, ss.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D, ds.components());
    src.setComponents(BlobSlot.S, ss.components());
    auto blob = src.exportToBytes();

    resetGlobalsToDefaults();
    auto dst = Blob128();
    dst.importFromBytes(blob);
    auto ns2 = Seed.fromComponents("aescmac",
        dst.getComponents(BlobSlot.N), dst.getKey(BlobSlot.N));
    auto ds2 = Seed.fromComponents("aescmac",
        dst.getComponents(BlobSlot.D), dst.getKey(BlobSlot.D));
    auto ss2 = Seed.fromComponents("aescmac",
        dst.getComponents(BlobSlot.S), dst.getKey(BlobSlot.S));
    auto pt = decrypt(ns2, ds2, ss2, ct);
    assert(pt == plaintext, "Blob128 aescmac roundtrip mismatch");
    restoreGlobals(orig);
}

// ----- Slot resolution + name parity ----------------------------------

void testStringAndIntSlotsEquivalent()
{
    auto b = Blob512();
    ubyte[] key = iota(64).map!(i => cast(ubyte)(0x9c ^ i)).array;
    ulong[] comps = [0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL,
                     0xDEADBEEF_CAFEBABEUL];
    auto slotN = slotFromName("n");
    b.setKey(slotN, key);
    b.setComponents(slotN, comps);
    assert(b.getKey(BlobSlot.N) == key);
    assert(b.getComponents(BlobSlot.N) == comps);
}

void testInvalidSlotName()
{
    auto err = collectException!ITBError(slotFromName("nope"));
    assert(err !is null, "slotFromName must reject 'nope'");
    assert(err.statusCode == Status.BadInput);
}

// ----- Mode mismatch / malformed / version-too-new --------------------

void testModeMismatch()
{
    auto orig = snapshotGlobals();
    engageNonDefaultGlobals();
    auto ns = Seed("areion512", 1024);
    auto ds = Seed("areion512", 1024);
    auto ss = Seed("areion512", 1024);
    auto src = Blob512();
    src.setKey(BlobSlot.N, ns.hashKey());
    src.setKey(BlobSlot.D, ds.hashKey());
    src.setKey(BlobSlot.S, ss.hashKey());
    src.setComponents(BlobSlot.N, ns.components());
    src.setComponents(BlobSlot.D, ds.components());
    src.setComponents(BlobSlot.S, ss.components());
    auto blob = src.exportToBytes();

    auto dst = Blob512();
    auto err = collectException!ITBBlobModeMismatchError(
        dst.importTriple(blob));
    assert(err !is null, "importTriple of Single blob must throw mode-mismatch");
    assert(err.statusCode == Status.BlobModeMismatch);
    restoreGlobals(orig);
}

void testMalformed()
{
    auto b = Blob512();
    auto err = collectException!ITBBlobMalformedError(
        b.importFromBytes(cast(const(ubyte)[]) "{not json"));
    assert(err !is null, "malformed JSON must throw");
    assert(err.statusCode == Status.BlobMalformed);
}

void testVersionTooNew()
{
    // Hand-built JSON with v=99 (above any version this build supports).
    // Shape mirrors the Python / Rust test exactly.
    string zk;
    foreach (i; 0 .. 64) zk ~= "00";
    string compsStr;
    foreach (i; 0 .. 8)
    {
        if (i > 0) compsStr ~= ",";
        compsStr ~= "\"0\"";
    }
    string doc =
        "{\"v\":99,\"mode\":1,\"key_bits\":512," ~
        "\"key_n\":\"" ~ zk ~ "\"," ~
        "\"key_d\":\"" ~ zk ~ "\"," ~
        "\"key_s\":\"" ~ zk ~ "\"," ~
        "\"ns\":[" ~ compsStr ~ "]," ~
        "\"ds\":[" ~ compsStr ~ "]," ~
        "\"ss\":[" ~ compsStr ~ "]," ~
        "\"globals\":{\"nonce_bits\":128,\"barrier_fill\":1,\"bit_soup\":0,\"lock_soup\":0}}";
    auto b = Blob512();
    auto err = collectException!ITBBlobVersionTooNewError(
        b.importFromBytes(cast(const(ubyte)[]) doc));
    assert(err !is null, "v=99 must throw version-too-new");
    assert(err.statusCode == Status.BlobVersionTooNew);
}

void main()
{
    testBlob256SingleExportImportRoundtrip();
    testBlob256FreshlyConstructedHasUnsetMode();
    testBlobSlotFromNameRoundTrip();
    testBlobDropDoesNotPanic();
    testConstructEachWidth();
    testBlob512SingleFullMatrix();
    testBlob512TripleFullMatrix();
    testBlob256Single();
    testBlob256Triple();
    testBlob128SiphashSingle();
    testBlob128AesCmacSingle();
    testStringAndIntSlotsEquivalent();
    testInvalidSlotName();
    testModeMismatch();
    testMalformed();
    testVersionTooNew();
    writeln("test_blob: ALL OK");
}
