// Phase-5 mirror: low-level Seed.attachLockSeed mutator.
//
// Mirrors bindings/rust/tests/test_attach_lock_seed.rs file-for-file.
//
// The dedicated lockSeed routes the bit-permutation derivation through
// its own state instead of the noiseSeed: the per-chunk PRF closure
// captures BOTH the lockSeed's components AND its hash function, so the
// lockSeed primitive may legitimately differ from the noiseSeed
// primitive within the same native hash width — keying-material
// isolation plus algorithm diversity for defence-in-depth on the
// bit-permutation channel, without changing the public encrypt /
// decrypt signatures.
//
// The bit-permutation overlay must be engaged via setBitSoup / setLockSoup
// before any encrypt call — without the overlay, the dedicated lockSeed
// has no observable effect on the wire output, and the Go-side
// build-PRF guard surfaces as ITBError.
import std.exception : collectException;
import std.stdio : writeln;
import itb;

struct LockSoupSnapshot
{
    int bitSoup;
    int lockSoup;
}

LockSoupSnapshot snapshotLockSoup()
{
    return LockSoupSnapshot(getBitSoup(), getLockSoup());
}

void restoreLockSoup(LockSoupSnapshot s)
{
    setBitSoup(s.bitSoup);
    setLockSoup(s.lockSoup);
}

void engageLockSoup()
{
    // setLockSoup(1) auto-couples BitSoup=1 inside libitb; both flags
    // are restored on exit via restoreLockSoup.
    setLockSoup(1);
}

void testRoundtrip()
{
    auto orig = snapshotLockSoup();
    engageLockSoup();
    auto plaintext = cast(ubyte[]) "attach_lock_seed roundtrip payload".dup;
    auto ns = Seed("blake3", 1024);
    auto ds = Seed("blake3", 1024);
    auto ss = Seed("blake3", 1024);
    auto ls = Seed("blake3", 1024);
    ns.attachLockSeed(ls);
    auto ct = encrypt(ns, ds, ss, plaintext);
    auto pt = decrypt(ns, ds, ss, ct);
    assert(pt == plaintext, "attach_lock_seed roundtrip mismatch");
    restoreLockSoup(orig);
}

void testPersistence()
{
    auto orig = snapshotLockSoup();
    engageLockSoup();
    auto plaintext = cast(ubyte[]) "cross-process attach lockseed roundtrip".dup;

    // Day 1 — sender.
    ulong[] nsComps, dsComps, ssComps, lsComps;
    ubyte[] nsKey, dsKey, ssKey, lsKey;
    ubyte[] ct;
    {
        auto ns = Seed("blake3", 1024);
        auto ds = Seed("blake3", 1024);
        auto ss = Seed("blake3", 1024);
        auto ls = Seed("blake3", 1024);
        ns.attachLockSeed(ls);

        nsComps = ns.components();
        dsComps = ds.components();
        ssComps = ss.components();
        lsComps = ls.components();
        nsKey = ns.hashKey();
        dsKey = ds.hashKey();
        ssKey = ss.hashKey();
        lsKey = ls.hashKey();

        ct = encrypt(ns, ds, ss, plaintext);
    }

    // Day 2 — receiver.
    auto ns2 = Seed.fromComponents("blake3", nsComps, nsKey);
    auto ds2 = Seed.fromComponents("blake3", dsComps, dsKey);
    auto ss2 = Seed.fromComponents("blake3", ssComps, ssKey);
    auto ls2 = Seed.fromComponents("blake3", lsComps, lsKey);

    ns2.attachLockSeed(ls2);
    auto pt = decrypt(ns2, ds2, ss2, ct);
    assert(pt == plaintext, "attach_lock_seed persistence mismatch");
    restoreLockSoup(orig);
}

void testSelfAttachRejected()
{
    auto ns = Seed("blake3", 1024);
    auto err = collectException!ITBError(ns.attachLockSeed(ns));
    assert(err !is null, "self-attach must throw");
    assert(err.statusCode == Status.BadInput);
}

void testWidthMismatchRejected()
{
    auto ns256 = Seed("blake3", 1024);    // width 256
    auto ls128 = Seed("siphash24", 1024); // width 128
    auto err = collectException!ITBError(ns256.attachLockSeed(ls128));
    assert(err !is null, "width mismatch must throw");
    assert(err.statusCode == Status.SeedWidthMix);
}

void testPostEncryptAttachRejected()
{
    auto orig = snapshotLockSoup();
    engageLockSoup();
    auto ns = Seed("blake3", 1024);
    auto ds = Seed("blake3", 1024);
    auto ss = Seed("blake3", 1024);
    auto ls = Seed("blake3", 1024);
    ns.attachLockSeed(ls);
    // Encrypt once — locks future attachLockSeed calls.
    encrypt(ns, ds, ss, cast(const(ubyte)[]) "pre-switch");
    auto ls2 = Seed("blake3", 1024);
    auto err = collectException!ITBError(ns.attachLockSeed(ls2));
    assert(err !is null, "post-encrypt attach must throw");
    assert(err.statusCode == Status.BadInput);
    restoreLockSoup(orig);
}

void testOverlayOffPanicsOnEncrypt()
{
    auto orig = snapshotLockSoup();
    setBitSoup(0);
    setLockSoup(0);
    auto ns = Seed("blake3", 1024);
    auto ds = Seed("blake3", 1024);
    auto ss = Seed("blake3", 1024);
    auto ls = Seed("blake3", 1024);
    ns.attachLockSeed(ls);
    auto err = collectException!ITBError(
        encrypt(ns, ds, ss, cast(const(ubyte)[]) "overlay off - should panic"));
    assert(err !is null,
        "encrypt with attached lockSeed but overlay off must surface ITBError");
    restoreLockSoup(orig);
}

void main()
{
    testRoundtrip();
    testPersistence();
    testSelfAttachRejected();
    testWidthMismatchRejected();
    testPostEncryptAttachRejected();
    testOverlayOffPanicsOnEncrypt();
    writeln("test_attach_lock_seed: ALL OK");
}
