// Phase-4 + Phase-5 mirror: confirm the high-level Encryptor surface
// round-trips plaintext under Single + Triple Ouroboros, authenticates
// on tampered ciphertext, and survives the exportState / importState
// cycle on a fresh encryptor.
//
// Lock-soup-related coverage (setLockSoup, setLockSeed, attachLockSeed)
// lives in test_easy_persistence.d / test_attach_lock_seed.d where the
// global setLockSoup knob is naturally serialised by per-process
// isolation.
//
// Mirrors bindings/rust/tests/test_easy.rs one-to-one. Each Rust
// `#[test] fn` becomes a `void test*()` here, called from main().

import std.algorithm : min;
import std.exception : collectException;
import std.stdio : writeln;

import itb;

private immutable ubyte[] PLAINTEXT =
    cast(immutable(ubyte)[]) "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

void testSingleRoundtripBlake3Kmac256()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = enc.encrypt(PLAINTEXT).dup;
    assert(ct != PLAINTEXT, "ciphertext must differ from plaintext");
    auto pt = enc.decrypt(ct).dup;
    assert(pt == PLAINTEXT, "Single roundtrip plaintext mismatch");

    // Verify the read-only field accessors on the constructed
    // encryptor reflect the constructor arguments.
    assert(enc.primitive() == "blake3");
    assert(enc.keyBits() == 1024);
    assert(enc.mode() == 1);
    assert(enc.macName() == "kmac256");
    assert(!enc.isMixed());
    assert(enc.seedCount() == 3);
}

void testTripleRoundtripAreion512Kmac256()
{
    auto enc = Encryptor("areion512", 2048, "kmac256", 3);
    auto ct = enc.encrypt(PLAINTEXT).dup;
    auto pt = enc.decrypt(ct).dup;
    assert(pt == PLAINTEXT, "Triple roundtrip plaintext mismatch");

    assert(enc.primitive() == "areion512");
    assert(enc.mode() == 3);
    assert(enc.seedCount() == 7);
}

void testAuthRoundtripSingle()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = enc.encryptAuth(PLAINTEXT).dup;
    auto pt = enc.decryptAuth(ct).dup;
    assert(pt == PLAINTEXT, "auth Single roundtrip mismatch");
}

void testAuthDecryptTamperedFailsWithMACFailure()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = enc.encryptAuth(PLAINTEXT).dup;
    // Flip 256 bytes immediately after the chunk header; this region
    // sits inside the structured payload and is reliably MAC-covered
    // regardless of container-layout details.
    auto h = enc.easyHeaderSize();
    auto end = min(h + 256, ct.length);
    foreach (i; h .. end)
        ct[i] ^= 0x01;
    auto err = collectException!ITBError(enc.decryptAuth(ct));
    assert(err !is null, "tampered ciphertext must throw");
    assert(err.statusCode == Status.MACFailure,
        "expected Status.MACFailure on tampered auth ciphertext");
}

void testExportImportRoundtrip()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = enc.encryptAuth(PLAINTEXT).dup;
    auto blob = enc.exportState().dup;
    assert(blob.length > 0, "exported blob must not be empty");

    // Peek-config the saved blob and reconstruct a fresh encryptor
    // bound to the same dimensions.
    auto cfg = peekConfig(blob);
    assert(cfg.primitive == "blake3");
    assert(cfg.keyBits == 1024);
    assert(cfg.mode == 1);
    assert(cfg.macName == "kmac256");

    auto dec = Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);
    dec.importState(blob);
    auto pt = dec.decryptAuth(ct).dup;
    assert(pt == PLAINTEXT, "decrypt after import mismatch");
}

void testPeekConfigReturnsCorrectFields()
{
    auto enc = Encryptor("areion512", 2048, "hmac-blake3", 3);
    auto blob = enc.exportState().dup;
    auto cfg = peekConfig(blob);
    assert(cfg.primitive == "areion512");
    assert(cfg.keyBits == 2048);
    assert(cfg.mode == 3);
    assert(cfg.macName == "hmac-blake3");
}

void testMixedSingleThreeSameWidthPrimitives()
{
    // Three 256-bit primitives — areion256, blake3, blake2s — share
    // the same native hash width, so newMixed accepts them as a
    // valid noise / data / start trio at keyBits=1024.
    auto enc = Encryptor.newMixed("areion256", "blake3", "blake2s",
                                   null, 1024, "kmac256");
    assert(enc.isMixed());
    assert(enc.primitiveAt(0) == "areion256");
    assert(enc.primitiveAt(1) == "blake3");
    assert(enc.primitiveAt(2) == "blake2s");

    auto ct = enc.encryptAuth(PLAINTEXT).dup;
    auto pt = enc.decryptAuth(ct).dup;
    assert(pt == PLAINTEXT, "mixed Single auth roundtrip mismatch");
}

void testInvalidModeRejected()
{
    auto err = collectException!ITBError(
        Encryptor("blake3", 1024, "kmac256", 2));
    assert(err !is null, "mode=2 must be rejected");
    assert(err.statusCode == Status.BadInput,
        "expected Status.BadInput for mode=2");
}

void testUnknownPrimitiveRejected()
{
    auto err = collectException!ITBError(
        Encryptor("fake_primitive", 1024, "kmac256", 1));
    assert(err !is null, "fake primitive must be rejected");
    assert(err.statusCode == Status.EasyUnknownPrimitive,
        "expected Status.EasyUnknownPrimitive");
}

void testUnknownMACRejected()
{
    auto err = collectException!ITBError(
        Encryptor("blake3", 1024, "fake_mac", 1));
    assert(err !is null, "fake MAC must be rejected");
    // libitb's ITB_Easy_New panic classifier
    // (cmd/cshared/internal/capi/easy_handles.go::classifyPanicMessage)
    // cannot distinguish an unknown primitive name from an unknown MAC
    // name: both go through the same easy.parseConstructorArgs
    // registry-try-all-slots lookup whose panic message is "unknown
    // name <X>". The classifier folds both onto
    // Status.EasyUnknownPrimitive ("favours the most-common cause --
    // a typo in the primitive name"). Status.EasyUnknownMAC (15) is
    // only produced by the import-state path (mapImportError in
    // easy_state.go), not the constructor.
    assert(err.statusCode == Status.EasyUnknownPrimitive,
        "expected Status.EasyUnknownPrimitive (libitb constructor "
        ~ "conflates unknown primitive vs unknown MAC)");
}

void testBadKeyBitsRejected()
{
    foreach (bits; [256, 511, 999, 2049])
    {
        auto err = collectException!ITBError(
            Encryptor("blake3", bits, "kmac256", 1));
        assert(err !is null, "keyBits=" ~ "must be rejected");
        assert(err.statusCode == Status.EasyBadKeyBits,
            "expected Status.EasyBadKeyBits");
    }
}

void testCloseIsIdempotent()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.close();
    enc.close();
}

void testCloseThenEncryptRaises()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    enc.close();
    auto err = collectException!ITBError(
        enc.encrypt(cast(const(ubyte)[]) "after close"));
    assert(err !is null, "encrypt after close must throw");
    assert(err.statusCode == Status.EasyClosed,
        "expected Status.EasyClosed after close");
}

void testHeaderSizeMatchesNonceBits()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto nb = enc.nonceBits();
    auto hs = enc.easyHeaderSize();
    // header = nonce(N) + width(2) + height(2)
    assert(hs == nb / 8 + 4, "header size formula mismatch");
}

void testParseChunkLenMatchesChunkLength()
{
    auto enc = Encryptor("blake3", 1024, "kmac256", 1);
    auto ct = enc.encrypt(PLAINTEXT).dup;
    auto hs = enc.easyHeaderSize();
    auto parsed = enc.parseChunkLen(ct[0 .. hs]);
    assert(parsed == ct.length, "parseChunkLen mismatch");
}

void testDefaultMACOverrideOnNullAndEmpty()
{
    // The binding maps both `null` and the empty string `""` for
    // `macName` onto `"hmac-blake3"` BEFORE the FFI call (see
    // encryptor.d's effectiveMac line). Regression test guards
    // against either path silently forwarding to libitb's own
    // default (`"kmac256"`).
    auto encNull = Encryptor("blake3", 1024);
    assert(encNull.macName() == "hmac-blake3",
        "Encryptor(...) with no MAC arg must default to hmac-blake3");

    auto encNullExplicit = Encryptor("blake3", 1024, null, 1);
    assert(encNullExplicit.macName() == "hmac-blake3",
        "Encryptor(..., null, 1) must default to hmac-blake3");

    auto encEmpty = Encryptor("blake3", 1024, "", 1);
    assert(encEmpty.macName() == "hmac-blake3",
        "Encryptor(..., \"\", 1) must default to hmac-blake3");

    auto encExplicit = Encryptor("blake3", 1024, "kmac256", 1);
    assert(encExplicit.macName() == "kmac256",
        "explicit MAC name must NOT trigger override");
}

void main()
{
    testSingleRoundtripBlake3Kmac256();
    testTripleRoundtripAreion512Kmac256();
    testAuthRoundtripSingle();
    testAuthDecryptTamperedFailsWithMACFailure();
    testExportImportRoundtrip();
    testPeekConfigReturnsCorrectFields();
    testMixedSingleThreeSameWidthPrimitives();
    testInvalidModeRejected();
    testUnknownPrimitiveRejected();
    testUnknownMACRejected();
    testBadKeyBitsRejected();
    testCloseIsIdempotent();
    testCloseThenEncryptRaises();
    testHeaderSizeMatchesNonceBits();
    testParseChunkLenMatchesChunkLength();
    testDefaultMACOverrideOnNullAndEmpty();
    writeln("test_easy: ALL OK");
}
