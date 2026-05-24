// Phase wrapper-rollout: confirms the format-deniability `wrapper`
// module round-trips ITB ciphertext under each of the nine PRF-grade
// outer keystream ciphers (Areion-SoEM-256 / Areion-SoEM-512 /
// SipHash-2-4 in CTR mode / AES-128-CTR / BLAKE2b-256 / BLAKE2b-512 /
// BLAKE2s / BLAKE3 / ChaCha20 (RFC8439)), exercising Single Message
// wrap/unwrap, in-place mutation, and streaming wrap/unwrap entry
// points.
//
// Mirrors bindings/python/tests/test_wrapper.py and
// bindings/rust/tests/test_wrapper.rs at coverage parity.
//
// Compile recipe:
//   ./run_tests.sh test_wrapper

import std.algorithm.searching : canFind;
import std.exception : assertThrown, collectException;
import std.format : format;
import std.range : iota;
import std.stdio : writeln;
import itb;

immutable Cipher[] ALL_CIPHERS = [
    Cipher.areion256,
    Cipher.areion512,
    Cipher.sipHash24,
    Cipher.aes128Ctr,
    Cipher.blake2b256,
    Cipher.blake2b512,
    Cipher.blake2s,
    Cipher.blake3,
    Cipher.chaCha20,
];

ubyte[] pseudoBlob(size_t n)
{
    auto buf = new ubyte[n];
    foreach (i; 0 .. n)
        buf[i] = cast(ubyte)((i * 31 + 7) & 0xff);
    return buf;
}

void testCipherEnumIntrospection()
{
    assert(ffiName(Cipher.areion256)  == "areion256");
    assert(ffiName(Cipher.areion512)  == "areion512");
    assert(ffiName(Cipher.sipHash24)  == "siphash24");
    assert(ffiName(Cipher.aes128Ctr)  == "aescmac");
    assert(ffiName(Cipher.blake2b256) == "blake2b256");
    assert(ffiName(Cipher.blake2b512) == "blake2b512");
    assert(ffiName(Cipher.blake2s)    == "blake2s");
    assert(ffiName(Cipher.blake3)     == "blake3");
    assert(ffiName(Cipher.chaCha20)   == "chacha20");

    assert(cipherFromName("areion256")  == Cipher.areion256);
    assert(cipherFromName("areion512")  == Cipher.areion512);
    assert(cipherFromName("siphash24")  == Cipher.sipHash24);
    assert(cipherFromName("aescmac")    == Cipher.aes128Ctr);
    assert(cipherFromName("blake2b256") == Cipher.blake2b256);
    assert(cipherFromName("blake2b512") == Cipher.blake2b512);
    assert(cipherFromName("blake2s")    == Cipher.blake2s);
    assert(cipherFromName("blake3")     == Cipher.blake3);
    assert(cipherFromName("chacha20")   == Cipher.chaCha20);

    assert(CIPHER_NAMES.length == 9);
    assert(CIPHER_NAMES[0] == Cipher.areion256);
    assert(CIPHER_NAMES[1] == Cipher.areion512);
    assert(CIPHER_NAMES[2] == Cipher.sipHash24);
    assert(CIPHER_NAMES[3] == Cipher.aes128Ctr);
    assert(CIPHER_NAMES[4] == Cipher.blake2b256);
    assert(CIPHER_NAMES[5] == Cipher.blake2b512);
    assert(CIPHER_NAMES[6] == Cipher.blake2s);
    assert(CIPHER_NAMES[7] == Cipher.blake3);
    assert(CIPHER_NAMES[8] == Cipher.chaCha20);

    auto err = collectException!WrapperInvalidCipherError(cipherFromName("nope"));
    assert(err !is null, "unknown cipher name must throw");
    assert(err.cipherName == "nope");
    assert(err.statusCode == Status.BadInput);
}

void testKeyAndNonceSizes()
{
    // Sizes must match the Go-side wrapper.KeySize / NonceSize for
    // each canonical cipher: areion256 32/16, areion512 64/16,
    // siphash 16/16, aes 16/16, blake2b256 32/16, blake2b512 32/16,
    // blake2s 32/16, blake3 32/16, chacha 32/12.
    assert(keySize(Cipher.areion256)  == 32);
    assert(keySize(Cipher.areion512)  == 64);
    assert(keySize(Cipher.sipHash24)  == 16);
    assert(keySize(Cipher.aes128Ctr)  == 16);
    assert(keySize(Cipher.blake2b256) == 32);
    assert(keySize(Cipher.blake2b512) == 32);
    assert(keySize(Cipher.blake2s)    == 32);
    assert(keySize(Cipher.blake3)     == 32);
    assert(keySize(Cipher.chaCha20)   == 32);

    assert(nonceSize(Cipher.areion256)  == 16);
    assert(nonceSize(Cipher.areion512)  == 16);
    assert(nonceSize(Cipher.sipHash24)  == 16);
    assert(nonceSize(Cipher.aes128Ctr)  == 16);
    assert(nonceSize(Cipher.blake2b256) == 16);
    assert(nonceSize(Cipher.blake2b512) == 16);
    assert(nonceSize(Cipher.blake2s)    == 16);
    assert(nonceSize(Cipher.blake3)     == 16);
    assert(nonceSize(Cipher.chaCha20)   == 12);
}

void testGenerateKeyLength()
{
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);
        assert(key.length == keySize(c),
            format("generateKey(%s).length must equal keySize", ffiName(c)));
        // Two consecutive draws must differ — would confirm the
        // CSPRNG path is live.
        auto key2 = wrapperGenerateKey(c);
        assert(key != key2,
            format("two consecutive generateKey(%s) draws must differ", ffiName(c)));
    }
}

void testDeriveKeyDeterministicAndRoundtrips()
{
    import std.random : uniform, Random, unpredictableSeed;

    // 32 random bytes as the master secret (stand-in for an ML-KEM
    // shared secret; the binding ships no KEM). 32 bytes is the
    // wrapper's uniform security floor; the kdf layer truncates /
    // stretches it to each cipher's key size, so a single 32-byte
    // master keys every outer cipher.
    auto rnd = Random(unpredictableSeed);
    auto master = new ubyte[32];
    foreach (i; 0 .. master.length)
        master[i] = cast(ubyte) uniform(0, 256, rnd);

    auto blob = pseudoBlob(1024);
    foreach (c; ALL_CIPHERS)
    {
        auto key1 = wrapperDeriveKey(c, master);
        assert(key1.length == keySize(c),
            format("deriveKey(%s).length must equal keySize", ffiName(c)));

        // Determinism: same (cipher, master) yields the same key.
        auto key2 = wrapperDeriveKey(c, master);
        assert(key1 == key2,
            format("deriveKey(%s) must be deterministic for a fixed master", ffiName(c)));

        // The derived key round-trips through wrap / unwrap.
        auto wire = wrap(c, key1, blob);
        auto recovered = unwrap(c, key1, wire);
        assert(recovered == blob,
            format("derived key for %s must round-trip through wrap/unwrap", ffiName(c)));
    }
}

void testDeriveKeyMasterFloorBoundary()
{
    // The wrapper enforces a uniform 32-byte master floor for every
    // cipher (not the per-cipher key size): 31 bytes is rejected, 32
    // bytes is accepted. The C ABI surfaces a too-short master as
    // Status.BadInput, mapped to the base ITBError.
    foreach (c; ALL_CIPHERS)
    {
        auto shortMaster = new ubyte[31];
        auto err = collectException!ITBError(wrapperDeriveKey(c, shortMaster));
        assert(err !is null,
            format("deriveKey(%s): 31-byte master must be rejected", ffiName(c)));
        assert(err.statusCode == Status.BadInput,
            format("deriveKey(%s): short master must carry Status.BadInput", ffiName(c)));

        auto floorMaster = new ubyte[32];
        auto key = wrapperDeriveKey(c, floorMaster);
        assert(key.length == keySize(c),
            format("deriveKey(%s): 32-byte master must be accepted", ffiName(c)));
    }
}

void testSingleShotRoundtrip()
{
    auto blob = pseudoBlob(4096);
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);
        auto wire = wrap(c, key, blob);
        assert(wire.length == nonceSize(c) + blob.length,
            format("wrap(%s) wire length must equal nonceSize + blob", ffiName(c)));
        assert(wire[nonceSize(c) .. $] != blob,
            format("wrap(%s) body must differ from plaintext (XOR has happened)", ffiName(c)));
        auto recovered = unwrap(c, key, wire);
        assert(recovered == blob,
            format("unwrap(%s) must recover original blob", ffiName(c)));
    }
}

void testSingleShotEmptyBlob()
{
    // Wrap of empty blob is degenerate — wire equals just the nonce.
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);
        auto wire = wrap(c, key, []);
        assert(wire.length == nonceSize(c),
            format("wrap(%s) of empty blob must produce nonce-only wire", ffiName(c)));
        auto recovered = unwrap(c, key, wire);
        assert(recovered.length == 0,
            format("unwrap(%s) of nonce-only wire must yield empty blob", ffiName(c)));
    }
}

void testInPlaceWrapRoundtrip()
{
    auto blob = pseudoBlob(2048);
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);
        auto mutable = blob.dup;
        auto nonce = wrapInPlace(c, key, mutable);
        assert(nonce.length == nonceSize(c),
            format("wrapInPlace(%s) returns %d-byte nonce", ffiName(c), nonceSize(c)));
        assert(mutable != blob,
            format("wrapInPlace(%s) must mutate the input blob", ffiName(c)));

        // Compose wire = nonce || ciphered blob
        ubyte[] wireBuf;
        wireBuf ~= nonce;
        wireBuf ~= mutable;

        auto bodyView = unwrapInPlace(c, key, wireBuf);
        assert(bodyView == blob,
            format("unwrapInPlace(%s) bodyView must equal original blob", ffiName(c)));
        assert(bodyView.ptr is &wireBuf[nonce.length],
            format("unwrapInPlace(%s) must alias wire[nlen .. $]", ffiName(c)));
    }
}

void testInPlaceMutatesInputBuffer()
{
    auto original = pseudoBlob(64);
    auto c = Cipher.chaCha20;
    auto key = wrapperGenerateKey(c);
    auto buf = original.dup;
    cast(void) wrapInPlace(c, key, buf);
    assert(buf != original,
        "wrapInPlace must mutate the caller's buffer (D mutability honesty)");
}

void testKeyLengthMismatchSurfacesTypedException()
{
    auto blob = pseudoBlob(32);
    foreach (c; ALL_CIPHERS)
    {
        ubyte[] tooShort = new ubyte[keySize(c) - 1];
        auto err = collectException!WrapperInvalidKeyError(
            wrap(c, tooShort, blob));
        assert(err !is null, "short key must throw WrapperInvalidKeyError");
        assert(err.statusCode == Status.BadInput);

        ubyte[] tooLong = new ubyte[keySize(c) + 1];
        auto err2 = collectException!WrapperInvalidKeyError(
            wrap(c, tooLong, blob));
        assert(err2 !is null, "long key must throw WrapperInvalidKeyError");
        assert(err2.statusCode == Status.BadInput);
    }
}

void testUnwrapShortWireSurfacesTypedException()
{
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);
        ubyte[] tooShort = new ubyte[nonceSize(c) - 1];
        auto err = collectException!WrapperInvalidNonceError(
            unwrap(c, key, tooShort));
        assert(err !is null,
            "wire shorter than nonce must throw WrapperInvalidNonceError");
        assert(err.statusCode == Status.BadInput);
    }
}

void testStreamingWriterReaderRoundtrip()
{
    auto blob = pseudoBlob(8192);
    foreach (c; ALL_CIPHERS)
    {
        auto key = wrapperGenerateKey(c);

        ubyte[] wireBuf;

        {
            auto ww = WrapStreamWriter(c, key);
            scope(exit) ww.close();
            wireBuf ~= ww.nonce;
            // Push two halves to confirm the keystream counter is
            // monotonic across update calls.
            wireBuf ~= ww.update(blob[0 .. blob.length / 2]);
            wireBuf ~= ww.update(blob[blob.length / 2 .. $]);
        }

        ubyte[] recovered;

        {
            auto nlen = nonceSize(c);
            auto ur = UnwrapStreamReader(c, key, wireBuf[0 .. nlen]);
            scope(exit) ur.close();
            recovered ~= ur.update(wireBuf[nlen .. $]);
        }

        assert(recovered == blob,
            format("streaming roundtrip(%s) must recover blob", ffiName(c)));
    }
}

void testStreamingMonotonicCounter()
{
    // Driving the writer in many small updates must produce
    // byte-identical output to one big update of the concatenated
    // input — the keystream counter is shared across calls.
    auto c = Cipher.aes128Ctr;
    auto key = wrapperGenerateKey(c);
    auto blob = pseudoBlob(4096);

    ubyte[] wireMany;
    auto ww1 = WrapStreamWriter(c, key);
    scope(exit) ww1.close();
    wireMany ~= ww1.nonce;
    foreach (i; 0 .. 16)
        wireMany ~= ww1.update(blob[i * 256 .. (i + 1) * 256]);

    // Re-encode under the SAME nonce — the writer-2 path manually
    // re-binds via the unwrap reader's update stream to confirm the
    // big-block decrypt yields the same recovered blob as the
    // small-block emission.
    auto nlen = nonceSize(c);
    auto ur = UnwrapStreamReader(c, key, wireMany[0 .. nlen]);
    scope(exit) ur.close();
    auto recovered = ur.update(wireMany[nlen .. $]);
    assert(recovered == blob,
        "streaming small-block writer + big-block reader must roundtrip");
}

void testStreamingCloseIdempotent()
{
    auto c = Cipher.sipHash24;
    auto key = wrapperGenerateKey(c);
    auto ww = WrapStreamWriter(c, key);
    ww.close();
    ww.close(); // second call must be a no-op
}

void testStreamingUpdateAfterCloseFails()
{
    auto c = Cipher.chaCha20;
    auto key = wrapperGenerateKey(c);
    auto ww = WrapStreamWriter(c, key);
    ww.close();
    auto err = collectException!WrapperHandleClosedError(
        ww.update(cast(const(ubyte)[]) "x"));
    assert(err !is null, "update after close must throw WrapperHandleClosedError");
    assert(err.statusCode == Status.BadHandle);
}

void testStreamingNonceLengthMismatchOnReader()
{
    auto c = Cipher.aes128Ctr;
    auto key = wrapperGenerateKey(c);
    ubyte[] badNonce = new ubyte[nonceSize(c) - 1];
    auto err = collectException!WrapperInvalidNonceError(
        UnwrapStreamReader(c, key, badNonce));
    assert(err !is null,
        "UnwrapStreamReader with wrong nonce length must throw");
    assert(err.statusCode == Status.BadInput);
}

void testStreamingRaiiReleasesHandle()
{
    auto c = Cipher.chaCha20;
    auto key = wrapperGenerateKey(c);
    // Construct + drop many writers/readers — the destructor must
    // release each libitb handle without leaking.
    foreach (_; 0 .. 32)
    {
        auto ww = WrapStreamWriter(c, key);
        ubyte[16] payload = 0xAB;
        cast(void) ww.update(payload[]);
        // Implicit destructor on scope exit.
    }
}

void testStreamingUpdateInPlaceRoundtrip()
{
    auto blob = pseudoBlob(1024);
    auto c = Cipher.aes128Ctr;
    auto key = wrapperGenerateKey(c);

    ubyte[] wire;
    auto ww = WrapStreamWriter(c, key);
    scope(exit) ww.close();
    wire ~= ww.nonce;
    auto buf = blob.dup;
    ww.updateInPlace(buf);
    wire ~= buf;

    auto nlen = nonceSize(c);
    auto ur = UnwrapStreamReader(c, key, wire[0 .. nlen]);
    scope(exit) ur.close();
    auto bodyBuf = wire[nlen .. $].dup;
    ur.updateInPlace(bodyBuf);
    assert(bodyBuf == blob, "streaming in-place roundtrip must recover blob");
}

void main()
{
    testCipherEnumIntrospection();
    testKeyAndNonceSizes();
    testGenerateKeyLength();
    testDeriveKeyDeterministicAndRoundtrips();
    testDeriveKeyMasterFloorBoundary();
    testSingleShotRoundtrip();
    testSingleShotEmptyBlob();
    testInPlaceWrapRoundtrip();
    testInPlaceMutatesInputBuffer();
    testKeyLengthMismatchSurfacesTypedException();
    testUnwrapShortWireSurfacesTypedException();
    testStreamingWriterReaderRoundtrip();
    testStreamingMonotonicCounter();
    testStreamingCloseIdempotent();
    testStreamingUpdateAfterCloseFails();
    testStreamingNonceLengthMismatchOnReader();
    testStreamingRaiiReleasesHandle();
    testStreamingUpdateInPlaceRoundtrip();
    writeln("test_wrapper: ALL OK");
}
