# ITB D Binding — Format-Deniability Wrapper

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

D-idiomatic surface over the format-deniability wrapper exposed by libitb. Mirrors `github.com/everanium/itb/wrapper` structurally; the wire bytes produced by the D helpers are byte-identical to the Go-native helpers under the same `(cipher, key, nonce)` tuple.

The runtime module lives at `itb.wrapper`; this directory carries the wrapper-side documentation (`README.md` + `BENCH.md`). The example utility lives at `bindings/dlang/eitb/source/eitb.d` and the benchmark binary at `bindings/dlang/bench/source/bench_wrapper.d`.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: one of PRF-grade ciphers. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The D module exposes Single Message helpers (immutable + in-place mutation) and a streaming RAII struct pair:

| Helper | Wire format | Use case |
|---|---|---|
| `wrap` / `unwrap` | `nonce \|\| keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output, immutable plaintext path. |
| `wrapInPlace` / `unwrapInPlace` | same as `wrap` / `unwrap` | Single Message, no output-buffer allocation. Mutates the caller's `ubyte[]` slice. |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — Streaming AEAD wraps the entire bytestream end-to-end; User-Driven Loop emits per-chunk caller-side framing (`u32_LE` length prefix) through the wrap-writer so the framing bytes also pass through the keystream XOR. |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

The streaming structs are RAII — the destructor releases the underlying libitb stream handle best-effort on scope exit. `close()` is the explicit release path that surfaces release-time errors to the caller. The structs are non-copyable (`@disable this(this);`).

### Binding asymmetry

The D binding exposes Streaming AEAD as a delegate-driven reader / writer pair (`Encryptor.encryptStreamAuth` / `decryptStreamAuth`, plus the free-function `itb.streams.encryptStreamAuth` / `decryptStreamAuth`). The Streaming No MAC path has **no** equivalent delegate-driven IO-Driven adapter pair for Non-AEAD streaming. This asymmetry is intentional. The Non-AEAD streaming arm in the D wrapper covers the **User-Driven Loop** variant only — caller produces an ITB ciphertext per chunk via `enc.encrypt(chunk)` (or `itb.cipher.encrypt(...)`), frames `u32_LE_len || ct`, and pushes through the streaming wrap handle.

## Outer ciphers

| Cipher | Enum | FFI name | Key | Nonce | Notes |
|---|---|---|---|---|---|
| Areion-SoEM-256 | `Cipher.areion256` | `"areion256"` | 32 B | 16 B | Keyed Areion-SoEM-256 PRF in CTR mode. AES-round-based; AES-NI accelerated. |
| Areion-SoEM-512 | `Cipher.areion512` | `"areion512"` | 64 B | 16 B | Keyed Areion-SoEM-512 PRF in CTR mode. AES-round-based; AES-NI accelerated. |
| BLAKE2b-256 | `Cipher.blake2b256` | `"blake2b256"` | 32 B | 16 B | Keyed BLAKE2b-256 PRF in CTR mode. |
| BLAKE2b-512 | `Cipher.blake2b512` | `"blake2b512"` | 32 B | 16 B | Keyed BLAKE2b-512 PRF in CTR mode. |
| BLAKE2s | `Cipher.blake2s` | `"blake2s"` | 32 B | 16 B | Keyed BLAKE2s-256 PRF in CTR mode. |
| BLAKE3 | `Cipher.blake3` | `"blake3"` | 32 B | 16 B | Keyed BLAKE3 PRF in CTR mode. |
| AES-128-CTR | `Cipher.aes128Ctr` | `"aescmac"` | 16 B | 16 B | libitb-side stdlib path with AES-NI. |
| SipHash-2-4 in CTR mode | `Cipher.sipHash24` | `"siphash24"` | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |
| ChaCha20 (RFC 8439) | `Cipher.chaCha20` | `"chacha20"` | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash128(key, nonce_hi || (nonce_lo XOR counter_LE))` — 16-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Code paths under `bindings/dlang/eitb/source/eitb.d`. Run the matrix:

```sh
cd bindings/dlang/eitb
dub build
LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/eitb
LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/eitb --help
```

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Encryptor.encryptStreamAuth` / `decryptStreamAuth` over reader / writer delegates. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the continuous bytestream ITB emits.

```d
import itb;

auto enc = Encryptor("areion512", 1024, "hmac-blake3", 1);
scope(exit) enc.close();
enc.setNonceBits(512);
enc.setBarrierFill(4);
enc.setBitSoup(1);
enc.setLockSoup(1);
enc.setLockBatch(1);  // Recommended under the PRF assumption,
                      // the performance Lock Soup mode.
                      // Symmetric, set on both sides.

auto outerKey = wrapperGenerateKey(cipher);

// Sender — wrap the entire AEAD bytestream in one keystream session.
ubyte[] wireBuf;
auto ww = WrapStreamWriter(cipher, outerKey);
scope(exit) ww.close();
wireBuf ~= ww.nonce;
size_t readOff = 0;
size_t reader(ubyte[] buf) @trusted { /* fill buf from plaintext source */ ... }
void writer(const(ubyte)[] chunk) @trusted { wireBuf ~= ww.update(chunk); }
enc.encryptStreamAuth(&reader, &writer, 16 * 1024);

// Receiver
auto nlen = nonceSize(cipher);
auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
scope(exit) ur.close();
auto innerWire = ur.update(wireBuf[nlen .. $]);
// Feed innerWire to enc.decryptStreamAuth via a delegate-pair.
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb.streams.encryptStreamAuth` / `itb.streams.decryptStreamAuth` with three explicit `Seed` handles plus a `MAC("hmac-blake3", &macKey)`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`.

```d
auto noise = Seed("areion512", 1024);
auto data  = Seed("areion512", 1024);
auto start = Seed("areion512", 1024);
auto mac   = MAC("hmac-blake3", macKey32);
auto outerKey = wrapperGenerateKey(cipher);

ubyte[] wireBuf;
auto ww = WrapStreamWriter(cipher, outerKey);
scope(exit) ww.close();
wireBuf ~= ww.nonce;
encryptStreamAuth(noise, data, start, mac, &reader, &writer, 16 * 1024);
// Receiver mirrors example 1.
```

### 3. Streaming Easy (No MAC, User-Driven Loop)

The "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.encrypt(chunk)` call. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```d
auto enc = Encryptor("areion512", 1024, null, 1);
scope(exit) enc.close();
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);
enc.setLockBatch(1);  // Recommended under the PRF assumption,
                      // the performance Lock Soup mode.
                      // Symmetric, set on both sides.

auto outerKey = wrapperGenerateKey(cipher);
ubyte[] wireBuf;
auto ww = WrapStreamWriter(cipher, outerKey);
scope(exit) ww.close();
wireBuf ~= ww.nonce;

size_t off = 0;
while (off < plaintext.length)
{
    size_t take = (plaintext.length - off < 16 * 1024)
                  ? plaintext.length - off : 16 * 1024;
    auto ct = enc.encrypt(plaintext[off .. off + take]).dup;
    ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
    wireBuf ~= ww.update(lenBytes[]);
    wireBuf ~= ww.update(ct);
    off += take;
}

// Receiver — pull entire decrypted bytestream then walk u32_LE-prefixed chunks.
auto nlen = nonceSize(cipher);
auto ur = UnwrapStreamReader(cipher, outerKey, wireBuf[0 .. nlen]);
scope(exit) ur.close();
auto decrypted = ur.update(wireBuf[nlen .. $]);
ubyte[] recovered;
size_t pos = 0;
while (pos < decrypted.length)
{
    ubyte[4] lenBytes = decrypted[pos .. pos + 4][0 .. 4];
    uint clen = littleEndianToNative!uint(lenBytes);
    pos += 4;
    recovered ~= enc.decrypt(decrypted[pos .. pos + clen]).dup;
    pos += clen;
}
```

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb.cipher.encrypt` / `itb.cipher.decrypt` with caller-side framing. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```d
auto noise = Seed("areion512", 1024);
auto data  = Seed("areion512", 1024);
auto start = Seed("areion512", 1024);
auto outerKey = wrapperGenerateKey(cipher);

ubyte[] wireBuf;
auto ww = WrapStreamWriter(cipher, outerKey);
scope(exit) ww.close();
wireBuf ~= ww.nonce;

size_t off = 0;
while (off < plaintext.length)
{
    size_t take = (plaintext.length - off < 16 * 1024)
                  ? plaintext.length - off : 16 * 1024;
    auto ct = encrypt(noise, data, start, plaintext[off .. off + take]);
    ubyte[4] lenBytes = nativeToLittleEndian(cast(uint) ct.length);
    wireBuf ~= ww.update(lenBytes[]);
    wireBuf ~= ww.update(ct);
    off += take;
}
// Receiver mirrors example 3 with itb.cipher.decrypt(noise, data, start, ct).
```

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.encrypt(plaintext)` returns one ITB blob. Wrap shape: `wrap` — `nonce || ks-XOR(blob)`. The `wrapInPlace` / `unwrapInPlace` variant is shown — mutates the caller's `ubyte[]` slice in place to skip the output-buffer allocation.

```d
auto enc = Encryptor("areion512", 2048, null, 1);
scope(exit) enc.close();
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);
enc.setLockBatch(1);  // Recommended under the PRF assumption,
                      // the performance Lock Soup mode.
                      // Symmetric, set on both sides.

auto encrypted = enc.encrypt(plaintext).dup;

auto outerKey = wrapperGenerateKey(cipher);
// wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
// auto wire = wrap(cipher, outerKey, encrypted);
auto nonce = wrapInPlace(cipher, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;

// Receiver — unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
// auto recovered = unwrap(cipher, outerKey, wire);
auto recovered = unwrapInPlace(cipher, outerKey, wire);
auto pt = enc.decrypt(recovered).dup;
```

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.encryptAuth` / `enc.decryptAuth`. Wrap shape: `wrap` (or `wrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```d
auto enc = Encryptor("areion512", 2048, "hmac-blake3", 1);
scope(exit) enc.close();
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);
enc.setLockBatch(1);  // Recommended under the PRF assumption,
                      // the performance Lock Soup mode.
                      // Symmetric, set on both sides.

auto encrypted = enc.encryptAuth(plaintext).dup;

auto outerKey = wrapperGenerateKey(cipher);
auto nonce = wrapInPlace(cipher, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;

// Receiver
auto recovered = unwrapInPlace(cipher, outerKey, wire);
auto pt = enc.decryptAuth(recovered).dup;
```

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `itb.cipher.encrypt(noise, data, start, plaintext)` / `itb.cipher.decrypt(...)` with three explicit `Seed` handles. Wrap shape: `wrap` (or `wrapInPlace`). Wire shape matches example 5; the difference is that the seed material is held by caller-side `Seed` handles rather than by an `Encryptor` instance.

```d
auto noise = Seed("areion512", 2048);
auto data  = Seed("areion512", 2048);
auto start = Seed("areion512", 2048);

auto encrypted = encrypt(noise, data, start, plaintext);

auto outerKey = wrapperGenerateKey(cipher);
auto nonce = wrapInPlace(cipher, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;

// Receiver
auto recovered = unwrapInPlace(cipher, outerKey, wire);
auto pt = decrypt(noise, data, start, recovered);
```

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `itb.cipher.encryptAuth(noise, data, start, mac, plaintext)` / `itb.cipher.decryptAuth(...)`. Wrap shape: `wrap` (or `wrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```d
auto noise = Seed("areion512", 2048);
auto data  = Seed("areion512", 2048);
auto start = Seed("areion512", 2048);
auto mac   = MAC("hmac-blake3", macKey32);

auto encrypted = encryptAuth(noise, data, start, mac, plaintext);

auto outerKey = wrapperGenerateKey(cipher);
auto nonce = wrapInPlace(cipher, outerKey, encrypted);
ubyte[] wire;
wire ~= nonce;
wire ~= encrypted;

// Receiver
auto recovered = unwrapInPlace(cipher, outerKey, wire);
auto pt = decryptAuth(noise, data, start, mac, recovered);
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with byte-equality. Sample run:

```
[PASS] aead-easy-io               + areion256   pt=65536 wire=90208
[PASS] aead-easy-io               + areion512   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2b256   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2b512   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2s    pt=65536 wire=90208
[PASS] aead-easy-io               + blake3     pt=65536 wire=90208
[PASS] aead-easy-io               + aescmac    pt=65536 wire=90208
[PASS] aead-easy-io               + siphash24   pt=65536 wire=90208
[PASS] aead-easy-io               + chacha20   pt=65536 wire=90204
...
[PASS] message-lowlevel-auth      + areion256   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + areion512   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2b256   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2b512   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2s    pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake3     pt=1024 wire=8276
[PASS] message-lowlevel-auth      + aescmac    pt=1024 wire=8276
[PASS] message-lowlevel-auth      + siphash24   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha20   pt=1024 wire=8272
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 bytes for every cipher except ChaCha20 (RFC 8439), which uses a 12-byte nonce); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk. The wire byte counts match the Python / Rust / C# / Node.js / Ada bindings' matrices exactly under the same plaintext sizes.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the example utility generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
