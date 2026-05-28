# ITB D Binding — Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `wrapInPlace` row mutates the caller's `ubyte[]` slice (no output-buffer allocation); the `wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

The wrapper bench covers allouter ciphers — each in CTR mode.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `wrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The D binding adds the per-call libitb-FFI crossing and a `ubyte[]` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + FFI overhead.

## Binding asymmetry note

The D binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair (no `OutputRange` / `InputRange` adapter for Non-AEAD streaming). The Streaming AEAD path covers IO-Driven for both Easy and Low-Level via the delegate-driven reader / writer surface.

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 306-case sub-bench matrix:
cd bindings/dlang/bench
dub build :wrapper --build=release --compiler=ldc2
LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/itb-bench-wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=bench_wrapper_only \
    LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/itb-bench-wrapper

ITB_BENCH_FILTER=bench_msg_single_easy_nomac \
    LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/itb-bench-wrapper

ITB_BENCH_FILTER=bench_stream_triple \
    LD_LIBRARY_PATH=$REPO_ROOT/dist/linux-amd64 ./bin/itb-bench-wrapper
```

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `setMaxWorkers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine clone each iteration via `.dup`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 606 | 1976 |
| **Areion-SoEM-512** | 628 | 1985 |
| **BLAKE2b-256** | 378 | 639 |
| **BLAKE2b-512** | 499 | 1137 |
| **BLAKE2s** | 388 | 700 |
| **BLAKE3** | 529 | 1312 |
| **AES-128-CTR** | 739 | 10431 |
| **SipHash-2-4** | 679 | 2913 |
| **ChaCha20** | 661 | 2701 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 150 | 233 | 157 | 234 | 177 | 217 | 165 | 205 |
| **Areion-SoEM-512** | 180 | 247 | 164 | 230 | 176 | 204 | 152 | 205 |
| **BLAKE2b-256** | 170 | 230 | 162 | 217 | 167 | 211 | 160 | 196 |
| **BLAKE2b-512** | 178 | 244 | 165 | 232 | 180 | 228 | 166 | 209 |
| **BLAKE2s** | 163 | 235 | 156 | 214 | 170 | 209 | 156 | 195 |
| **BLAKE3** | 183 | 252 | 161 | 239 | 180 | 226 | 166 | 216 |
| **AES-128-CTR** | 189 | 271 | 175 | 252 | 184 | 236 | 177 | 227 |
| **SipHash-2-4** | 182 | 258 | 170 | 241 | 179 | 223 | 170 | 208 |
| **ChaCha20** | 188 | 267 | 172 | 244 | 184 | 227 | 171 | 209 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 245 | 283 | 226 | 269 | 239 | 250 | 221 | 226 |
| **Areion-SoEM-512** | 248 | 279 | 217 | 261 | 237 | 231 | 208 | 236 |
| **BLAKE2b-256** | 211 | 239 | 197 | 230 | 211 | 219 | 192 | 210 |
| **BLAKE2b-512** | 236 | 269 | 210 | 252 | 229 | 238 | 210 | 228 |
| **BLAKE2s** | 217 | 247 | 201 | 234 | 213 | 219 | 198 | 207 |
| **BLAKE3** | 240 | 275 | 214 | 262 | 233 | 241 | 213 | 225 |
| **AES-128-CTR** | 257 | 302 | 230 | 283 | 254 | 268 | 229 | 248 |
| **SipHash-2-4** | 250 | 290 | 224 | 276 | 251 | 246 | 222 | 235 |
| **ChaCha20** | 246 | 294 | 224 | 278 | 246 | 253 | 220 | 241 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 135 | 166 | 132 | 168 |
| **Areion-SoEM-512** | 137 | 174 | 134 | 171 |
| **BLAKE2b-256** | 132 | 161 | 130 | 163 |
| **BLAKE2b-512** | 135 | 173 | 138 | 171 |
| **BLAKE2s** | 132 | 164 | 128 | 161 |
| **BLAKE3** | 143 | 171 | 134 | 181 |
| **AES-128-CTR** | 134 | 176 | 139 | 181 |
| **SipHash-2-4** | 135 | 175 | 134 | 180 |
| **ChaCha20** | 145 | 189 | 143 | 183 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 155 | 222 | 159 | 201 |
| **Areion-SoEM-512** | 155 | 224 | 158 | 204 |
| **BLAKE2b-256** | 143 | 198 | 149 | 194 |
| **BLAKE2b-512** | 152 | 215 | 155 | 208 |
| **BLAKE2s** | 146 | 204 | 146 | 204 |
| **BLAKE3** | 159 | 228 | 162 | 221 |
| **AES-128-CTR** | 162 | 236 | 170 | 221 |
| **SipHash-2-4** | 158 | 230 | 163 | 210 |
| **ChaCha20** | 166 | 238 | 166 | 240 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 187 | 202 | 182 | 207 |
| **Areion-SoEM-512** | 183 | 209 | 182 | 207 |
| **BLAKE2b-256** | 162 | 187 | 158 | 181 |
| **BLAKE2b-512** | 176 | 203 | 168 | 200 |
| **BLAKE2s** | 157 | 179 | 157 | 185 |
| **BLAKE3** | 174 | 191 | 169 | 193 |
| **AES-128-CTR** | 188 | 206 | 188 | 222 |
| **SipHash-2-4** | 187 | 222 | 182 | 223 |
| **ChaCha20** | 177 | 214 | 183 | 221 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 207 | 248 | 213 | 246 |
| **Areion-SoEM-512** | 206 | 249 | 215 | 254 |
| **BLAKE2b-256** | 176 | 221 | 193 | 221 |
| **BLAKE2b-512** | 195 | 239 | 212 | 230 |
| **BLAKE2s** | 180 | 221 | 177 | 201 |
| **BLAKE3** | 197 | 249 | 201 | 229 |
| **AES-128-CTR** | 221 | 267 | 222 | 269 |
| **SipHash-2-4** | 219 | 265 | 227 | 266 |
| **ChaCha20** | 204 | 262 | 203 | 244 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
