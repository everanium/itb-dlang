/// EncryptMessage throughput vs plaintext size (Single Message
/// profile) at 1 MiB / 16 MiB / 64 MiB.
///
/// Bench configuration is driven by environment variables so a
/// side-by-side comparison with the root Go bench harness is
/// straightforward:
///
/// | env var            | default                   |
/// |--------------------|---------------------------|
/// | ITB_NONCE_BITS     | 512                       |
/// | ITB_KEY_BITS       | 1024                      |
/// | ITB_WITH_PARALLAX  | false                     |
/// | ITB_WITH_WRAPPER   | false                     |
/// | ITB_INNER_HASH     | (profile default)         |
/// | ITB_PROFILE        | singlemsg-triple-nomac-v1 |
/// | ITB_BENCH_MIN_SEC  | 5                         |
module bench_message;

import bench_util;
import itb;

void main()
{
    // Bench-scale allocation churn leaks Go scratch heap unboundedly
    // without a soft memory cap + aggressive GC; the return values
    // report the previous settings, not an error.
    cast(void) setMemoryLimit(512L * 1024 * 1024); // 512 MiB soft cap
    cast(void) setGCPercent(20);                   // aggressive GC

    auto pipe = Pipeline.create(
        benchProfileName("singlemsg-triple-nomac-v1"), benchBuildOpts());
    benchHeader();
    foreach (size; [size_t(1) << 20, size_t(16) << 20, size_t(64) << 20])
    {
        auto plain = new ubyte[size];
        fillRandom(plain);
        benchCase("message", size, {
            cast(void) pipe.encryptMessage(plain);
        });
        // Pre-encrypt one wire for the decrypt timing loop; a copy is
        // taken so the borrowed slice never overlaps subsequent calls.
        auto wireBorrowed = pipe.encryptMessage(plain);
        auto wire = wireBorrowed.dup;
        benchCase("message-dec", size, {
            cast(void) pipe.decryptMessage(wire);
        });
    }
}
