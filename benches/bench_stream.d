/// encryptStreamPump throughput vs plaintext size (Streaming
/// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB.
///
/// Env-var overrides identical to bench_message.d except the profile
/// default:
///
/// | env var            | default                    |
/// |--------------------|----------------------------|
/// | ITB_NONCE_BITS     | 512                        |
/// | ITB_KEY_BITS       | 1024                       |
/// | ITB_WITH_PARALLAX  | false                      |
/// | ITB_WITH_WRAPPER   | false                      |
/// | ITB_INNER_HASH     | (profile default)          |
/// | ITB_PROFILE        | streaming-noaead-triple-v1 |
/// | ITB_BENCH_MIN_SEC  | 5                          |
module bench_stream;

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
        benchProfileName("streaming-noaead-triple-v1"), benchBuildOpts());
    benchHeader();
    foreach (size; [size_t(1) << 20, size_t(16) << 20, size_t(64) << 20])
    {
        auto plain = new ubyte[size];
        fillRandom(plain);
        benchCase("stream_pump", size, {
            cast(void) pipe.encryptStreamPump(plain);
        });
        auto wireBorrowed = pipe.encryptStreamPump(plain);
        auto wire = wireBorrowed.dup;
        benchCase("stream_pump-dec", size, {
            cast(void) pipe.decryptStreamPump(wire);
        });
    }
}
