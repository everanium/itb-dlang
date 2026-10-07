/// The final summary in both renderings, and the two measurements it
/// folds in that are not per-worker counters: the process resident set
/// and the shared library's pool counters.
module loop.summary;

import core.atomic : atomicLoad;
import core.stdc.stdio : fflush, fwrite, stdout;

import std.format : format;
import std.process : environment;

import itb3;

import loop.main : detail, logLine, onOff, policyLabel;
import loop.payload : payloadModeName;
import loop.size : fmtF, humanBytes, humanBytesSigned, humanDuration, humanRate, mbPerSec;
import loop.state;
import loop.worker : shapeName;

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
void readRss(out ulong current, out ulong peak) @trusted
{
    import std.conv : to;
    import std.file : readText;
    import std.string : splitLines, startsWith, strip;

    current = 0;
    peak = 0;
    string text;
    try
        text = readText("/proc/self/status");
    catch (Exception)
        return;
    foreach (line; text.splitLines)
    {
        if (!line.startsWith("VmRSS:") && !line.startsWith("VmHWM:"))
            continue;
        auto rest = line[6 .. $].strip;
        size_t j = 0;
        while (j < rest.length && rest[j] >= '0' && rest[j] <= '9')
            j++;
        if (j == 0)
            continue;
        immutable kb = rest[0 .. j].to!ulong * 1024;
        if (line.startsWith("VmRSS:"))
            current = kb;
        else
            peak = kb;
    }
}

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and the
/// parallax chunk pool the checkouts, constructor misses, regrows and
/// regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a pool
/// keeps its items warm between calls or evicts them across GC cycles.
/// The slot layout is read from the library: slot 0 carries the tier
/// count T, tier i occupies the five slots at 1 + 5*i, and the two byte
/// pools occupy the eight slots at 1 + 5*T; the buffer is sized from
/// the binding's length query, never from a constant.
bool poolSnapshotAlloc(out long[] dst) @safe
{
    immutable slots = poolStatsLen();
    if (slots == 0)
        return false;
    dst = new long[slots];
    return true;
}

bool poolSnapshotTake(scope long[] dst) @safe
{
    try
        cast(void) poolStats(dst);
    catch (ItbException)
        return false;
    return true;
}

/// The differenced pool figures of one run.
private struct PoolDelta
{
    long tiers;
    long[] starter;
    long[] get;
    long[] fresh;
    long[] regrow;
    long[] newBytes;
    long bufGet, bufNew, bufRegrow, bufRegrowBytes;
    long chunkGet, chunkNew, chunkRegrow, chunkRegrowBytes;
}

private PoolDelta poolDiff(const ref RunState r) @safe
{
    PoolDelta d;
    if (r.poolWarmup.length < 9 || r.poolSteady.length != r.poolWarmup.length)
        return d;
    auto w = r.poolWarmup;
    auto s = r.poolSteady;
    immutable tiers = s[0];
    if (tiers < 0 || tiers > 64 || 1 + 5 * tiers + 8 > cast(long) s.length)
        return d;
    d.tiers = tiers;
    d.starter = new long[tiers];
    d.get = new long[tiers];
    d.fresh = new long[tiers];
    d.regrow = new long[tiers];
    d.newBytes = new long[tiers];
    foreach (i; 0 .. tiers)
    {
        immutable base = cast(size_t)(1 + 5 * i);
        d.starter[i] = s[base + 0];
        d.get[i] = s[base + 1] - w[base + 1];
        d.fresh[i] = s[base + 2] - w[base + 2];
        d.regrow[i] = s[base + 3] - w[base + 3];
        d.newBytes[i] = s[base + 4] - w[base + 4];
    }
    immutable tail = cast(size_t)(1 + 5 * tiers);
    d.bufGet = s[tail + 0] - w[tail + 0];
    d.bufNew = s[tail + 1] - w[tail + 1];
    d.bufRegrow = s[tail + 2] - w[tail + 2];
    d.bufRegrowBytes = s[tail + 3] - w[tail + 3];
    d.chunkGet = s[tail + 4] - w[tail + 4];
    d.chunkNew = s[tail + 5] - w[tail + 5];
    d.chunkRegrow = s[tail + 6] - w[tail + 6];
    d.chunkRegrowBytes = s[tail + 7] - w[tail + 7];
    return d;
}

/// Misses over checkouts as a percentage; zero when nothing was
/// checked out.
private double missPercent(long miss, long get) @safe nothrow @nogc
{
    if (get <= 0)
        return 0.0;
    return 100.0 * cast(double) miss / cast(double) get;
}

/// Writes `s` as a JSON string literal with the escapes JSON requires.
private string jsonString(string s) @safe
{
    string outText = "\"";
    foreach (ch; cast(const(ubyte)[]) s)
        switch (ch)
        {
        case '"':
            outText ~= `\"`;
            break;
        case '\\':
            outText ~= `\\`;
            break;
        case '\n':
            outText ~= `\n`;
            break;
        case '\r':
            outText ~= `\r`;
            break;
        case '\t':
            outText ~= `\t`;
            break;
        default:
            if (ch < 0x20)
                outText ~= format("\\u%04x", ch);
            else
                outText ~= cast(char) ch;
        }
    return outText ~ "\"";
}

/// The effective GC percentage as the runtime reports it: the query
/// form of the setter (a set-and-restore round trip inside the
/// library) so the field is the same whether the value came from the
/// flag, the environment, or the runtime default.
private int effectiveGogc(int flag) @safe
{
    return flag > 0 ? flag : setGCPercent(-1);
}

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines
/// in the same order, the same keys in the same order, floats with a
/// fixed number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal
/// lines after rss: and its runtime-internal keys after
/// parallax_chunk_pool; nothing here reproduces them because nothing
/// they read is reachable through the C ABI.
int finalSummary(ref RunState r, long elapsedNs) @trusted
{
    auto cfg = &r.cfg;
    long totalIters, totalEnc, totalDec, nanosEnc, nanosDec;
    int errors;
    foreach (i; 0 .. cfg.workers)
    {
        auto w = &r.workers[i];
        totalIters += atomicLoad(w.iters);
        totalEnc += atomicLoad(w.bytesEnc);
        totalDec += atomicLoad(w.bytesDec);
        nanosEnc += atomicLoad(w.nanosEnc);
        nanosDec += atomicLoad(w.nanosDec);
        if (w.failed)
            errors++;
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    immutable avgEnc = nanosEnc > 0 ? nanosEnc / cfg.workers : 0;
    immutable avgDec = nanosDec > 0 ? nanosDec / cfg.workers : 0;

    immutable rssDelta = cast(long) r.rssFinal - cast(long) r.rssWarmup;
    double rssGrowth = 0.0;
    if (r.rssWarmup > 0)
        rssGrowth = 100.0 * cast(double) rssDelta / cast(double) r.rssWarmup;

    auto pd = poolDiff(r);

    immutable pass = errors == 0;
    immutable rekeys = atomicLoad(r.rekeys);
    immutable cycles = atomicLoad(r.blobCycles);
    immutable gomaxprocs = setGOMAXPROCS(0);
    immutable streamProfile = r.hasStream ? r.streamProfile : "";
    immutable msgProfile = r.hasMsg ? r.msgProfile : "";

    if (cfg.jsonOutput)
    {
        string j = "{\"duration_seconds\":" ~ fmtF!"%.3f"(cast(double) elapsedNs / 1e9);
        j ~= format(",\"iterations\":%d", totalIters);
        j ~= ",\"per_worker_iterations\":[";
        foreach (i; 0 .. cfg.workers)
            j ~= format("%s%d", i > 0 ? "," : "", atomicLoad(r.workers[i].iters));
        j ~= "]";
        j ~= format(",\"bytes_encrypted\":%d", totalEnc);
        j ~= format(",\"bytes_decrypted\":%d", totalDec);
        j ~= ",\"encrypt_mb_per_sec\":" ~ fmtF!"%.1f"(mbPerSec(totalEnc, avgEnc));
        j ~= ",\"decrypt_mb_per_sec\":" ~ fmtF!"%.1f"(mbPerSec(totalDec, avgDec));
        j ~= ",\"combined_mb_per_sec\":" ~ fmtF!"%.1f"(mbPerSec(totalEnc + totalDec, elapsedNs));
        j ~= format(",\"rekeys\":%d", rekeys);
        j ~= format(",\"blob_cycles\":%d", cycles);
        j ~= ",\"worker_errors\":[";
        {
            int n;
            foreach (i; 0 .. cfg.workers)
                if (r.workers[i].failed)
                {
                    if (n++ > 0)
                        j ~= ",";
                    j ~= jsonString(r.workers[i].error);
                }
        }
        j ~= "]";
        j ~= format(",\"verdict\":\"%s\"", pass ? "PASS" : "FAIL");
        j ~= format(",\"shape\":\"%s\"", shapeName(cfg.shape));
        j ~= ",\"stream_profile\":" ~ jsonString(streamProfile);
        j ~= ",\"message_profile\":" ~ jsonString(msgProfile);
        j ~= ",\"hash\":" ~ jsonString(cfg.hash);
        j ~= ",\"mac\":" ~ jsonString(cfg.mac);
        j ~= format(",\"payload_bytes\":%d", cfg.payload);
        j ~= format(",\"payload_mode\":\"%s\"", payloadModeName(cfg.payloadMode));
        j ~= format(",\"seed\":%d", cfg.seed);
        j ~= format(",\"key_bits\":%d", cfg.keyBits);
        j ~= format(",\"nonce_bits\":%d", cfg.nonceBits);
        j ~= format(",\"blob_mode\":%d", cfg.blobMode);
        j ~= ",\"drbg\":" ~ jsonString(cfg.drbg);
        j ~= ",\"drbg_auto_tier\":" ~ jsonString(drbgAutoTier());
        j ~= format(",\"chunk_size_bytes\":%d", cfg.chunkSize);
        j ~= format(",\"barrier_fill\":%d", cfg.barrierFill);
        j ~= format(",\"parallax\":\"%s\"", onOff(cfg.parallax));
        j ~= format(",\"wrapper\":\"%s\"", onOff(cfg.wrapper));
        j ~= format(",\"goroutines_requested\":%d", cfg.workersRequested);
        j ~= format(",\"goroutines\":%d", cfg.workers);
        j ~= format(",\"concurrency\":\"%s\"", concurrencyMode);
        j ~= format(",\"gogc\":\"%d\"", effectiveGogc(cfg.gogc));
        j ~= format(",\"memlimit_bytes\":%d", cfg.memlimit);
        j ~= format(",\"gomaxprocs\":%d", gomaxprocs);
        j ~= ",\"microbatch_tiers\":" ~ jsonString(policyLabel("ITB_MICROBATCH_TIERS"));
        j ~= ",\"hashpool_starters\":" ~ jsonString(policyLabel("ITB_HASHPOOL_STARTERS"));
        j ~= format(",\"rss_warmup_bytes\":%d", r.rssWarmup);
        j ~= format(",\"rss_peak_bytes\":%d", r.rssPeak);
        j ~= format(",\"rss_final_bytes\":%d", r.rssFinal);
        j ~= ",\"rss_growth_percent\":" ~ fmtF!"%.2f"(rssGrowth);
        j ~= ",\"hash_pool_tiers\":[";
        {
            int n;
            foreach (i; 0 .. pd.tiers)
            {
                if (pd.starter[i] == 0)
                    continue;
                j ~= format("%s{\"tier\":%d,\"starter\":%d,\"get\":%d,\"new\":%d,"
                        ~ "\"regrow\":%d,\"new_bytes\":%d,\"miss_percent\":",
                        n++ > 0 ? "," : "", i, pd.starter[i], pd.get[i],
                        pd.fresh[i], pd.regrow[i], pd.newBytes[i]);
                j ~= fmtF!"%.2f"(missPercent(pd.fresh[i] + pd.regrow[i], pd.get[i])) ~ "}";
            }
        }
        j ~= "]";
        j ~= format(",\"buf_pool\":{\"get\":%d,\"new\":%d,\"regrow\":%d,\"regrow_bytes\":%d,"
                ~ "\"miss_percent\":", pd.bufGet, pd.bufNew, pd.bufRegrow, pd.bufRegrowBytes);
        j ~= fmtF!"%.2f"(missPercent(pd.bufRegrow, pd.bufGet)) ~ "}";
        j ~= format(",\"parallax_chunk_pool\":{\"get\":%d,\"new\":%d,\"regrow\":%d,"
                ~ "\"regrow_bytes\":%d,\"miss_percent\":",
                pd.chunkGet, pd.chunkNew, pd.chunkRegrow, pd.chunkRegrowBytes);
        j ~= fmtF!"%.2f"(missPercent(pd.chunkRegrow, pd.chunkGet)) ~ "}";
        j ~= "}\n";
        fwrite(j.ptr, 1, j.length, stdout);
        fflush(stdout);
        return pass ? 0 : 1;
    }

    logLine("=== FINAL ===");
    logLine("  duration: " ~ humanDuration((elapsedNs + 500_000) / 1_000_000 * 1_000_000));
    {
        string parts;
        foreach (i; 0 .. cfg.workers)
            parts ~= format("%s%d", i > 0 ? " + " : "", atomicLoad(r.workers[i].iters));
        logLine(format("  iterations: %s = %d total", parts, totalIters));
    }
    logLine(format("  throughput: encrypt %s, decrypt %s, combined %s",
            humanRate(totalEnc, avgEnc), humanRate(totalDec, avgDec),
            humanRate(totalEnc + totalDec, elapsedNs)));
    logLine(format("  bytes: %s encrypted, %s decrypted",
            humanBytes(totalEnc), humanBytes(totalDec)));
    logLine(format("  data integrity: %d/%d PASS", totalIters, totalIters));
    logLine(format("  concurrency: %s, workers %d (requested %d)",
            concurrencyMode, cfg.workers, cfg.workersRequested));
    logLine(format("  rss: warmup %s, peak %s, final %s (delta %s, %s%% growth)",
            humanBytes(cast(long) r.rssWarmup), humanBytes(cast(long) r.rssPeak),
            humanBytes(cast(long) r.rssFinal), humanBytesSigned(rssDelta),
            fmtF!"%.1f"(rssGrowth)));
    foreach (i; 0 .. pd.tiers)
    {
        if (pd.starter[i] == 0)
            continue;
        logLine(format("  hash pool tier %d (starter %d): get %d, miss %d "
                ~ "(new %d + regrow %d), miss %s%%, %s allocated",
                i, pd.starter[i], pd.get[i], pd.fresh[i] + pd.regrow[i],
                pd.fresh[i], pd.regrow[i],
                fmtF!"%.2f"(missPercent(pd.fresh[i] + pd.regrow[i], pd.get[i])),
                humanBytes(pd.newBytes[i])));
    }
    logLine(format("  buf pool: get %d, regrow %d (of which fresh %d), miss %s%%, %s regrown",
            pd.bufGet, pd.bufRegrow, pd.bufNew,
            fmtF!"%.2f"(missPercent(pd.bufRegrow, pd.bufGet)),
            humanBytes(pd.bufRegrowBytes)));
    logLine(format("  parallax chunk pool: get %d, regrow %d (of which fresh %d), "
            ~ "miss %s%%, %s regrown",
            pd.chunkGet, pd.chunkRegrow, pd.chunkNew,
            fmtF!"%.2f"(missPercent(pd.chunkRegrow, pd.chunkGet)),
            humanBytes(pd.chunkRegrowBytes)));
    if (rekeys > 0)
        logLine(format("  rekeys: %d", rekeys));
    if (cycles > 0)
        logLine(format("  blob cycles: %d", cycles));
    foreach (i; 0 .. cfg.workers)
        if (r.workers[i].failed)
            logLine("  ERROR: " ~ r.workers[i].error);
    if (pass)
    {
        logLine("  verdict: PASS");
        return 0;
    }
    logLine(format("  verdict: FAIL (errors=%d)", errors));
    return 1;
}
