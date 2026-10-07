/// Long-run stress harness. The loop utility holds one Pipeline handle
/// per exercised cipher surface for minutes, hammers it with
/// concurrent encrypt → decrypt → compare round-trips from N worker
/// threads, rotates the outer masters and reopens the handle from its
/// session blob on a schedule, and reports whether the process
/// survived with every byte intact. It is the D binding's counterpart
/// of the Go harness under tools/loop: the same flags, the same round
/// structure, the same summary in both renderings.
///
/// The default shape is full production: the Streaming AEAD profile
/// with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
/// inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
/// driven through a stream session by three workers for five minutes
/// on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
/// plaintext held for the whole run, so any cross-call state leakage
/// inside the Pipeline surfaces as a data mismatch between workers
/// rather than cancelling out.
///
/// A failure is one of two things. A cipher, rekey or load call that
/// returns a non-OK status is a worker error: the run stops, the
/// summary lists it, the verdict is FAIL and the exit code 1. A
/// round-trip that returns without error but with different bytes is a
/// data mismatch: the process terminates on the spot with exit code 3,
/// printing the worker, the iteration and the first differing offset,
/// and no summary — the state that produced the wrong bytes is the
/// evidence. A crash inside the shared library or the host runtime has
/// no exit code of its own here; surfacing it is what the utility is
/// for.
///
/// Usage:
///
///   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
///          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
///          --parallax on --wrapper on
///
/// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
/// then the partial summary prints.
module loop.main;

import core.atomic : atomicStore;
import core.stdc.stdio : fflush, fwrite, stderr, stdout;
import core.sync.barrier : Barrier;
import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.sync.rwmutex : ReadWriteMutex;
import core.sys.posix.signal : SIGINT, SIGTERM, sigaction, sigaction_t, sigemptyset;
import core.thread : Thread;
import core.time : dur;

import std.algorithm : canFind, startsWith;
import std.conv : ConvException, to;
import std.format : format;
import std.process : environment;
import std.string : indexOf, strip;

import itb3;

import loop.payload : fillPayload, parsePayloadMode, payloadModeName, seedWorker;
import loop.size : humanBytes, humanDuration, nowNs, parseDuration, parseSize;
import loop.state;
import loop.summary : finalSummary, poolSnapshotAlloc, poolSnapshotTake, readRss;
import loop.worker : parseShape, shapeName, workerMain;

/// Profiles the shape-based pair is built against when --profile is
/// empty.
private enum string defaultStreamProfile = "streaming-aead-triple-mac-v1";
private enum string defaultMessageProfile = "singlemsg-triple-mac-v1";

/// The primitive supplied for the parallax palette and the outer
/// cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
/// so it is sound outside the Interlocked Barrier, and it is the
/// closest relative of the AES-based inner primitive whose profiles
/// need this fill.
private enum string keystreamFillCipher = "aescmac";

// ─── Logging ───────────────────────────────────────────────────────

/// Prints one prefixed status line to stdout. The text, its prefix and
/// its newline leave in one write: workers log concurrently during
/// maintenance, and a routine that emitted them separately would let
/// another worker's line land between the parts.
void logLine(string text) @trusted
{
    immutable line = "[loop] " ~ text ~ "\n";
    fwrite(line.ptr, 1, line.length, stdout);
    fflush(stdout);
}

/// The stderr counterpart, under the same one-write rule.
void errLine(string text) @trusted
{
    immutable line = "loop: " ~ text ~ "\n";
    fwrite(line.ptr, 1, line.length, stderr);
    fflush(stderr);
}

/// Writes text to stderr verbatim, in one call (the usage block).
private void errRaw(string text) @trusted
{
    fwrite(text.ptr, 1, text.length, stderr);
    fflush(stderr);
}

string onOff(bool b) @safe nothrow
{
    return b ? "on" : "off";
}

/// Renders an encoder policy env value for the summary: the raw string
/// when set, "default" when the shipped ladder applies.
string policyLabel(string name) @safe
{
    auto v = environment.get(name);
    if (v is null)
        return "default";
    v = v.strip;
    return v.length ? v : "default";
}

/// Renders a failed library call the way every implementation reports
/// one: the numeric status the binding's own surface carries, then the
/// sentence the library left behind.
///
/// D-specific. The exception's own message carries the same pair under
/// a different punctuation, so the two parts are taken from the
/// binding's surface — the status code off the exception, the sentence
/// off `lastError` — rather than reshaped from that text.
string detail(ItbException e) @safe
{
    return format("status %d: %s", cast(int) e.status, lastError());
}

// ─── Flags ─────────────────────────────────────────────────────────

/// The raw flag values before validation.
private struct RawFlags
{
    int barrierFill = 0;
    long blobCycleEvery = 0;
    int blobMode = 1;
    string chunkSize = "0";
    string drbg = "";
    string duration = "5m";
    int gogc = 0;
    int gomaxprocs = 0;
    int goroutines = 3;
    string hash = "areion512";
    long iterations = 0;
    bool jsonOutput = false;
    int keyBits = 0;
    string mac = "hmac-blake3";
    string memlimit = "auto";
    string memprofile = "";
    int nonceBits = 0;
    string parallax = "on";
    string payloadMode = "fixed";
    string payloadSize = "16MB";
    string profile = "";
    long rekeyEvery = 0;
    ulong seed = 0;
    string shape = "stream";
    string wrapper = "on";
}

/// One command-line flag: its name, the type label the usage prints,
/// the help text, the rendered default suffix, and the assignment that
/// lands the raw value in its slot. Values are validated after the
/// whole line is parsed.
private struct Flag
{
    string name;
    string typeLabel;
    string help;
    bool boolean;
    string defaultSuffix;
    bool delegate(string) @safe assign;
}

/// The flag table, in alphabetical order (the order the usage prints).
/// The default suffix is rendered from the slot while it still holds
/// its default, so the usage can never disagree with the value the
/// parse starts from.
private Flag[] flagTable(ref RawFlags f) @trusted
{
    Flag[] t;
    void addInt(string name, int* slot, string help)
    {
        t ~= Flag(name, "int", help, false,
                *slot != 0 ? format(" (default %d)", *slot) : "",
                (string v) @safe {
            try
                *slot = v.to!int;
            catch (ConvException)
                return false;
            return true;
        });
    }

    void addLong(string name, long* slot, string help)
    {
        t ~= Flag(name, "int", help, false, "", (string v) @safe {
            try
                *slot = v.to!long;
            catch (ConvException)
                return false;
            return true;
        });
    }

    void addULong(string name, ulong* slot, string help)
    {
        t ~= Flag(name, "uint", help, false, "", (string v) @safe {
            if (v.length == 0 || v[0] == '-')
                return false;
            try
                *slot = v.to!ulong;
            catch (ConvException)
                return false;
            return true;
        });
    }

    void addString(string name, string label, string* slot, string help)
    {
        t ~= Flag(name, label, help, false,
                slot.length ? format(" (default \"%s\")", *slot) : "",
                (string v) @safe { *slot = v; return true; });
    }

    void addBool(string name, bool* slot, string help)
    {
        t ~= Flag(name, "", help, true, "", (string v) @safe {
            if (v == "true")
                *slot = true;
            else if (v == "false")
                *slot = false;
            else
                return false;
            return true;
        });
    }

    addInt("barrier-fill", &f.barrierFill,
            "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)");
    addLong("blob-cycle-every", &f.blobCycleEvery,
            "reopen each pipeline from its session blob every N iterations per worker; 0 = never");
    addInt("blob-mode", &f.blobMode,
            "container floor sizing mode: 1 (per-region, default) | 2 (per-container)");
    addString("chunk-size", "string", &f.chunkSize,
            "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape");
    addString("drbg", "string", &f.drbg,
            "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)");
    addString("duration", "duration", &f.duration,
            "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0");
    addInt("gogc", &f.gogc, "GC trigger percentage; 0 = leave the runtime default");
    addInt("gomaxprocs", &f.gomaxprocs,
            "Go runtime GOMAXPROCS override; 0 = inherit from the environment");
    addInt("goroutines", &f.goroutines,
            "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1");
    addString("hash", "string", &f.hash, "inner ITB hash primitive name");
    addLong("iterations", &f.iterations,
            "fixed per-worker iteration count; 0 = duration-based");
    addBool("json-output", &f.jsonOutput,
            "print the final summary as one compact JSON object instead of log lines");
    addInt("key-bits", &f.keyBits,
            "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)");
    addString("mac", "string", &f.mac, "MAC primitive name");
    addString("memlimit", "string", &f.memlimit,
            "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)");
    addString("memprofile", "string", &f.memprofile,
            "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none");
    addInt("nonce-bits", &f.nonceBits,
            "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)");
    addString("parallax", "string", &f.parallax, "parallax layer: on | off");
    addString("payload-mode", "string", &f.payloadMode,
            "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii");
    addString("payload-size", "string", &f.payloadSize,
            "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)");
    addString("profile", "string", &f.profile,
            "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair");
    addLong("rekey-every", &f.rekeyEvery,
            "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never");
    addULong("seed", &f.seed,
            "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts");
    addString("shape", "string", &f.shape,
            "cipher surface to exercise: stream | message | stream_one_shot | both");
    addString("wrapper", "string", &f.wrapper, "wrapper layer: on | off");
    return t;
}

private void usage(const Flag[] table) @safe
{
    string outText = "Usage of loop:\n";
    foreach (fl; table)
    {
        outText ~= format("  -%s%s%s\n", fl.name, fl.typeLabel.length ? " " : "", fl.typeLabel);
        outText ~= format("    \t%s%s\n", fl.help, fl.defaultSuffix);
    }
    errRaw(outText);
}

/// Parses argv into the raw flag values. Accepts -name value,
/// --name value, -name=value and --name=value; a boolean flag takes no
/// value unless given as -name=true / -name=false. Returns 0, 1 for
/// -h / --help (usage printed), or -1 after printing the error.
private int parseArgv(string[] argv, Flag[] table) @trusted
{
    for (size_t i = 1; i < argv.length; i++)
    {
        auto arg = argv[i];
        if (arg.length < 2 || arg[0] != '-')
        {
            errLine(format("unexpected positional arguments: [%s]", arg));
            return -1;
        }
        auto name = arg[arg[1] == '-' ? 2 : 1 .. $];
        if (name == "h" || name == "help")
        {
            usage(table);
            return 1;
        }
        string value;
        bool haveValue;
        immutable eq = name.indexOf('=');
        if (eq >= 0)
        {
            value = name[eq + 1 .. $];
            haveValue = true;
            name = name[0 .. eq];
        }
        ptrdiff_t at = -1;
        foreach (k, ref candidate; table)
            if (name == candidate.name)
            {
                at = k;
                break;
            }
        if (at < 0)
        {
            errLine(format("flag provided but not defined: -%s", name));
            usage(table);
            return -1;
        }
        auto fl = &table[at];
        if (!haveValue)
        {
            if (fl.boolean)
                value = "true";
            else if (i + 1 < argv.length)
                value = argv[++i];
            else
            {
                errLine(format("flag needs an argument: -%s", fl.name));
                return -1;
            }
        }
        if (!fl.assign(value))
        {
            errLine(format("invalid value \"%s\" for flag -%s", value, fl.name));
            return -1;
        }
    }
    return 0;
}

/// Maps "on" / "off" to a bool; false otherwise.
private bool parseOnOff(string v, out bool outValue) @safe nothrow
{
    if (v == "on")
    {
        outValue = true;
        return true;
    }
    if (v == "off")
    {
        outValue = false;
        return true;
    }
    return false;
}

/// Whether `name` is in the shipped hash registry the binding
/// enumerates. The registry is the authority the flag validation
/// reads; reaching it any other way would reach past the binding.
private bool hashRegistered(string name) @safe
{
    try
        return hashNames().canFind(name);
    catch (ItbException)
        return false;
}

/// Folds a keystream primitive into opts for any layer the named
/// profile leaves unfilled but the operator asked for.
///
/// A profile built around a primitive that is safe only inside the
/// Interlocked Barrier ships with no parallax palette and no outer
/// cipher: both layers run outside the barrier, where that primitive
/// would stand bare, so the recipe leaves them unnamed rather than
/// naming a primitive that must not key them. Engaging either layer
/// therefore needs a keystream-capable primitive supplied from outside
/// the recipe; without it construction fails on a palette below its
/// minimum or an unnamed outer cipher, and the primitive that most
/// deserves stressing becomes the one that cannot be stressed with
/// those layers engaged.
///
/// Overrides fold into the resolved record the blob carries, so the
/// receiver rebuilds the same shape from the blob alone.
///
/// D-specific. The binding decodes the record into a typed value, so
/// the unfilled state is an empty palette / outer-cipher field rather
/// than an absent JSON key.
///
/// Returns 1 when a layer was filled, 0 when none needed it, -1 on a
/// lookup failure (message already printed).
private int fillKeystreamLayers(string name, ref Opts opts,
        bool wantParallax, bool wantWrapper) @safe
{
    Profile record;
    try
        record = lookup(name);
    catch (ItbException)
    {
        errLine(format("--profile \"%s\" is not a registered triple profile", name));
        return -1;
    }
    int filled;
    if (wantParallax && record.parallaxPalette.length == 0)
    {
        opts = opts.withParallaxPalette(
                [keystreamFillCipher, keystreamFillCipher, keystreamFillCipher]);
        if (record.parallaxSegmentSize == 0)
            // A recipe that never carried a palette never carried a
            // segment size either, and the schedule rejects zero.
            opts = opts.withParallaxSegmentSize(4093);
        filled = 1;
    }
    if (wantWrapper && record.outerCipher.length == 0)
    {
        opts = opts.withOuterCipher(keystreamFillCipher);
        filled = 1;
    }
    return filled;
}

/// Resolves a registered profile to the shape family its record's mode
/// exposes by reading the record through the binding's lookup: a mode
/// beginning with "streaming" exposes the stream surfaces, one
/// beginning with "singlemsg" the message surface, "blob-only" none.
/// Prints the validation message and returns false on rejection.
private bool profileSurface(string name, out Shape surface) @safe
{
    Profile record;
    try
        record = lookup(name);
    catch (ItbException)
    {
        errLine(format("--profile \"%s\" is not a registered triple profile", name));
        return false;
    }
    if (record.mode.startsWith("streaming"))
    {
        surface = Shape.stream;
        return true;
    }
    if (record.mode.startsWith("singlemsg"))
    {
        surface = Shape.message;
        return true;
    }
    errLine(format("--profile \"%s\" carries no cipher surface (blob-only mode)", name));
    return false;
}

/// Applies a --profile's surface to the requested shape: a
/// message-surface profile forces message; a stream-surface profile
/// keeps stream or stream_one_shot as requested and turns message or
/// both into stream.
private Shape narrowShape(Shape requested, Shape surface) @safe nothrow
{
    if (surface == Shape.message)
        return Shape.message;
    return requested == Shape.streamOneShot ? Shape.streamOneShot : Shape.stream;
}

/// Builds the resolved config from argv. Returns 0, 1 for help, or -1
/// after printing "loop: <message>" for the first failing rule.
private int parseFlags(string[] argv, ref Config cfg) @safe
{
    RawFlags f;
    auto table = flagTable(f);
    immutable rc = parseArgv(argv, table);
    if (rc != 0)
        return rc;

    if (!parseDuration(f.duration, cfg.durationNs) || cfg.durationNs <= 0)
    {
        errLine(format("--duration must be positive, got %s", f.duration));
        return -1;
    }
    cfg.iterations = f.iterations;
    if (cfg.iterations < 0)
    {
        errLine(format("--iterations must be >= 0, got %d", cfg.iterations));
        return -1;
    }
    if (f.goroutines < 1 || f.goroutines > maxWorkers)
    {
        errLine(format("--goroutines must be in 1..%d, got %d", maxWorkers, f.goroutines));
        return -1;
    }
    // Concurrency mode. This binding runs shared-handle: druntime
    // threads call into one Pipeline handle concurrently, which the
    // shared library permits after construction, so --goroutines is
    // the thread count verbatim, never clamped.
    cfg.workersRequested = f.goroutines;
    cfg.workers = f.goroutines;
    if (!parseShape(f.shape, cfg.shape))
    {
        errLine(format("--shape must be stream | message | stream_one_shot | both, got \"%s\"",
                f.shape));
        return -1;
    }
    if (!hashRegistered(f.hash))
    {
        errLine(format("--hash \"%s\" is not a registered hash primitive", f.hash));
        return -1;
    }
    cfg.hash = f.hash;
    cfg.mac = f.mac; // validated by Init: the C ABI enumerates no MAC names
    if (!parseSize(f.payloadSize, cfg.payload))
    {
        errLine(format("--payload-size: invalid size \"%s\"", f.payloadSize));
        return -1;
    }
    if (cfg.payload < 1)
    {
        errLine("--payload-size must be at least 1 byte");
        return -1;
    }
    if (f.memlimit == "auto")
    {
        cfg.memlimitAuto = true;
        cfg.memlimit = cfg.workers <= 3 ? (1L << 30) : (256L << 20);
    }
    else if (!parseSize(f.memlimit, cfg.memlimit))
    {
        errLine(format("--memlimit: invalid size \"%s\"", f.memlimit));
        return -1;
    }
    cfg.gogc = f.gogc;
    if (cfg.gogc < 0)
    {
        errLine(format("--gogc must be >= 0, got %d", cfg.gogc));
        return -1;
    }
    if (!parseOnOff(f.parallax, cfg.parallax))
    {
        errLine(format("--parallax must be on | off, got \"%s\"", f.parallax));
        return -1;
    }
    if (!parseOnOff(f.wrapper, cfg.wrapper))
    {
        errLine(format("--wrapper must be on | off, got \"%s\"", f.wrapper));
        return -1;
    }
    cfg.profile = f.profile;
    if (cfg.profile.length)
    {
        Shape surface;
        if (!profileSurface(cfg.profile, surface))
            return -1;
        cfg.shape = narrowShape(cfg.shape, surface);
    }
    cfg.keyBits = f.keyBits;
    switch (cfg.keyBits)
    {
    case 0:
    case 512:
    case 1024:
    case 2048:
        break;
    default:
        errLine(format("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d",
                cfg.keyBits));
        return -1;
    }
    cfg.nonceBits = f.nonceBits;
    switch (cfg.nonceBits)
    {
    case 0:
    case 128:
    case 256:
    case 512:
        break;
    default:
        errLine(format("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d",
                cfg.nonceBits));
        return -1;
    }
    cfg.blobMode = f.blobMode;
    switch (cfg.blobMode)
    {
    case 1:
    case 2:
        break;
    default:
        errLine(format("--blob-mode must be 1 (per-region) | 2 (per-container), got %d",
                cfg.blobMode));
        return -1;
    }
    cfg.barrierFill = f.barrierFill;
    switch (cfg.barrierFill)
    {
    case 0:
    case 1:
    case 2:
    case 4:
    case 8:
    case 16:
    case 32:
        break;
    default:
        errLine(format("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d",
                cfg.barrierFill));
        return -1;
    }
    cfg.drbg = f.drbg; // validated by Init: the C ABI enumerates no DRBG names
    if (!parseSize(f.chunkSize, cfg.chunkSize))
    {
        errLine(format("--chunk-size: invalid size \"%s\"", f.chunkSize));
        return -1;
    }
    cfg.gomaxprocs = f.gomaxprocs;
    if (cfg.gomaxprocs < 0)
    {
        errLine(format("--gomaxprocs must be > 0 when specified, got %d", cfg.gomaxprocs));
        return -1;
    }
    cfg.rekeyEvery = f.rekeyEvery;
    if (cfg.rekeyEvery < 0)
    {
        errLine(format("--rekey-every must be >= 0, got %d", cfg.rekeyEvery));
        return -1;
    }
    cfg.blobCycleEvery = f.blobCycleEvery;
    if (cfg.blobCycleEvery < 0)
    {
        errLine(format("--blob-cycle-every must be >= 0, got %d", cfg.blobCycleEvery));
        return -1;
    }
    if (!parsePayloadMode(f.payloadMode, cfg.payloadMode))
    {
        errLine(format("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"%s\"",
                f.payloadMode));
        return -1;
    }
    cfg.seed = f.seed;
    cfg.jsonOutput = f.jsonOutput;
    cfg.memprofile = f.memprofile;
    return 0;
}

// ─── Signals ───────────────────────────────────────────────────────

private __gshared int signalSeen = 0;

private extern (C) void onSignal(int) nothrow @nogc @system
{
    signalSeen = 1;
}

/// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
/// while it waits for the workers; it turns the flag into the stop
/// request every worker checks before starting an iteration, so a
/// signal interrupts nothing mid-call — the in-flight encrypt /
/// decrypt / compare completes, the worker returns, and the partial
/// summary prints with the verdict the completed iterations earned.
private void installSignals() @trusted
{
    sigaction_t sa;
    sa.sa_handler = &onSignal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, null);
    sigaction(SIGTERM, &sa, null);
}

// ─── Pipelines ─────────────────────────────────────────────────────

/// Prints the construction line with the recipe read back from the
/// blob the Pipeline handed out, not echoed from the flags: every
/// construction override is proven to have reached the library by the
/// value the receiver would see. Record values that are empty (a No
/// MAC profile's MAC, a mixed profile's single hash) print as "-".
private void logPipelineInitialised(string profile, scope const(ubyte)[] blob) @safe
{
    Profile record;
    try
        record = inspect(blob);
    catch (ItbException)
    {
        logLine(format("pipeline initialised: profile=%s blob=%d bytes (inspect: %s)",
                profile, blob.length, lastError()));
        return;
    }
    string line = format("pipeline initialised: profile=%s blob=%d bytes hash=%s key-bits=%d "
            ~ "nonce-bits=%d barrier-fill=%d chunk-size=%d mac=%s parallax=%s wrapper=%s",
            profile, blob.length,
            record.innerHash.length ? record.innerHash : "-", record.keyBits,
            record.nonceBits.isNull ? 0 : record.nonceBits.get,
            record.barrierFill.isNull ? 0 : record.barrierFill.get,
            record.chunkSize, record.macName.length ? record.macName : "-",
            onOff(record.parallax), onOff(record.wrapper));
    if (!record.containerMode.isNull && record.containerMode.get == 2)
        line ~= " container-mode=2";
    if (record.drbg.length)
        line ~= " drbg=" ~ record.drbg;
    logLine(line);
}

/// Sets the inner blob's "mode" field of a wrap-layer session blob to
/// `targetMode` (1 = per-region, 2 = per-container) in place. The wrap
/// layer's profile record carries its own "mode" (a string), so the
/// search starts at the inner blob ("ib"); both shipped modes are one
/// digit wide, so the blob length does not change. Returns false when
/// the inner blob or its mode field is not found.
private bool editInnerBlobMode(ubyte[] blob, int targetMode) @safe
{
    import std.algorithm.searching : countUntil;

    immutable ubyte[] ibKey = cast(immutable(ubyte)[]) `"ib":{`;
    immutable ubyte[] modeKey = cast(immutable(ubyte)[]) `"mode":`;
    immutable ib = blob.countUntil(ibKey);
    if (ib < 0)
        return false;
    immutable off = ib + ibKey.length;
    immutable mode = blob[off .. $].countUntil(modeKey);
    if (mode < 0)
        return false;
    immutable at = off + mode + modeKey.length;
    if (at + 1 >= blob.length || blob[at] < '1' || blob[at] > '2'
            || (blob[at + 1] >= '0' && blob[at + 1] <= '9'))
        return false;
    blob[at] = cast(ubyte)('0' + targetMode);
    return true;
}

/// Constructs one Pipeline against `profile` with every flag-carried
/// override in the opts string (zero values included — the shared
/// library treats zero as "profile default"), then obtains the Init
/// blob once through save: the binding's init entry does not hand the
/// blob back, and the bytes are the ones Init produced. Later blob
/// reopens use the retained blob; save is never called again.
private bool buildPipeline(const ref Config cfg, string profile,
        ref Pipeline pipe, ref bool present, ref ubyte[] blob) @trusted
{
    auto opts = Opts()
        .withInnerHash(cfg.hash)
        .withMacName(cfg.mac)
        .withParallax(cfg.parallax)
        .withWrapper(cfg.wrapper)
        .withKeyBits(cfg.keyBits)
        .withNonceBits(cfg.nonceBits)
        .withBarrierFill(cfg.barrierFill)
        .withDrbg(cfg.drbg)
        .withChunkSize(cfg.chunkSize);
    if (cfg.profile.length)
    {
        immutable filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper);
        if (filled < 0)
            return false;
        if (filled > 0)
            errLine(format("%s leaves the requested keystream layers unnamed; %s supplied for them",
                    cfg.profile, keystreamFillCipher));
    }

    try
        pipe = Pipeline.create(profile, opts);
    catch (ItbException e)
    {
        errLine(format("Init(%s): %s", profile, detail(e)));
        return false;
    }
    present = true;
    try
        blob = pipe.save();
    catch (ItbException e)
    {
        errLine(format("Save(%s): %s", profile, detail(e)));
        return false;
    }
    if (cfg.blobMode == 2)
    {
        import std.algorithm.mutation : move;

        // The sizing mode is not an Opts knob: the Init blob is edited
        // and the pipeline reopened from it, so the retained blob (the
        // one blob-cycle reopens from) carries the edited mode.
        if (!editInnerBlobMode(blob, 2))
        {
            errLine("rewrite blob mode: inner blob mode field not found");
            return false;
        }
        try
        {
            // D-specific. The move-assignment releases the Init handle.
            auto fresh = Pipeline.load(blob);
            pipe = move(fresh);
        }
        catch (ItbException e)
        {
            errLine(format("reload Mode 2 blob: %s", detail(e)));
            return false;
        }
    }
    logPipelineInitialised(profile, blob);
    return true;
}

// ─── Run ───────────────────────────────────────────────────────────

/// D-specific. Module-level state is thread-local by default, so the
/// run state every worker shares is declared __gshared.
private __gshared RunState runState;

/// D-specific. A delegate literal written inside the launch loop would
/// close over that loop's own frame, so every thread would run against
/// whichever worker the last iteration left there. Binding the pointer
/// in a function of its own gives each thread a frame of its own.
private Thread spawnWorker(Worker* wp) @trusted
{
    return new Thread({ workerMain(wp); });
}

private int run(string[] argv) @trusted
{
    auto r = &runState;
    auto cfg = &r.cfg;
    immutable rc = parseFlags(argv, *cfg);
    if (rc == 1)
        return 0;
    if (rc != 0)
        return 2;

    // Runtime shaping. A long run under allocation churn grows the Go
    // heap inside the shared library without bound unless a soft limit
    // paces the collector, so a limit is always in force: an explicit
    // --memlimit is set as given, and auto caps the heap only when the
    // runtime reports no limit at all (a limit already installed from
    // the environment is left standing). The GC percentage and
    // GOMAXPROCS are set only when their flag is non-zero — a zero flag
    // skips the setter rather than calling it with zero, because zero
    // is a real value to the GC-percent setter, and a call would
    // clobber whatever the environment installed. All of it lands
    // before any Pipeline exists so the baselines are taken under the
    // shaped runtime.
    if (cfg.memlimitAuto)
    {
        if (setMemoryLimit(-1) == long.max)
            cast(void) setMemoryLimit(cfg.memlimit);
    }
    else
        cast(void) setMemoryLimit(cfg.memlimit);
    cfg.memlimit = setMemoryLimit(-1);
    if (cfg.gogc > 0)
        cast(void) setGCPercent(cfg.gogc);
    if (cfg.gomaxprocs > 0)
        cast(void) setGOMAXPROCS(cfg.gomaxprocs);

    logLine(format("start: duration=%s iterations=%d goroutines=%d workers=%d concurrency=%s "
            ~ "shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s",
            humanDuration(cfg.durationNs), cfg.iterations, cfg.workersRequested, cfg.workers,
            concurrencyMode, shapeName(cfg.shape), cfg.hash, cfg.mac,
            humanBytes(cfg.payload), humanBytes(cfg.memlimit),
            onOff(cfg.parallax), onOff(cfg.wrapper)));
    logLine(format("overrides: profile=\"%s\" key-bits=%d nonce-bits=%d chunk-size=%s "
            ~ "barrier-fill=%d gomaxprocs=%d rekey-every=%d blob-cycle-every=%d "
            ~ "payload-mode=%s seed=%d json-output=%s",
            cfg.profile, cfg.keyBits, cfg.nonceBits, humanBytes(cfg.chunkSize),
            cfg.barrierFill, cfg.gomaxprocs, cfg.rekeyEvery, cfg.blobCycleEvery,
            payloadModeName(cfg.payloadMode), cfg.seed,
            cfg.jsonOutput ? "true" : "false")
            ~ (cfg.blobMode != 1 ? format(" blob-mode=%d", cfg.blobMode) : "")
            ~ (cfg.drbg.length ? " drbg=" ~ cfg.drbg : ""));
    logLine(format("policy: microbatch-tiers=%s hashpool-starters=%s",
            policyLabel("ITB_MICROBATCH_TIERS"), policyLabel("ITB_HASHPOOL_STARTERS")));

    // Pipeline construction — one shared handle per exercised shape.
    // stream and stream_one_shot share the streaming handle.
    r.streamProfile = cfg.profile.length ? cfg.profile : defaultStreamProfile;
    r.msgProfile = cfg.profile.length ? cfg.profile : defaultMessageProfile;
    if (cfg.shape == Shape.stream || cfg.shape == Shape.streamOneShot || cfg.shape == Shape.both)
        if (!buildPipeline(*cfg, r.streamProfile, r.streamPipe, r.hasStream, r.streamBlob))
            return 1;
    if (cfg.shape == Shape.message || cfg.shape == Shape.both)
        if (!buildPipeline(*cfg, r.msgProfile, r.msgPipe, r.hasMsg, r.msgBlob))
            return 1;

    // Allocation posture. Per-worker plaintexts are allocated once and
    // held for the whole run (rotating mode refills them in place per
    // iteration); the pump accumulators and the drain slice live inside
    // each worker and are reused across iterations; the message and
    // one-shot outputs are handed back per call and released at the end
    // of the iteration. Under the default fixed CSPRNG mode every
    // worker's buffer is distinct, so cross-worker data crossover is
    // detectable; pattern modes trade that property for content
    // edge-case coverage.
    r.workers = new Worker[cfg.workers];
    foreach (i; 0 .. cfg.workers)
    {
        auto w = &r.workers[i];
        w.id = i;
        w.run = r;
        w.plaintext = new ubyte[cast(size_t) cfg.payload];
        // The wire accumulator is sized to the encrypt-side envelope
        // (payload plus expansion and framing) and the round-trip one
        // to the plaintext, so the pump refills them in place instead
        // of growing them inside an iteration.
        immutable size_t payloadBytes = cast(size_t) cfg.payload;
        w.wire = new ubyte[payloadBytes + payloadBytes / 4 + 131_072];
        w.plain = new ubyte[payloadBytes];
        w.scratch = new ubyte[pumpSlice];
        w.payloadMode = cfg.payloadMode;
        w.seeded = cfg.seed != 0;
        w.rng = seedWorker(cfg.seed, i);
        if (!fillPayload(cfg.payloadMode, w.seeded, w.rng, w.plaintext))
        {
            errLine("payload fill: csprng");
            return 1;
        }
    }

    if (!poolSnapshotAlloc(r.poolWarmup) || !poolSnapshotAlloc(r.poolSteady))
    {
        errLine("pool snapshot alloc failed");
        return 1;
    }

    installSignals();
    r.pipeLock = new ReadWriteMutex();
    r.doneMu = new Mutex();
    r.doneCv = new Condition(r.doneMu);
    r.warmupDone = new Barrier(cast(uint)(cfg.workers + 1));
    r.release = new Barrier(cast(uint)(cfg.workers + 1));
    atomicStore(r.stop, false);
    r.active = cfg.workers;

    // Warmup barrier. Every worker runs one iteration and waits; the
    // clock starts only once all of them have paid their first-call
    // costs (pool warm-up, lazy kernel dispatch, page faults on the
    // payload buffers), and the RSS and pool baselines taken here
    // describe a process that has already run the whole cipher path
    // once per worker.
    immutable warmupStart = nowNs();
    foreach (i; 0 .. cfg.workers)
    {
        auto t = spawnWorker(&r.workers[i]);
        r.workers[i].thread = t;
        t.start();
    }
    r.warmupDone.wait();
    readRss(r.rssWarmup, r.rssPeak);
    cast(void) poolSnapshotTake(r.poolWarmup);
    immutable warmupNs = nowNs() - warmupStart;
    logLine(format("warmup: %d workers x 1 iter completed in %s (baseline rss=%s)",
            cfg.workers, humanDuration((warmupNs + 50_000_000) / 100_000_000 * 100_000_000),
            humanBytes(cast(long) r.rssWarmup)));

    // Open the gate; the duration timer is a deadline the waiter below
    // enforces in duration mode.
    r.startNs = nowNs();
    r.finishNs = r.startNs;
    r.release.wait();

    // Wait for every worker, polling every 100 ms so the deadline and a
    // signal are both noticed promptly.
    synchronized (r.doneMu)
    {
        while (r.active > 0)
        {
            if (signalSeen != 0)
                atomicStore(r.stop, true);
            if (cfg.iterations == 0 && nowNs() - r.startNs >= cfg.durationNs)
                atomicStore(r.stop, true);
            cast(void) r.doneCv.wait(dur!"msecs"(100));
        }
    }
    foreach (i; 0 .. cfg.workers)
        r.workers[i].thread.join();
    immutable elapsedNs = r.finishNs - r.startNs;
    readRss(r.rssFinal, r.rssPeak);
    cast(void) poolSnapshotTake(r.poolSteady);

    if (cfg.memprofile.length)
    {
        try
        {
            writeHeapProfile(cfg.memprofile);
            logLine("memprofile: heap profile written to " ~ cfg.memprofile);
        }
        catch (ItbException)
            errLine("memprofile: " ~ lastError());
    }

    return finalSummary(*r, elapsedNs);
}

int main(string[] argv)
{
    return run(argv);
}
