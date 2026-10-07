/// Shared declarations of the loop stress harness: the vocabulary,
/// the resolved configuration, the per-worker state and the run state
/// every worker shares.
///
/// D-specific. The unit boundaries need `main` and `worker` to name
/// each other's types, which a module system resolves by putting the
/// shared declarations in a unit of their own; a language whose units
/// may reference each other freely folds these into the units that
/// own them.
module loop.state;

import core.sync.barrier : Barrier;
import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.sync.rwmutex : ReadWriteMutex;
import core.thread : Thread;

import itb3;

// ─── Vocabulary ────────────────────────────────────────────────────

/// Cipher surfaces the --shape flag selects.
enum Shape
{
    stream,        /// session pump: begin / write / read / end
    message,       /// Single Message: one whole-buffer call
    streamOneShot, /// stream surface, one whole-buffer call
    both           /// all three, rotating by iteration number
}

/// Plaintext content policies the --payload-mode flag selects.
enum PayloadMode
{
    fixed,
    rotating,
    patternZero,
    patternFF,
    patternAscii
}

/// --goroutines ceiling; the harness targets modest hosts and each
/// worker pins payload-sized buffers for the whole run.
enum int maxWorkers = 10;

/// The concurrency mode this binding implements, as the summary
/// reports it (shared-handle / independent-handles / single).
enum string concurrencyMode = "shared-handle";

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
enum size_t pumpSlice = 1 << 20;

// ─── Configuration ─────────────────────────────────────────────────

/// The resolved command line.
struct Config
{
    long durationNs;        /// run duration; ignored when iterations > 0
    long iterations;        /// per-worker count incl. warmup; 0 = duration-based
    int workersRequested;   /// the --goroutines value as given
    int workers;            /// the effective worker count
    Shape shape;
    string hash;
    string mac;
    long payload;           /// bytes per iteration
    long memlimit;          /// resolved bytes; the effective limit once shaped
    bool memlimitAuto;      /// --memlimit auto: cap only when the runtime has no limit
    int gogc;               /// 0 = leave the runtime default
    bool parallax;
    bool wrapper;

    string profile;         /// empty = shape-based profile pair
    int keyBits;            /// 0 = profile default
    int nonceBits;          /// 0 = profile default
    int blobMode;           /// container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    long chunkSize;         /// 0 = profile default
    int barrierFill;        /// 0 = profile default
    string drbg;            /// DRBG fill primitive; empty = profile default (auto tier)
    int gomaxprocs;         /// 0 = inherit from the environment
    long rekeyEvery;        /// per-worker iterations between rotations; 0 = never
    long blobCycleEvery;    /// per-worker iterations between reopens; 0 = never
    PayloadMode payloadMode;
    ulong seed;             /// 0 = OS CSPRNG plaintexts
    bool jsonOutput;
    string memprofile;      /// empty = none
}

// ─── Worker and run state ──────────────────────────────────────────

/// One worker's private state: its plaintext, its reusable output
/// buffers, its generator, its counters, and the error it stopped on.
struct Worker
{
    int id;
    RunState* run;
    Thread thread;

    ubyte[] plaintext;
    PayloadMode payloadMode;
    bool seeded;
    ulong rng;              /// splitmix64 state when seeded

    /// D-specific. The pump accumulators are allocated once at their
    /// full working size and refilled in place, with a byte count
    /// beside each, rather than grown by append. An append that grows
    /// allocates inside the iteration, and this runtime's collector
    /// does not survive running there while sibling worker threads are
    /// inside a call into the shared library: a build that grew them
    /// instead terminated on a corrupted stack in roughly one run in
    /// five under three workers on 16 MiB payloads, and the same
    /// difference reproduces outside this utility on the binding's
    /// surface alone. Filling in place keeps the iteration free of
    /// allocation; the message and one-shot entries hand back their own
    /// malloc-backed buffers, which is the posture the binding already
    /// takes on its own cipher path.
    ubyte[] wire;           /// pump-loop wire accumulator
    size_t wireLen;         /// bytes currently held in wire
    ubyte[] plain;          /// pump-loop round-trip accumulator
    size_t plainLen;        /// bytes currently held in plain
    ubyte[] scratch;        /// pump-loop drain slice

    /// Counters read by the summary after every worker has returned.
    shared long iters;
    shared long bytesEnc;
    shared long bytesDec;
    shared long nanosEnc;
    shared long nanosDec;

    bool failed;
    string error;
}

/// The state every worker shares: the Pipeline handles, the retained
/// blobs, the lock that keeps iterations clear of handle mutation, the
/// stop request, the barriers, and the baselines the summary reads.
struct RunState
{
    Config cfg;

    Pipeline streamPipe;    /// live only while hasStream
    Pipeline msgPipe;       /// live only while hasMsg
    bool hasStream;
    bool hasMsg;
    string streamProfile;
    string msgProfile;

    /// Handle mutation. Iterations hold the read side for their whole
    /// encrypt → decrypt → compare; rekey and blob reopen take the
    /// write side, so no cipher call is in flight while a handle's
    /// keying changes or the handle itself is swapped, and no encrypt
    /// is separated from its decrypt by either.
    ReadWriteMutex pipeLock;

    /// The blob Init handed out, replaced by every rekey; the input of
    /// the next blob reopen. Guarded by pipeLock.
    ubyte[] streamBlob;
    ubyte[] msgBlob;

    shared long rekeys;
    shared long blobCycles;

    Worker[] workers;

    /// Warmup barrier: workers arrive at warmupDone after iteration 0
    /// and at release once main has taken the baselines.
    Barrier warmupDone;
    Barrier release;

    /// Set by the duration deadline, by a signal, or by a failing
    /// worker; checked by every worker before it starts an iteration.
    shared bool stop;

    /// Main waits on doneCv for active to reach zero; the last
    /// returning worker stamps finishNs so elapsed excludes the
    /// wake-up latency of the waiter.
    Mutex doneMu;
    Condition doneCv;
    int active;
    long startNs;
    long finishNs;

    /// Baselines taken after the warmup barrier and at shutdown.
    ulong rssWarmup;
    ulong rssPeak;
    ulong rssFinal;
    long[] poolWarmup;
    long[] poolSteady;
}
