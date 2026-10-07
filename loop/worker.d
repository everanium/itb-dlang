/// The worker: its thread body (one warmup iteration, the warmup
/// barrier, the main loop), one iteration, the session pump loop the
/// stream shape drives, and the round-trip comparison that decides
/// between a worker error and a data mismatch.
module loop.worker;

import core.atomic : atomicFetchAdd, atomicLoad, atomicStore;
import core.stdc.stdlib : _Exit;

import std.format : format;

import itb3;

import loop.main : detail, errLine;
import loop.ops : workerMaintenance;
import loop.payload : fillPayload;
import loop.size : nowNs;
import loop.state;

private static immutable string[] shapeNames = [
    "stream", "message", "stream_one_shot", "both",
];

string shapeName(Shape shape) @safe nothrow
{
    return shapeNames[cast(size_t) shape];
}

bool parseShape(string s, out Shape outShape) @safe nothrow
{
    foreach (i, name; shapeNames)
        if (s == name)
        {
            outShape = cast(Shape) i;
            return true;
        }
    return false;
}

/// Records the worker's error text (first error wins) and requests a
/// stop of the whole run.
void workerFail(ref Worker w, string text) @trusted
{
    if (!w.failed)
    {
        w.error = text;
        w.failed = true;
    }
    atomicStore(w.run.stop, true);
}

/// First offset at which `a` and `b` differ; the shorter length when
/// one is a prefix of the other.
private size_t firstDifference(scope const(ubyte)[] a, scope const(ubyte)[] b) @safe nothrow @nogc
{
    immutable n = a.length < b.length ? a.length : b.length;
    foreach (i; 0 .. n)
        if (a[i] != b[i])
            return i;
    return n;
}

/// Up to 16 bytes of `buf` from `off` as lowercase hex, or "-" when
/// `buf` has no bytes there.
private string hexWindow(scope const(ubyte)[] buf, size_t off) @safe
{
    if (off >= buf.length)
        return "-";
    immutable end = off + 16 < buf.length ? off + 16 : buf.length;
    string outText;
    foreach (b; buf[off .. end])
        outText ~= format("%02x", b);
    return outText;
}

/// Records a worker error for a failed cipher call. `stage` names the
/// session step for a pump failure and is empty for a whole-buffer
/// call, whose only step is the direction itself.
private void cipherFail(ref Worker w, long iter, Shape shape, string direction,
        string stage, ItbException e) @safe
{
    if (stage.length == 0 || stage == direction)
        workerFail(w, format("g%d iter %d shape=%s: %s: %s",
                w.id, iter, shapeName(shape), direction, detail(e)));
    else
        workerFail(w, format("g%d iter %d shape=%s: %s: %s: %s",
                w.id, iter, shapeName(shape), direction, stage, detail(e)));
}

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the C ABI has no reader /
/// writer entry, so the caller drives it: open a session, feed slices
/// of at most 1 MiB, drain whatever the session has produced after
/// every write (a read before end never blocks), end, then drain until
/// the session reports finished (after end, a read on an empty spool
/// blocks until the terminal bytes arrive). The whole produced output
/// lands in the worker's reusable accumulator. The loop is written
/// here rather than delegated to the binding's pump convenience so it
/// stands in the utility, at the same place, in every language.
private void pumpBody(Session)(ref Worker w, ref Session session,
        scope const(ubyte)[] src, ref ubyte[] acc, ref size_t used,
        ref string stage) @trusted
{
    void put(scope const(ubyte)[] bytes)
    {
        if (used + bytes.length > acc.length)
            acc.length = used + bytes.length;
        acc[used .. used + bytes.length] = bytes[];
        used += bytes.length;
    }

    size_t off = 0;
    while (off < src.length)
    {
        immutable hi = off + pumpSlice < src.length ? off + pumpSlice : src.length;
        stage = "StreamWrite";
        session.write(src[off .. hi]);
        off = hi;
        for (;;)
        {
            stage = "StreamRead";
            bool finished;
            immutable n = session.read(w.scratch, finished);
            if (n == 0)
                break;
            put(w.scratch[0 .. n]);
        }
    }
    stage = "StreamEnd";
    session.end();
    for (;;)
    {
        stage = "StreamRead";
        bool finished;
        immutable n = session.read(w.scratch, finished);
        put(w.scratch[0 .. n]);
        if (finished)
            return;
    }
}

/// Runs one direction of the pump against the streaming Pipeline.
/// Returns null on success, or the exception the failing step threw
/// with that step's name left in `stage`.
private ItbException pump(ref Worker w, ref Pipeline pipe, bool encrypt,
        scope const(ubyte)[] src, ref ubyte[] acc, ref size_t used,
        ref string stage) @trusted
{
    used = 0;
    try
    {
        stage = "StreamBegin";
        if (encrypt)
        {
            auto session = pipe.encryptStream();
            pumpBody(w, session, src, acc, used, stage);
        }
        else
        {
            auto session = pipe.decryptStream();
            pumpBody(w, session, src, acc, used, stage);
        }
    }
    catch (ItbException e)
        return e;
    return null;
}

/// One iteration. In order: refill the plaintext under rotating mode;
/// take the read lock; pick the surface; encrypt (timed); decrypt
/// (timed); compare the round-trip with the plaintext; bump the
/// counters; release the lock. The whole round-trip runs under the
/// read lock so handle-mutating maintenance (rekey, blob reopen) never
/// lands between an encrypt and its matching decrypt — maintenance
/// runs after this returns, from the worker loop.
private bool iterate(ref Worker w, long iter) @trusted
{
    auto r = w.run;

    if (w.payloadMode == PayloadMode.rotating)
        if (!fillPayload(PayloadMode.rotating, w.seeded, w.rng, w.plaintext))
        {
            workerFail(w, format("g%d iter %d: payload refill: csprng", w.id, iter));
            return false;
        }

    r.pipeLock.reader.lock();
    scope (exit)
        r.pipeLock.reader.unlock();

    // Shape dispatch. message is one whole-buffer call on the Single
    // Message Pipeline; stream_one_shot is one whole-buffer call on
    // the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
    // which routes to the same one-shot stream entry the Go
    // harness calls by name); stream opens a session on the same
    // streaming Pipeline and drives the chunk loop from here. Under
    // both the three rotate by iteration number so the session path
    // and the whole-buffer path alternate on one handle inside every
    // worker — the cross-path state-reuse hazard this harness exists
    // to catch.
    auto shape = r.cfg.shape;
    if (shape == Shape.both)
        final switch (iter % 3)
        {
        case 0:
            shape = Shape.stream;
            break;
        case 1:
            shape = Shape.message;
            break;
        case 2:
            shape = Shape.streamOneShot;
            break;
        }

    const(ubyte)[] got;
    // D-specific. The message and one-shot entries hand back move-only
    // malloc-backed buffers that free themselves when the iteration
    // leaves scope; the pump accumulators are the worker's own and are
    // reused. Both owners are declared here so either path's output
    // outlives the comparison below.
    BorrowedBytes ownedWire;
    BorrowedBytes ownedPlain;
    string stage;
    long t0;

    final switch (shape)
    {
    case Shape.stream:
        t0 = nowNs();
        if (auto e = pump(w, r.streamPipe, true, w.plaintext, w.wire, w.wireLen, stage))
        {
            cipherFail(w, iter, shape, "encrypt", stage, e);
            return false;
        }
        atomicFetchAdd(w.nanosEnc, nowNs() - t0);
        t0 = nowNs();
        if (auto e = pump(w, r.streamPipe, false, w.wire[0 .. w.wireLen],
                w.plain, w.plainLen, stage))
        {
            cipherFail(w, iter, shape, "decrypt", stage, e);
            return false;
        }
        atomicFetchAdd(w.nanosDec, nowNs() - t0);
        got = w.plain[0 .. w.plainLen];
        break;
    case Shape.streamOneShot:
        try
        {
            t0 = nowNs();
            ownedWire = r.streamPipe.encryptStreamOneShot(w.plaintext);
            atomicFetchAdd(w.nanosEnc, nowNs() - t0);
        }
        catch (ItbException e)
        {
            cipherFail(w, iter, shape, "encrypt", "", e);
            return false;
        }
        try
        {
            t0 = nowNs();
            ownedPlain = r.streamPipe.decryptStreamOneShot(ownedWire);
            atomicFetchAdd(w.nanosDec, nowNs() - t0);
        }
        catch (ItbException e)
        {
            cipherFail(w, iter, shape, "decrypt", "", e);
            return false;
        }
        got = ownedPlain;
        break;
    case Shape.message:
        try
        {
            t0 = nowNs();
            ownedWire = r.msgPipe.encryptMessage(w.plaintext);
            atomicFetchAdd(w.nanosEnc, nowNs() - t0);
        }
        catch (ItbException e)
        {
            cipherFail(w, iter, shape, "encrypt", "", e);
            return false;
        }
        try
        {
            t0 = nowNs();
            ownedPlain = r.msgPipe.decryptMessage(ownedWire);
            atomicFetchAdd(w.nanosDec, nowNs() - t0);
        }
        catch (ItbException e)
        {
            cipherFail(w, iter, shape, "decrypt", "", e);
            return false;
        }
        got = ownedPlain;
        break;
    case Shape.both:
        break; // resolved above
    }

    // Failure model. A cipher call that returns a non-OK status is a
    // worker error: it is recorded, the run is asked to stop, the
    // other workers finish their in-flight iteration, and the error is
    // listed in the summary with the FAIL verdict. A round-trip that
    // returns OK with different bytes is a data mismatch: the process
    // terminates here, without summary or cleanup, because the
    // Pipeline state that produced the wrong bytes is the evidence and
    // nothing that runs afterwards may touch it.
    if (got != w.plaintext)
    {
        immutable off = firstDifference(w.plaintext, got);
        errLine(format("DATA MISMATCH g%d iter %d shape=%s: want %d bytes, got %d bytes, "
                ~ "first difference at offset %d: want %s got %s",
                w.id, iter, shapeName(shape), w.plaintext.length, got.length,
                off, hexWindow(w.plaintext, off), hexWindow(got, off)));
        _Exit(3);
    }

    atomicFetchAdd(w.iters, 1L);
    atomicFetchAdd(w.bytesEnc, cast(long) w.plaintext.length);
    atomicFetchAdd(w.bytesDec, cast(long) got.length);
    return true;
}

/// Marks this worker returned; the last one to return stamps the
/// finish instant and wakes main.
private void workerDone(RunState* r) @trusted
{
    synchronized (r.doneMu)
    {
        r.active--;
        if (r.active == 0)
        {
            r.finishNs = nowNs();
            r.doneCv.notify();
        }
    }
}

/// The worker thread body: one warmup iteration, the warmup barrier,
/// then the main loop until a stop is requested or the fixed
/// per-worker iteration budget (warmup included) is spent. A failing
/// warmup still passes both barriers so the launcher never waits on a
/// worker that has already given up.
void workerMain(Worker* wp) @trusted
{
    auto w = wp;
    auto r = w.run;

    // Warmup iteration — counted in the totals; its completion feeds
    // the post-warmup baselines.
    immutable ok = iterate(*w, 0);
    r.warmupDone.wait();
    r.release.wait();
    if (!ok)
    {
        workerDone(r);
        return;
    }

    for (long iter = 1;; iter++)
    {
        if (r.cfg.iterations > 0 && iter >= r.cfg.iterations)
            break;
        if (atomicLoad(r.stop))
            break;
        if (!iterate(*w, iter))
            break;
        if (!workerMaintenance(*w, iter))
            break;
    }
    workerDone(r);
}
