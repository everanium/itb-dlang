/// The maintenance operations that mutate a live Pipeline handle
/// between iterations: master rotation (--rekey-every) and blob
/// reopen (--blob-cycle-every).
module loop.ops;

import core.atomic : atomicFetchAdd;

import std.format : format;

import itb3;

import loop.main : detail, logLine;
import loop.payload : fillRandom;
import loop.state;
import loop.worker : workerFail;

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
private enum size_t rekeyMasterSize = 32;

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed blob
/// for subsequent blob reopens. Masters are drawn fresh from the OS
/// CSPRNG on every rotation regardless of --seed (master rotation is
/// pipeline keying, not plaintext content); a disabled layer passes no
/// bytes, which Rekey ignores. The eight inner seeds and the MAC key
/// are untouched by design — Rekey targets only the two outer-layer
/// master secrets.
private bool rekeyPipes(ref Worker w, long iter) @trusted
{
    auto r = w.run;
    ubyte[rekeyMasterSize] perm;
    ubyte[rekeyMasterSize] wrap;
    const(ubyte)[] permView;
    const(ubyte)[] wrapView;

    if (r.cfg.parallax)
    {
        if (!fillRandom(perm[]))
        {
            workerFail(w, format("g%d iter %d: csprng: parallax master", w.id, iter));
            return false;
        }
        permView = perm[];
    }
    if (r.cfg.wrapper)
    {
        if (!fillRandom(wrap[]))
        {
            workerFail(w, format("g%d iter %d: csprng: wrapper master", w.id, iter));
            return false;
        }
        wrapView = wrap[];
    }

    r.pipeLock.writer.lock();
    scope (exit)
        r.pipeLock.writer.unlock();
    if (r.hasStream)
    {
        try
            r.streamBlob = r.streamPipe.rekey(permView, wrapView);
        catch (ItbException e)
        {
            workerFail(w, format("g%d iter %d: Rekey(%s): %s",
                    w.id, iter, r.streamProfile, detail(e)));
            return false;
        }
    }
    if (r.hasMsg)
    {
        try
            r.msgBlob = r.msgPipe.rekey(permView, wrapView);
        catch (ItbException e)
        {
            workerFail(w, format("g%d iter %d: Rekey(%s): %s",
                    w.id, iter, r.msgProfile, detail(e)));
            return false;
        }
    }
    immutable n = atomicFetchAdd(r.rekeys, 1L) + 1;
    logLine(format("rekey: g%d iter %d rotated parallax + wrapper masters (rekey #%d)",
            w.id, iter, n));
    return true;
}

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is freed, and the fresh one is swapped in, so every
/// later iteration round-trips through seeds and masters that survived
/// a blob crossing. The input is the blob Init or the latest Rekey
/// handed out, not a fresh Save: that is what a receiver holds, and
/// reopening from it proves the handed-out bytes rather than the live
/// state. The blob carries the Pipeline's full shape, so no override
/// reaches the reopen. On a Load failure the running handle stays and
/// the failure aborts the run.
private bool blobCyclePipes(ref Worker w, long iter) @trusted
{
    import std.algorithm.mutation : move;

    auto r = w.run;
    r.pipeLock.writer.lock();
    scope (exit)
        r.pipeLock.writer.unlock();
    if (r.hasStream)
    {
        try
        {
            // D-specific. The fresh handle is constructed into its own
            // local first, so a throwing Load leaves the running one in
            // place; the move-assignment then releases the old handle.
            auto fresh = Pipeline.load(r.streamBlob);
            r.streamPipe = move(fresh);
        }
        catch (ItbException e)
        {
            workerFail(w, format("g%d iter %d: Load(%s): %s",
                    w.id, iter, r.streamProfile, detail(e)));
            return false;
        }
    }
    if (r.hasMsg)
    {
        try
        {
            auto fresh = Pipeline.load(r.msgBlob);
            r.msgPipe = move(fresh);
        }
        catch (ItbException e)
        {
            workerFail(w, format("g%d iter %d: Load(%s): %s",
                    w.id, iter, r.msgProfile, detail(e)));
            return false;
        }
    }
    immutable n = atomicFetchAdd(r.blobCycles, 1L) + 1;
    logLine(format("blob-cycle: g%d iter %d reopened from session blob (cycle #%d)",
            w.id, iter, n));
    return true;
}

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher
/// calls on other workers drain before anything changes and no encrypt
/// is separated from its decrypt by either. Returns false after
/// recording the worker error.
bool workerMaintenance(ref Worker w, long iter) @trusted
{
    auto cfg = &w.run.cfg;
    if (cfg.rekeyEvery > 0 && iter % cfg.rekeyEvery == 0)
        if (!rekeyPipes(w, iter))
            return false;
    if (cfg.blobCycleEvery > 0 && iter % cfg.blobCycleEvery == 0)
        if (!blobCyclePipes(w, iter))
            return false;
    return true;
}
