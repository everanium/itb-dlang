// Phase-5 mirror: process-global configuration roundtrip tests.
//
// Mirrors bindings/rust/tests/test_config.rs file-for-file.
//
// These tests mutate libitb's process-wide atomics (BitSoup, LockSoup,
// MaxWorkers, NonceBits, BarrierFill); they live in their own
// standalone D test program so per-process isolation makes the
// mutation safe without explicit serial-locking.
import std.exception : collectException;
import std.stdio : writeln;
import itb;

void testBitSoupRoundtrip()
{
    auto orig = getBitSoup();
    setBitSoup(1);
    assert(getBitSoup() == 1, "setBitSoup(1) must read back as 1");
    setBitSoup(0);
    assert(getBitSoup() == 0, "setBitSoup(0) must read back as 0");
    setBitSoup(orig);
}

void testLockSoupRoundtrip()
{
    auto orig = getLockSoup();
    setLockSoup(1);
    assert(getLockSoup() == 1, "setLockSoup(1) must read back as 1");
    setLockSoup(orig);
}

void testMaxWorkersRoundtrip()
{
    auto orig = getMaxWorkers();
    setMaxWorkers(4);
    assert(getMaxWorkers() == 4, "setMaxWorkers(4) must read back as 4");
    setMaxWorkers(orig);
}

void testNonceBitsValidation()
{
    auto orig = getNonceBits();
    foreach (valid; [128, 256, 512])
    {
        setNonceBits(valid);
        assert(getNonceBits() == valid,
            "setNonceBits roundtrip must preserve value");
    }
    foreach (bad; [0, 1, 192, 1024])
    {
        auto err = collectException!ITBError(setNonceBits(bad));
        assert(err !is null, "setNonceBits invalid must throw");
        assert(err.statusCode == Status.BadInput,
            "setNonceBits invalid must surface Status.BadInput");
    }
    setNonceBits(orig);
}

void testBarrierFillValidation()
{
    auto orig = getBarrierFill();
    foreach (valid; [1, 2, 4, 8, 16, 32])
    {
        setBarrierFill(valid);
        assert(getBarrierFill() == valid,
            "setBarrierFill roundtrip must preserve value");
    }
    foreach (bad; [0, 3, 5, 7, 64])
    {
        auto err = collectException!ITBError(setBarrierFill(bad));
        assert(err !is null, "setBarrierFill invalid must throw");
        assert(err.statusCode == Status.BadInput,
            "setBarrierFill invalid must surface Status.BadInput");
    }
    setBarrierFill(orig);
}

void main()
{
    testBitSoupRoundtrip();
    testLockSoupRoundtrip();
    testMaxWorkersRoundtrip();
    testNonceBitsValidation();
    testBarrierFillValidation();
    writeln("test_config: ALL OK");
}
