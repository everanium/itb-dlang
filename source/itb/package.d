/// Thin D proxy over the libitb shared library's Triple Pipeline
/// surface.
///
/// The package wraps the `ITB_Triple_*` C ABI exported by
/// `cmd/cshared` (libitb.so) through compile-time `extern (C)`
/// linkage. Every hash-name / MAC-name / cipher-name / profile-name
/// is an opaque string passed through to Go for validation; the
/// binding carries no ITB construction logic of its own.
///
/// ---
/// import itb;
///
/// auto sender = Pipeline.create("singlemsg-triple-mac-v1");
/// auto receiver = Pipeline.load(sender.save());
/// auto wire = sender.encryptMessage(cast(const(ubyte)[]) "hello");
/// assert(receiver.decryptMessage(wire) == cast(const(ubyte)[]) "hello");
/// ---
module itb;

public import itb.buffer : BorrowedBytes;
public import itb.error : ItbException, lastError;
public import itb.opts : Opts;
public import itb.pipeline : Pipeline, inspect, lookup, profiles, register;
public import itb.profile : Profile;
public import itb.runtime : bindingVersion, libitbVersion, setGCPercent,
    setMemoryLimit;
public import itb.status : Status, statusFromRc, statusLabel;
public import itb.stream : DecryptStream, EncryptStream;
