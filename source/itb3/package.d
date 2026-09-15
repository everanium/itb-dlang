/// Thin D proxy over the libitb3 shared library's Triple Pipeline
/// surface.
///
/// The package wraps the `ITB_Triple_*` C ABI exported by
/// `cmd/cshared` (libitb3.so) through compile-time `extern (C)`
/// linkage. Every hash-name / MAC-name / cipher-name / profile-name
/// is an opaque string passed through to Go for validation; the
/// binding carries no ITB construction logic of its own.
///
/// ---
/// import itb3;
///
/// auto sender = Pipeline.create("singlemsg-triple-mac-v1");
/// auto receiver = Pipeline.load(sender.save());
/// auto wire = sender.encryptMessage(cast(const(ubyte)[]) "hello");
/// assert(receiver.decryptMessage(wire) == cast(const(ubyte)[]) "hello");
/// ---
module itb3;

public import itb3.buffer : BorrowedBytes;
public import itb3.error : ItbException, lastError;
public import itb3.opts : Opts;
public import itb3.pipeline : Pipeline, inspect, lookup, profiles, register;
public import itb3.profile : Profile;
public import itb3.runtime : bindingVersion, libitb3Version, setGCPercent,
    setMemoryLimit;
public import itb3.status : Status, statusFromRc, statusLabel;
public import itb3.stream : DecryptStream, EncryptStream;
