/// Size and duration parsing, the monotonic clock, and the human
/// renderings of sizes, rates and durations. Every rendering here is
/// part of the output contract shared with the Go harness and the
/// other bindings' loop utilities, so the formats are fixed to the
/// character, not to taste.
module loop.size;

import core.stdc.stdio : snprintf;
import core.time : MonoTime, ticksToNSecs;

import std.ascii : isDigit, isWhite;
import std.conv : ConvException, to;
import std.format : format;
import std.string : strip, toUpper;

/// D-specific. The fractional renderings go through C's `snprintf`
/// rather than the standard library's formatter, so the digits a
/// summary carries are the ones every other implementation prints.
string fmtF(string spec)(double v) @trusted
{
    char[64] buf;
    immutable n = snprintf(buf.ptr, buf.length, spec.ptr, v);
    return n > 0 ? buf[0 .. n].idup : "";
}

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary multiple:
/// K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
/// bytes; matching is case-insensitive and surrounding whitespace is
/// trimmed. Returns false on a malformed or negative value.
bool parseSize(string s, out long outValue) @safe
{
    static immutable string[2][] table = [
        ["KIB", "1024"], ["KB", "1024"], ["K", "1024"],
        ["MIB", "1048576"], ["MB", "1048576"], ["M", "1048576"],
        ["GIB", "1073741824"], ["GB", "1073741824"], ["G", "1073741824"],
        ["B", "1"],
    ];
    auto upper = s.strip.toUpper;
    if (upper.length == 0 || upper.length >= 64)
        return false;
    long mult = 1;
    size_t digits = upper.length;
    foreach (row; table)
    {
        immutable suffix = row[0];
        if (upper.length >= suffix.length
            && upper[$ - suffix.length .. $] == suffix)
        {
            mult = row[1].to!long;
            digits = upper.length - suffix.length;
            break;
        }
    }
    while (digits > 0 && upper[digits - 1].isWhite)
        digits--;
    if (digits == 0)
        return false;
    foreach (c; upper[0 .. digits])
        if (!c.isDigit)
            return false;
    long n;
    try
        n = upper[0 .. digits].to!long;
    catch (ConvException)
        return false;
    if (n < 0 || (mult > 1 && n > long.max / mult))
        return false;
    outValue = n * mult;
    return true;
}

/// Parses the Go duration grammar — a sequence of decimal numbers each
/// followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
/// "1h30m", "1.5s" — into nanoseconds. Returns false on a malformed
/// string.
bool parseDuration(string s, out long outNs) @safe
{
    import std.ascii : isAlpha;

    static immutable string[2][] units = [
        ["ns", "1"], ["us", "1000"], ["ms", "1000000"],
        ["s", "1000000000"], ["m", "60000000000"], ["h", "3600000000000"],
    ];
    if (s.length == 0)
        return false;
    double total = 0.0;
    size_t i = 0;
    while (i < s.length)
    {
        if (!s[i].isDigit && s[i] != '.')
            return false;
        size_t j = i;
        while (j < s.length && (s[j].isDigit || s[j] == '.'))
            j++;
        double v;
        try
            v = s[i .. j].to!double;
        catch (ConvException)
            return false;
        if (v < 0.0)
            return false;
        i = j;
        double mult = 0.0;
        foreach (row; units)
        {
            immutable unit = row[0];
            if (s.length - i >= unit.length && s[i .. i + unit.length] == unit
                && (s.length - i == unit.length || !s[i + unit.length].isAlpha))
            {
                mult = row[1].to!double;
                i += unit.length;
                break;
            }
        }
        if (mult == 0.0)
            return false;
        total += v * mult;
    }
    if (total > 9.2e18)
        return false;
    outNs = cast(long) total;
    return true;
}

/// Monotonic wall clock in nanoseconds.
long nowNs() @safe nothrow
{
    return ticksToNSecs(MonoTime.currTime.ticks);
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
string humanBytes(long n) @safe
{
    if (n >= (1L << 30))
        return fmtF!"%.1f"(cast(double) n / cast(double)(1L << 30)) ~ "GiB";
    if (n >= (1L << 20))
        return fmtF!"%.1f"(cast(double) n / cast(double)(1L << 20)) ~ "MiB";
    if (n >= (1L << 10))
        return fmtF!"%.1f"(cast(double) n / cast(double)(1L << 10)) ~ "KiB";
    return format("%dB", n);
}

/// Renders a possibly-negative byte delta with an explicit sign.
string humanBytesSigned(long n) @safe
{
    return n < 0 ? "-" ~ humanBytes(-n) : "+" ~ humanBytes(n);
}

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
double mbPerSec(long bytes, long ns) @safe nothrow @nogc
{
    if (ns <= 0)
        return 0.0;
    return cast(double) bytes / cast(double)(1 << 20) / (cast(double) ns / 1e9);
}

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
string humanRate(long bytes, long ns) @safe
{
    if (ns <= 0)
        return "n/a";
    return fmtF!"%.1f"(mbPerSec(bytes, ns)) ~ "MB/s";
}

/// Appends the fractional part of a nanosecond remainder (0 .. 1e9)
/// as ".ddd" with trailing zeros removed; appends nothing for zero.
private string fraction(long fracNs) @safe
{
    if (fracNs == 0)
        return "";
    auto digits = format("%09d", fracNs);
    while (digits.length > 0 && digits[$ - 1] == '0')
        digits = digits[0 .. $ - 1];
    return "." ~ digits;
}

/// Renders a duration the way Go's time.Duration prints: below one
/// second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
/// where the hour part appears when non-zero, the minute part when
/// the hour part appears or the minutes are non-zero, and the seconds
/// carry their fraction with trailing zeros removed ("5s", "5.003s",
/// "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
string humanDuration(long ns) @safe
{
    if (ns < 0)
        ns = -ns;
    if (ns == 0)
        return "0s";
    if (ns < 1_000_000_000L)
        return format("%d", ns / 1_000_000L) ~ fraction((ns % 1_000_000L) * 1000L) ~ "ms";
    immutable hours = ns / 3_600_000_000_000L;
    auto rem = ns % 3_600_000_000_000L;
    immutable minutes = rem / 60_000_000_000L;
    rem %= 60_000_000_000L;
    immutable seconds = rem / 1_000_000_000L;
    immutable frac = rem % 1_000_000_000L;
    string outText;
    if (hours > 0)
        outText ~= format("%dh", hours);
    if (hours > 0 || minutes > 0)
        outText ~= format("%dm", minutes);
    outText ~= format("%d", seconds) ~ fraction(frac) ~ "s";
    return outText;
}
