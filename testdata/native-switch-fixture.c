/*
 * Source-owned producer input for WF17 native dispatch evidence checks.
 *
 * This file declares C semantics, not expected disassembly or Ghidra output.
 * In particular, a compiler may lower either switch to branches or tables,
 * split one switch into several dispatches, or merge destination blocks.
 * Inspect the actual compiler-produced bytes before claiming a jump table,
 * its bounds, label-to-target mapping, defaults, or reference classifications.
 * No executable entry point is provided; analysis must not run the fixture.
 *
 * rr_native_switch_fixture has a dense nonzero cluster (10..25), holes 16/20,
 * negative labels, sparse labels, three labels sharing one body, and default.
 * The noinline callee and volatile accesses keep real control-flow work in
 * each body rather than a switch whose result is merely a constant lookup.
 * rr_native_sparse_switch_fixture supplies a separate sparse-switch control.
 * rr_native_indirect_call_fixture has a caller-supplied, statically unknown
 * callback: an indirect call is not evidence of switch cases or jump targets.
 * The volatile object also supplies ordinary data reads/writes; these must
 * never be promoted to case destinations merely because they are references.
 */

#if defined(__GNUC__)
#define RR_NOINLINE __attribute__((noinline, noclone))
#else
#define RR_NOINLINE __declspec(noinline)
#endif

#if defined(_WIN32)
#define RR_EXPORT __declspec(dllexport)
#else
#define RR_EXPORT
#endif

RR_EXPORT volatile unsigned int rr_native_switch_state = 0x13579bdfu;

static RR_NOINLINE unsigned int rr_native_switch_effect(unsigned int tag,
                                                        unsigned int sample)
{
    unsigned int before = rr_native_switch_state;
    rr_native_switch_state = (before ^ sample) + tag;
    return tag ^ (before + (sample << 1));
}

RR_EXPORT RR_NOINLINE unsigned int rr_native_switch_fixture(int selector)
{
    unsigned int sample = rr_native_switch_state;

    switch (selector) {
    case -11:
        return rr_native_switch_effect(0x900bu, sample);
    case -1:
        return rr_native_switch_effect(0x9001u, sample);
    case 10:
        return rr_native_switch_effect(0x100au, sample);
    case 11:
        return rr_native_switch_effect(0x100bu, sample);
    case 12:
    case 18:
    case 25:
        return rr_native_switch_effect(0x5151u, sample);
    case 13:
        return rr_native_switch_effect(0x100du, sample);
    case 14:
        return rr_native_switch_effect(0x100eu, sample);
    case 15:
        return rr_native_switch_effect(0x100fu, sample);
    case 17:
        return rr_native_switch_effect(0x1011u, sample);
    case 19:
        return rr_native_switch_effect(0x1013u, sample);
    case 21:
        return rr_native_switch_effect(0x1015u, sample);
    case 22:
        return rr_native_switch_effect(0x1016u, sample);
    case 23:
        return rr_native_switch_effect(0x1017u, sample);
    case 24:
        return rr_native_switch_effect(0x1018u, sample);
    case 101:
        return rr_native_switch_effect(0xa065u, sample);
    case 4096:
        return rr_native_switch_effect(0xb000u, sample);
    default:
        return rr_native_switch_effect(0xdefau, sample);
    }
}

RR_EXPORT RR_NOINLINE unsigned int rr_native_sparse_switch_fixture(int selector)
{
    unsigned int sample = rr_native_switch_state;

    switch (selector) {
    case -4096:
        return rr_native_switch_effect(0xc001u, sample);
    case -17:
    case 65537:
        return rr_native_switch_effect(0xc002u, sample);
    case 257:
        return rr_native_switch_effect(0xc003u, sample);
    case 1000003:
        return rr_native_switch_effect(0xc004u, sample);
    default:
        return rr_native_switch_effect(0xc0ffu, sample);
    }
}

typedef unsigned int (*rr_native_switch_callback)(int selector,
                                                 unsigned int sample);

RR_EXPORT RR_NOINLINE unsigned int
rr_native_indirect_call_fixture(rr_native_switch_callback callback, int selector)
{
    unsigned int sample = rr_native_switch_state;

    if (callback == 0) {
        return rr_native_switch_effect(0xbad0u, sample);
    }
    return callback(selector, sample);
}
