"""PPC to C - a python rewrite of xorloser's PPC2C plugin.

This is not a decompiler.  It writes a C-ish comment next to the PowerPC
instructions that are hard to read at a glance, above all the rotate-and-mask
family:

    rlwinm  r3, r3, 28,3,31     # r3 = ((r3 >> 4) | (r3 << 28)) & 0x1FFFFFFF
    clrlwi  r0, r0, 31          # r0 = r0 & 1
    rldicr  r10, r10, 24,39     # r10 = ((r10 << 24) | (r10 >> 40)) & 0xFFFFFFFFFF000000
    bc      14, 4*cr7+eq, loc_8  # if(cr7 is equal) goto loc_8

Instructions are decoded from the raw opcode word rather than from what IDA
prints, so the simplified mnemonics (sldi, srdi, clrlwi, rotlwi, ...) are
handled without having to know how each IDA version spells them.

Use it from the Edit/Plugins menu, with the hotkeys below, or from
plugins.cfg exactly like the original:

    PPC_To_C:_Current_Line      ppc2c   Ctrl-Alt-C          0
    PPC_To_C:_Entire_Function   ppc2c   Ctrl-Alt-Shift-C    1

The decoder has no IDA dependency, so `python ppc2c.py --selftest` works.
"""

import sys

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

CR_BITS = ("less than", "greater than", "equal", "summary overflow")
CR_BITS_NOT = ("not less than", "not greater than", "not equal",
               "no summary overflow")

SPR_NAMES = {1: "xer", 8: "lr", 9: "ctr", 256: "vrsave", 268: "tb", 269: "tbu"}


def _signed(value, bits):
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def mask32(mb, me):
    """The PowerPC MASK(mb, me), bits numbered from the most significant."""
    if mb <= me:
        bits = ((1 << (me - mb + 1)) - 1) << (31 - me)
    else:
        bits = (((1 << (31 - mb + 1)) - 1)) | (((1 << (me + 1)) - 1) << (31 - me))
    return bits & M32


def mask64(mb, me):
    if mb <= me:
        return (((1 << (me - mb + 1)) - 1) << (63 - me)) & M64
    return ((((1 << (63 - mb + 1)) - 1)) | (((1 << (me + 1)) - 1) << (63 - me))) & M64


def _hex(value, bits=32):
    return "0x%0*X" % (bits // 4, value)


def _rot(reg, sh, width):
    """Textual rotate left of `reg` by `sh` in a `width` bit register."""
    if sh == 0:
        return reg
    return "((%s << %d) | (%s >> %d))" % (reg, sh, reg, width - sh)


class Insn(object):
    """The few fields of a PowerPC instruction word that this plugin needs."""

    def __init__(self, word):
        self.word = word & M32
        w = self.word
        self.op = w >> 26
        self.rs = (w >> 21) & 31            # also rt / rd / bo
        self.ra = (w >> 16) & 31            # also bi
        self.rb = (w >> 11) & 31            # also sh for M-form
        self.mb = (w >> 6) & 31
        self.me = (w >> 1) & 31
        self.xo10 = (w >> 1) & 0x3FF
        self.xo3 = (w >> 2) & 7
        self.rc = w & 1
        self.ui = w & 0xFFFF
        self.si = _signed(w & 0xFFFF, 16)
        # MD/MDS form: the shift amount and the mask bound are split up
        self.sh6 = (((w >> 1) & 1) << 5) | ((w >> 11) & 31)
        mbf = (w >> 5) & 0x3F
        self.mb6 = ((mbf & 1) << 5) | (mbf >> 1)


def _r(n):
    return "r%d" % n


def _spr(insn):
    """The SPR field is stored as spr[5:9] || spr[0:4], low half first."""
    spr = (insn.ra | (insn.rb << 5)) & 0x3FF
    return SPR_NAMES.get(spr, "spr%d" % spr)


def _cr_cond(bo, bi):
    """(condition text, always) for a conditional branch."""
    cr = bi >> 2
    bit = bi & 3
    if bo & 0x10:                       # branch always / ctr only
        if bo & 0x04:
            return None, True
        return ("--ctr; if(ctr %s 0)" % ("!=" if not (bo & 2) else "==")), False
    true_branch = bool(bo & 0x08)
    text = "cr%d is %s" % (cr, (CR_BITS if true_branch else CR_BITS_NOT)[bit])
    if bo & 0x04:
        return "if(%s)" % text, False
    return "--ctr; if(ctr %s 0 && %s)" % ("!=" if not (bo & 2) else "==", text), False


def _branch_target(insn, ea):
    bd = _signed(insn.word & 0xFFFC, 16)
    if insn.word & 2:                   # AA
        return bd & M64
    if ea is None:
        return None
    return (ea + bd) & M64


def _rlwinm(rs, ra, sh, mb, me, rc):
    m = mask32(mb, me)
    dst, src = _r(ra), _r(rs)
    if m == M32:
        body = _rot(src, sh, 32)
        text = "%s = %s" % (dst, body)
    elif sh == 0:
        text = "%s = %s & %s" % (dst, src, _hex(m))
    elif mb == 0 and me == 31 - sh:                     # slwi
        text = "%s = %s << %d" % (dst, src, sh)
    elif me == 31 and mb == 32 - sh:                    # srwi
        text = "%s = %s >> %d" % (dst, src, 32 - sh)
    else:
        text = "%s = %s & %s" % (dst, _rot(src, sh, 32), _hex(m))
    return text + (" (sets cr0)" if rc else "")


def _rlwimi(rs, ra, sh, mb, me, rc):
    m = mask32(mb, me)
    text = "%s = (%s & %s) | (%s & %s)" % (_r(ra), _r(ra), _hex(m ^ M32),
                                           _rot(_r(rs), sh, 32), _hex(m))
    return text + (" (sets cr0)" if rc else "")


def _rld(kind, rs, ra, sh, bound, rc):
    dst, src = _r(ra), _r(rs)
    if kind == "icl":
        m = mask64(bound, 63)
        if sh == 0:
            text = "%s = %s & %s" % (dst, src, _hex(m, 64))
        elif bound == 64 - sh:                          # srdi
            text = "%s = %s >> %d" % (dst, src, 64 - sh)
        elif m == M64:
            text = "%s = %s" % (dst, _rot(src, sh, 64))
        else:
            text = "%s = %s & %s" % (dst, _rot(src, sh, 64), _hex(m, 64))
    elif kind == "icr":
        m = mask64(0, bound)
        if sh == 0:
            text = "%s = %s & %s" % (dst, src, _hex(m, 64))
        elif bound == 63 - sh:                          # sldi
            text = "%s = %s << %d" % (dst, src, sh)
        else:
            text = "%s = %s & %s" % (dst, _rot(src, sh, 64), _hex(m, 64))
    elif kind == "ic":
        m = mask64(bound, 63 - sh)
        text = "%s = %s & %s" % (dst, _rot(src, sh, 64), _hex(m, 64))
    else:                                               # imi
        m = mask64(bound, 63 - sh)
        text = "%s = (%s & %s) | (%s & %s)" % (dst, dst, _hex(m ^ M64, 64),
                                               _rot(src, sh, 64), _hex(m, 64))
    return text + (" (sets cr0)" if rc else "")


def to_c(word, ea=None, name_of=None):
    """A C-ish description of one PowerPC instruction, or None."""
    i = Insn(word)
    op = i.op

    if op == 16:                                        # bc
        cond, always = _cr_cond(i.rs, i.ra)
        tgt = _branch_target(i, ea)
        where = None
        if tgt is not None:
            where = (name_of(tgt) if name_of else None) or ("0x%X" % tgt)
        if always:
            return None
        if i.word & 1:                                  # LK
            return "%s %s()" % (cond, where or "...")
        return "%s goto %s" % (cond, where or "...")

    if op == 20:
        return _rlwimi(i.rs, i.ra, i.rb, i.mb, i.me, i.rc)
    if op == 21:
        return _rlwinm(i.rs, i.ra, i.rb, i.mb, i.me, i.rc)
    if op == 23:
        return "%s = %s & %s (rotate by %s)" % (
            _r(i.ra), _r(i.rs), _hex(mask32(i.mb, i.me)), _r(i.rb))

    if op == 30:
        kind = {0: "icl", 1: "icr", 2: "ic", 3: "imi"}.get(i.xo3)
        if kind is None:                                # MDS form, shift in rb
            return "%s = rotate %s left by %s, then mask" % (_r(i.ra), _r(i.rs), _r(i.rb))
        return _rld(kind, i.rs, i.ra, i.sh6, i.mb6, i.rc)

    if op in (24, 25, 26, 27, 28, 29):
        sym = {24: "|", 25: "|", 26: "^", 27: "^", 28: "&", 29: "&"}[op]
        value = i.ui if op in (24, 26, 28) else i.ui << 16
        if op == 24 and i.rs == i.ra and i.ui == 0:
            return "nop"
        text = "%s = %s %s %s" % (_r(i.ra), _r(i.rs), sym, _hex(value))
        return text + (" (sets cr0)" if op in (28, 29) else "")

    if op == 14:                                        # addi / li
        if i.ra == 0:
            return "%s = %s" % (_r(i.rs), _hex(i.si & M64, 64) if i.si < 0 else "%d" % i.si)
        return "%s = %s %s %d" % (_r(i.rs), _r(i.ra), "-" if i.si < 0 else "+", abs(i.si))
    if op == 15:                                        # addis / lis
        if i.ra == 0:
            return "%s = %s" % (_r(i.rs), _hex((i.si << 16) & M32))
        return "%s = %s + %s" % (_r(i.rs), _r(i.ra), _hex((i.si << 16) & M32))
    if op == 12 or op == 13:                            # addic
        return "%s = %s %s %d (sets carry)" % (_r(i.rs), _r(i.ra),
                                               "-" if i.si < 0 else "+", abs(i.si))
    if op == 7:                                         # mulli
        return "%s = %s * %d" % (_r(i.rs), _r(i.ra), i.si)
    if op == 8:                                         # subfic
        return "%s = %d - %s (sets carry)" % (_r(i.rs), i.si, _r(i.ra))

    if op == 11:                                        # cmpi
        return "cr%d = compare(%s, %d)" % (i.rs >> 2, _r(i.ra), i.si)
    if op == 10:                                        # cmpli
        return "cr%d = compare(%s, %s) unsigned" % (i.rs >> 2, _r(i.ra), _hex(i.ui, 16))

    if op == 31:
        xo = i.xo10
        if xo == 0:
            return "cr%d = compare(%s, %s)" % (i.rs >> 2, _r(i.ra), _r(i.rb))
        if xo == 32:
            return "cr%d = compare(%s, %s) unsigned" % (i.rs >> 2, _r(i.ra), _r(i.rb))
        if xo == 444:                                   # or / mr
            if i.rs == i.rb:
                return "%s = %s" % (_r(i.ra), _r(i.rs))
            return "%s = %s | %s" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 28:
            return "%s = %s & %s" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 316:
            return "%s = %s ^ %s" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 476:
            return "%s = ~(%s & %s)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 124:
            if i.rs == i.rb:
                return "%s = ~%s" % (_r(i.ra), _r(i.rs))
            return "%s = ~(%s | %s)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 60:
            return "%s = %s & ~%s" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 412:
            return "%s = %s | ~%s" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 284:
            return "%s = ~(%s ^ %s)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 24:
            return "%s = %s << (%s & 63)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 536:
            return "%s = %s >> (%s & 63)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 27:
            return "%s = %s << (%s & 127)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 539:
            return "%s = %s >> (%s & 127)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo in (824, 826):                            # srawi / sradi
            sh = i.rb if xo == 824 else i.sh6
            return "%s = (signed)%s >> %d (sets carry)" % (_r(i.ra), _r(i.rs), sh)
        if xo == 792:
            return "%s = (signed)%s >> (%s & 63)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 794:
            return "%s = (signed)%s >> (%s & 127)" % (_r(i.ra), _r(i.rs), _r(i.rb))
        if xo == 954:
            return "%s = (signed char)%s" % (_r(i.ra), _r(i.rs))
        if xo == 922:
            return "%s = (signed short)%s" % (_r(i.ra), _r(i.rs))
        if xo == 986:
            return "%s = (signed int)%s" % (_r(i.ra), _r(i.rs))
        if xo == 26:
            return "%s = count_leading_zeros32(%s)" % (_r(i.ra), _r(i.rs))
        if xo == 58:
            return "%s = count_leading_zeros64(%s)" % (_r(i.ra), _r(i.rs))
        if xo == 104:
            return "%s = -%s" % (_r(i.rs), _r(i.ra))
        if xo == 40:
            return "%s = %s - %s" % (_r(i.rs), _r(i.rb), _r(i.ra))
        if xo == 266:
            return "%s = %s + %s" % (_r(i.rs), _r(i.ra), _r(i.rb))
        if xo == 235 or xo == 235 + 512:
            return "%s = %s * %s" % (_r(i.rs), _r(i.ra), _r(i.rb))
        if xo == 339:                                   # mfspr
            return "%s = %s" % (_r(i.rs), _spr(i))
        if xo == 467:                                   # mtspr
            return "%s = %s" % (_spr(i), _r(i.rs))
    return None


# ---------------------------------------------------------------------------
# IDA side
# ---------------------------------------------------------------------------

def _ida():
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_name
    return ida_bytes, ida_funcs, ida_kernwin, ida_name


def comment_ea(ea):
    """Comment one instruction, returns True when something was written."""
    ida_bytes, _f, _k, ida_name = _ida()
    if not ida_bytes.is_loaded(ea):
        return False
    word = ida_bytes.get_dword(ea)
    text = to_c(word, ea, lambda a: ida_name.get_name(a) or None)
    if not text:
        return False
    ida_bytes.set_cmt(ea, text, False)
    return True


def comment_function(ea):
    ida_bytes, ida_funcs, _k, _n = _ida()
    pfn = ida_funcs.get_func(ea)
    if not pfn:
        return 0
    import ida_bytes as b
    count = 0
    cur = pfn.start_ea
    while cur < pfn.end_ea:
        if comment_ea(cur):
            count += 1
        nxt = b.get_item_end(cur)
        cur = nxt if nxt > cur else cur + 4
    return count


try:
    import ida_idaapi
    import ida_idp
    import ida_kernwin

    class Ppc2cPlugin(ida_idaapi.plugin_t):
        flags = 0
        comment = "Comment tricky PowerPC instructions with C equivalents"
        help = __doc__
        wanted_name = "PPC to C"
        wanted_hotkey = ""

        ACTIONS = (
            ("ppc2c:line", "PPC to C: current line", "Ctrl-Alt-C", 0),
            ("ppc2c:func", "PPC to C: entire function", "Ctrl-Alt-Shift-C", 1),
        )

        def init(self):
            if ida_idp.ph_get_id() != ida_idp.PLFM_PPC:
                return ida_idaapi.PLUGIN_SKIP
            for name, label, hotkey, arg in self.ACTIONS:
                handler = self._handler(arg)
                desc = ida_kernwin.action_desc_t(name, label, handler, hotkey,
                                                 label, -1)
                ida_kernwin.register_action(desc)
            return ida_idaapi.PLUGIN_KEEP

        def _handler(self, arg):
            plugin = self

            class Handler(ida_kernwin.action_handler_t):
                def activate(self, ctx):
                    plugin.run(arg)
                    return 1

                def update(self, ctx):
                    return ida_kernwin.AST_ENABLE_ALWAYS

            return Handler()

        def run(self, arg):
            ea = ida_kernwin.get_screen_ea()
            if arg == 1:
                n = comment_function(ea)
                ida_kernwin.msg("[ppc2c] %d instructions commented\n" % n)
            else:
                if not comment_ea(ea):
                    ida_kernwin.msg("[ppc2c] nothing to say about %08X\n" % ea)
            return True

        def term(self):
            for name, _l, _h, _a in self.ACTIONS:
                ida_kernwin.unregister_action(name)

    def PLUGIN_ENTRY():
        return Ppc2cPlugin()

except ImportError:
    pass            # running outside IDA, only the decoder is available


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------

def _selftest():
    cases = [
        # every word here was taken out of a real 4.93 lv2_kernel.self and the
        # expected text checked against what IDA prints for that address
        (0x796B1F24, "r11 = r11 << 3"),                        # sldi   r11,r11,3
        (0x5463E0FE, "r3 = ((r3 << 28) | (r3 >> 4)) & 0x1FFFFFFF"),   # rlwinm r3,r3,28,3,31
        (0x5463203E, "r3 = ((r3 << 4) | (r3 >> 28))"),         # rotlwi r3,r3,4
        (0x5400073E, "r0 = r0 & 0x0000000F"),                  # clrlwi r0,r0,28
        (0x7863F842, "r3 = r3 >> 1"),                          # rldicl r3,r3,63,1
        (0x5463E13E, "r3 = r3 >> 4"),                          # rlwinm r3,r3,28,4,31
        (0x7C60FE70, "r0 = (signed)r3 >> 31 (sets carry)"),    # srawi  r0,r3,31
        (0x282B0400, "cr0 = compare(r11, 0x0400) unsigned"),   # cmpldi r11,0x400
        (0x7C091A78, "r9 = r0 ^ r3"),                          # xor    r9,r0,r3
        (0x7D204850, "r9 = r9 - r0"),                          # subf   r9,r0,r9
        (0x3863000F, "r3 = r3 + 15"),                          # addi   r3,r3,0xF
        (0x7C6307B4, "r3 = (signed int)r3"),                   # extsw  r3,r3
        (0x7C8802A6, "r4 = lr"),                               # mflr   r4
        (0x7C6803A6, "lr = r3"),                               # mtlr   r3
        (0x7DAB6A14, "r13 = r11 + r13"),                       # add    r13,r11,r13
        (0x2FA40000, "cr7 = compare(r4, 0)"),                  # cmpdi  cr7,r4,0
        (0x60000000, "nop"),
        (0x7C641B78, "r4 = r3"),                               # mr     r4,r3
        (0x38600001, "r3 = 1"),                                # li     r3,1
    ]
    bad = 0
    for word, expect in cases:
        got = to_c(word, 0x1000)
        if got != expect:
            print("FAIL %08X: got %r want %r" % (word, got, expect))
            bad += 1
    print("selftest: %d/%d" % (len(cases) - bad, len(cases)))
    return bad


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(1 if _selftest() else 0)
    print(__doc__)
