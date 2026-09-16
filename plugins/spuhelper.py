"""SPU Helper - a python rewrite of xorloser's SPUHelper plugin.

Same idea as ppchelper, for Cell SPU code:

    before                          after
    stqd    r80, var_10(sp)         stqd    r80, save_r80(sp)
    stqd    lr, arg_10(sp)          stqd    lr, save_lr(sp)
    lr      r80, r3                 arg0 = r80   (from the next instruction on)

The original only worked with xorloser's own SPU processor module; this one
reads registers by number, so it works with the SPU module IDA ships (which
names them lr, sp, r2 ... r127).

SPU ABI as used by the PS3 SDK:

    lr (r0)     link register
    sp (r1)     stack pointer
    r2          scratch / environment
    r3 - r74    arguments and return values
    r75 - r79   scratch
    r80 - r127  callee saved

    SPU_Helper:_Current_Function    spuhelper   Ctrl-Alt-H          0
    SPU_Helper:_All_Functions       spuhelper   Ctrl-Alt-Shift-H    1
"""

import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_typeinf
import ida_ua
import idautils
import idc

STORES = {"stqd": 16, "stqx": 16, "stqa": 16, "stqr": 16}
MOVES = ("lr", "move", "or")

ARG_REGS = tuple("r%d" % n for n in range(3, 75))
NONVOLATILE = tuple("r%d" % n for n in range(80, 128))

MAX_PROLOGUE = 64


def _reg(op):
    return ida_idp.get_reg_name(op.reg, 16) or ""


def _frame(pfn):
    frame = ida_typeinf.tinfo_t()
    return frame if ida_frame.get_func_frame(frame, pfn) else None


def _frame_members(pfn):
    out = {}
    frame = _frame(pfn)
    if frame is None:
        return out
    udt = ida_typeinf.udt_type_data_t()
    if not frame.get_udt_details(udt):
        return out
    for member in udt:
        out[member.offset // 8] = member.name
    return out


def _tif(size):
    code = {1: ida_typeinf.BTF_UINT8, 2: ida_typeinf.BTF_UINT16,
            4: ida_typeinf.BTF_UINT32, 8: ida_typeinf.BTF_UINT64}
    tif = ida_typeinf.tinfo_t()
    if size == 16:
        base = ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)
        if tif.create_array(base, 4):
            return tif
        return base
    return ida_typeinf.tinfo_t(code.get(size, ida_typeinf.BTF_UINT32))


def _rename_slot(pfn, members, off, name, size, renamed):
    current = members.get(off)
    if current is not None and not (ida_frame.is_dummy_member_name(current)
                                    or ida_frame.is_anonymous_member_name(current)):
        return False
    frame = _frame(pfn)
    if frame is None:
        return False
    final = name
    n = 2
    while final in renamed:
        final = "%s_%d" % (name, n)
        n += 1
    if current is None:
        if not ida_frame.add_frame_member(pfn, final, off, _tif(size)):
            return False
    else:
        idx, _udm = frame.get_udm_by_offset(off * 8)
        if idx is None or idx < 0 or frame.rename_udm(idx, final) != 0:
            return False
    renamed.add(final)
    members[off] = final
    return True


def analyze(pfn):
    members = _frame_members(pfn)
    renamed = set(members.values())
    arg_of = dict((r, "arg%d" % i) for i, r in enumerate(ARG_REGS))
    written = set()
    regvars = {}
    slots = 0
    sp_alias = set(["sp"])

    ea = pfn.start_ea
    for _ in range(MAX_PROLOGUE):
        if ea >= pfn.end_ea:
            break
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not size:
            break
        mnem = ida_ua.print_insn_mnem(ea) or ""
        feature = insn.get_canon_feature()

        if mnem in STORES:
            src = _reg(insn.ops[0])
            for opn in (1, 2):
                op = insn.ops[opn]
                if op.type != ida_ua.o_displ:
                    continue
                if _reg(op) not in sp_alias:
                    break
                off = ida_frame.calc_stkvar_struc_offset(pfn, insn, opn)
                if off == idc.BADADDR:
                    continue
                name = None
                if src in arg_of and src not in written:
                    name = arg_of[src]
                elif src in ("lr", "sp") and src not in written:
                    name = "save_" + src
                elif src in NONVOLATILE and src not in written:
                    name = "save_" + src
                if name and _rename_slot(pfn, members, off, name,
                                         STORES[mnem], renamed):
                    slots += 1
                    ida_bytes.op_stkvar(ea, opn)
                break
        elif mnem in MOVES and insn.ops[1].type == ida_ua.o_reg:
            dst, src = _reg(insn.ops[0]), _reg(insn.ops[1])
            if mnem == "or" and _reg(insn.ops[2]) != src:
                pass                                    # a real or, not a move
            elif src in sp_alias and dst:
                sp_alias.add(dst)
                written.discard(dst)
                ea += size
                continue
            elif src in arg_of and dst and dst != "sp":
                arg_of[dst] = arg_of[src]
                if dst in NONVOLATILE and arg_of[src] not in \
                        [n for n, _e in regvars.values()]:
                    regvars[dst] = (arg_of[src], ea + size)
                written.discard(dst)
                ea += size
                continue

        if feature & ida_idp.CF_CHG1 and insn.ops[0].type == ida_ua.o_reg:
            dst = _reg(insn.ops[0])
            if mnem not in MOVES:
                arg_of.pop(dst, None)
                regvars.pop(dst, None)
                sp_alias.discard(dst)
            written.add(dst)
        if feature & (ida_idp.CF_JUMP | ida_idp.CF_CALL):
            break
        ea += size

    regs = 0
    for canon, (name, from_ea) in regvars.items():
        if ida_frame.add_regvar(pfn, from_ea, pfn.end_ea, canon, name,
                                "incoming %s" % name) == 0:
            regs += 1
    return slots, regs


def run_on(ea):
    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        return None
    return analyze(pfn)


def run_all():
    slots = regs = funcs = 0
    for fea in idautils.Functions():
        got = run_on(fea)
        if got:
            slots += got[0]
            regs += got[1]
            funcs += 1
    return funcs, slots, regs


class SpuHelperPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Name saved registers and argument slots in SPU functions"
    help = __doc__
    wanted_name = "SPU Helper"
    wanted_hotkey = ""

    ACTIONS = (
        ("spuhelper:func", "SPU Helper: current function", "Ctrl-Alt-H", 0),
        ("spuhelper:all", "SPU Helper: all functions", "Ctrl-Alt-Shift-H", 1),
    )

    def init(self):
        if ida_idp.ph_get_id() != ida_idp.PLFM_SPU:
            return ida_idaapi.PLUGIN_SKIP
        for name, label, hotkey, arg in self.ACTIONS:
            desc = ida_kernwin.action_desc_t(name, label, self._handler(arg),
                                             hotkey, label, -1)
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
        if arg == 1:
            funcs, slots, regs = run_all()
            ida_kernwin.msg("[spuhelper] %d functions: %d stack slots, "
                            "%d registers named\n" % (funcs, slots, regs))
        else:
            got = run_on(ida_kernwin.get_screen_ea())
            if got is None:
                ida_kernwin.msg("[spuhelper] no function here\n")
            else:
                ida_kernwin.msg("[spuhelper] %d stack slots, %d registers named\n"
                                % got)
        ida_auto.auto_wait()
        return True

    def term(self):
        for name, _l, _h, _a in self.ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return SpuHelperPlugin()
