"""PPC Helper - a python rewrite of xorloser's PPCHelper plugin.

Reads the prologue of a PowerPC function and gives its stack slots and
registers names that mean something:

    before                                after
    std     r31, 0xE0+var_8(r1)           std     r31, 0xE0+save_r31(r1)
    mr      r31, r3                       arg0 = r31
    stw     r0, 0x110(r31)                stw     r0, 0x110+arg2(r31)

What it does, all of it driven by the ELF v1 PowerPC ABI the PS3 uses:

  * a store of a callee saved register (r14-r31, f14-f31) to the frame before
    anything has written to it is the register's save slot -> `save_r31`
  * r3-r10 hold the incoming integer arguments, so those registers, and any
    callee saved register they are copied into during the prologue, are named
    `arg0`..`arg7` for the body of the function
  * when such a register is spilled to the frame, that slot is named after the
    argument too

Only dummy names (var_8, arg_10, ...) are touched, so anything you or IDA has
already named is left alone - IDA's own `back_chain` / `saved_toc` /
`sender_lr` survive.

    PPC_Helper:_Current_Function    ppchelper   Ctrl-Alt-H          0
    PPC_Helper:_All_Functions       ppchelper   Ctrl-Alt-Shift-H    1
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

# stores whose first operand is the register being saved
STORES = {"std": 8, "stw": 4, "stb": 1, "sth": 2,
          "stfd": 8, "stfs": 4, "stdx": 8, "stwx": 4}
MOVES = ("mr", "mr.")

ARG_REGS = tuple("r%d" % n for n in range(3, 11))
NONVOLATILE = tuple("r%d" % n for n in range(14, 32)) + \
              tuple("f%d" % n for n in range(14, 32))

MAX_PROLOGUE = 64


def _reg(op):
    return ida_idp.get_reg_name(op.reg, 8) or ""


def _frame(pfn):
    frame = ida_typeinf.tinfo_t()
    return frame if ida_frame.get_func_frame(frame, pfn) else None


def _frame_members(pfn):
    """{offset: name} of the current frame."""
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


def _rename_slot(pfn, members, off, name, size, renamed):
    """Rename the frame slot at `off`, but only if nobody named it first.

    The frame is a tinfo since IDA 9, and its member offsets are what
    calc_stkvar_struc_offset() returns - which is *not* what define_stkvar()
    wants (that one takes a stack offset, negative for locals), so rename the
    member in the frame type directly.
    """
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
        # nothing there yet - the incoming parameter slots live above the
        # frame and IDA does not create them by itself
        if not ida_frame.add_frame_member(pfn, final, off, _tif(size)):
            return False
    else:
        idx, _udm = frame.get_udm_by_offset(off * 8)
        if idx is None or idx < 0 or frame.rename_udm(idx, final) != 0:
            return False
    renamed.add(final)
    members[off] = final
    return True


def _tif(size):
    code = {1: ida_typeinf.BTF_UINT8, 2: ida_typeinf.BTF_UINT16,
            4: ida_typeinf.BTF_UINT32, 8: ida_typeinf.BTF_UINT64}
    return ida_typeinf.tinfo_t(code.get(size, ida_typeinf.BTF_UINT64))


def analyze(pfn):
    """(slots renamed, registers renamed) for one function."""
    members = _frame_members(pfn)
    renamed = set(members.values())
    arg_of = dict((r, "arg%d" % i) for i, r in enumerate(ARG_REGS))
    written = set()
    regvars = {}
    slots = 0
    # a displacement is only a frame access when its base register really is
    # the stack pointer, r1 or a register the prologue copied it into
    sp_alias = set(["r1"])

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
                elif src in NONVOLATILE and src not in written:
                    name = "save_" + src
                if name and _rename_slot(pfn, members, off, name,
                                         STORES[mnem], renamed):
                    slots += 1
                    # without this the operand keeps showing a raw offset
                    ida_bytes.op_stkvar(ea, opn)
                break
        elif mnem in MOVES:
            dst, src = _reg(insn.ops[0]), _reg(insn.ops[1])
            if src in sp_alias and dst:
                sp_alias.add(dst)
                written.discard(dst)
                ea += size
                continue
            if src in arg_of and dst and dst not in ("r1",):
                arg_of[dst] = arg_of[src]
                # the register only holds the argument from here on, before
                # this it still has the caller's value, and the first register
                # to take an argument is the one that gets to wear its name
                if dst in NONVOLATILE and arg_of[src] not in                         [n for n, _e in regvars.values()]:
                    regvars[dst] = (arg_of[src], ea + size)
                written.discard(dst)
                ea += size
                continue

        # whatever else the instruction changes stops being an argument
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


class PpcHelperPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Name saved registers and argument slots in PowerPC functions"
    help = __doc__
    wanted_name = "PPC Helper"
    wanted_hotkey = ""

    ACTIONS = (
        ("ppchelper:func", "PPC Helper: current function", "Ctrl-Alt-H", 0),
        ("ppchelper:all", "PPC Helper: all functions", "Ctrl-Alt-Shift-H", 1),
    )

    def init(self):
        if ida_idp.ph_get_id() != ida_idp.PLFM_PPC:
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
            ida_kernwin.msg("[ppchelper] %d functions: %d stack slots, "
                            "%d registers named\n" % (funcs, slots, regs))
        else:
            got = run_on(ida_kernwin.get_screen_ea())
            if got is None:
                ida_kernwin.msg("[ppchelper] no function here\n")
            else:
                ida_kernwin.msg("[ppchelper] %d stack slots, %d registers named\n"
                                % got)
        ida_auto.auto_wait()
        return True

    def term(self):
        for name, _l, _h, _a in self.ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return PpcHelperPlugin()
