# PS3 loaders for IDA Pro, in Python

A Python rewrite of the PlayStation 3 half of xorloser's *IDA console stuff*
(`ps3.dll` / `ps364.dll`, package dated 2021-03-19).  The original is a
compiled SDK plugin tied to one IDA version; this one is plain IDAPython, so it
keeps working across IDA releases and can be edited when a file does something
unexpected.

    loaders/
        ps3.py          the loader itself
        ps3.xml         NID database (xorloser's file, one typo fixed)
        ps3lib/
            sce.py      SELF container: parse, decrypt, rebuild an ELF
            keys.py     116 key sets extracted from ps3.dll
    plugins/
        ppc2c.py        C comments for tricky PowerPC instructions
        ppchelper.py    names saved registers and argument slots (PPC)
        spuhelper.py    the same for SPU

## Install

Copy `ps3.py`, `ps3.xml` and the `ps3lib` directory into `<IDA>/loaders`, and
the three files in `plugins/` into `<IDA>/plugins`.  Everything is already
installed in `C:\ida94b1`.

The helper modules live in `ps3lib/` on purpose: IDA treats every `.py` file
directly inside `loaders/` as a loader, a subdirectory is left alone.

## What it handles

| file | what you get |
| --- | --- |
| `.self` (PPU) | decrypted in memory, no scetool step |
| `.sprx` / `.prx` | relocated to 0x10000, PT_SCE_PPURELA applied |
| `.elf` (PPU) | loaded, with a reminder that the SELF carries more |
| SPU `.self` / `.elf` | loaded with IDA's SPU processor module |
| `lv1.self`, `lv2_kernel.self` | 64 bit kernels, syscall table named |

Per file it does:

* **Decryption.** The metadata info is unwrapped with each key set in turn and
  the right one is recognised by its two padding fields being zero, so key
  selection does not depend on a self-type/revision table.  That is why 4.93
  files decrypt even though the key table stops at "4.20 - 4.81" - the same
  keys are still in use.  Debug SELFs (`se_flags & 0x8000`, nothing encrypted)
  and fake-signed SELFs work too; NPDRM SELFs work when the content is free
  (the klicensee is derived), otherwise you get a message naming the content id.
* **Segments** from the section headers when they survived, from the program
  headers otherwise.  Overlapping sections are skipped rather than fought over.
* **Relocations** for prx/sprx: ADDR32, ADDR16_LO/HI/HA, REL24, ADDR64, REL64,
  ADDR16_LO_DS.
* **`.opd`**: every function descriptor becomes a real function.  Sony strips
  the section name table out of most retail files, so when `.opd` is not named
  the loader finds it - the longest run of entries whose function points into
  an executable segment and whose rtoc is one constant value, starting on a
  section boundary.  Entries are 8 bytes on user land modules and the standard
  ppc64 24 bytes on lv1/lv2.
* **rtoc**: set as the default value of `r2` for the whole image, so TOC
  relative loads resolve.
* **Module info, imports and exports**: `sceModuleInfo`, `sys_proc_prx_param`,
  `sys_process_param`, the `SceLibStub` / `SceLibEnt` tables, and a name for
  every NID out of `ps3.xml` (`cellAdecOpen`, `sys_prx_load_module`, ...).
  Unknown NIDs get `<library>_<NID>`, the same convention xorloser used.  The
  nameless library every module exports is named `module_start` / `module_stop`
  / `module_exit` / `module_info`.

  Three things were needed to make this work on every file, not just on prx:

  - `vsh.self` has a full `.lib.ent` and `.lib.stub` but an **empty**
    `sys_prx_param`, and its section names are stripped, so nothing points at
    either table.  They are found by scanning for runs of back to back library
    structures, and a run is classified as an export table when its pointers
    land in `.opd` and as an import table when they land on a trampoline.
  - a library that only deals in functions uses the short **0x1C** form of the
    structure, not just the 0x2C one.
  - an import's stub table points **straight at the trampoline** in
    `.sceStub.text`, it is not an `.opd` entry, so that address is what gets
    the name - that is what turns a call site into `bl cellFsOpen`.

  On 4.93's `vsh.self` that is 194/194 import trampolines and 4415/4415 export
  functions named, of which `ps3.xml` can resolve 131 and 4274 to real names
  (the rest are libraries the 2.60/3.20-era NID dump never saw, `_cellAudio`,
  `sceNpOauth`, `np_sns_plugin`).  When two NIDs resolve to the same code the
  first name wins and the second is added as a repeatable comment.
* **Syscall tables**: for lv1/lv2 the array of pointers into `.opd` is located
  and each handler named from the `Syscall_lv1` / `Syscall_lv2` groups of
  `ps3.xml`.

  The layout was read off the dispatcher rather than guessed.  The 0xC00
  vector lands in `sys_syscall_entry`, which does

        cmpldi  r11, 0x400        ; syscall number, 1024 slots
        blt     ok
        li      r11, 0            ; out of range uses slot 0
    ok: sldi    r11, r11, 3
        add     r13, r11, r13     ; table base comes out of the process
        ld      r13, 0(r13)       ; slot -> .opd entry
        ld      r13, 0(r13)       ; .opd entry -> function

  so a slot index *is* the syscall number, with no bias, and the table is
  exactly 1024 entries.  On 4.93 that is 632 live handlers, 435 of them named
  by `ps3.xml`, the other 197 named `lv2_syscall_<n>`.  Verified slot by slot
  against ground truth read straight out of the file: 633 of 633 exact.

  The syscall numbers the firmware dropped all point at one shared stub, which
  is named `lv2_invalid_syscall` once; the 88 names `ps3.xml` still lists for
  them are left on the table slots as comments instead of being dumped on that
  one function.

  Cross-checked against the kernel itself: 10 handlers reference a
  `syscall_sys_*` debug string naming them, and all 10 land on the function the
  table + `ps3.xml` named.  Two of those strings name syscalls `ps3.xml` cannot
  (860 `sys_ss_get_cache_of_analog_sunset_flag`, which the xml has commented
  out, and 870 `sys_ss_get_console_id`, which it never had).

  One data file bug turned up: **`ps3.xml` named both syscall 802 and 803
  `sys_fs_read`** - 803 is really `sys_fs_write`.  That one line is now fixed
  in the shipped `ps3.xml`, with an XML comment next to it saying what was
  changed; it is the only edit to xorloser's file.  Every other syscall group
  was checked for the same kind of duplicate and is clean (`Syscall_proc` has
  `proc_map_pages` on 28 and 35 and `proc_unmap_pages` on 29 and 36, but those
  look like deliberate aliases, so they were left alone).

  The loader still warns if a future edit reintroduces a duplicate name.

## Using the SELF code on its own

`ps3lib/sce.py` has no IDA dependency, so it doubles as a decrypter:

    python ps3lib/sce.py lv2_kernel.self lv2_kernel.elf

    SELF: LV2, auth id 0x1050000003000001, vendor id 0x05000002, version 4.93
          key revision 0x0000
          key set: Retail LV2 Keys (4.00 - 4.11) (LV2400)
          elf: 3641960 bytes, machine 21, type 0x0002, 2 phdrs, 11 shdrs

It uses pycryptodome or `cryptography` if either is importable and falls back
to a built-in AES otherwise (slow, but it keeps the loader working in a bare
IDA interpreter).

## Where the keys came from

`ps3.dll` carries the key table at file offset 0x105940: 116 entries of 0xD0
bytes, laid out as

    0x00 char name[0x40]      "Retail LV2 Keys (3.55)"
    0x40 char id[0x20]        "LV2355"
    0x60 u8   erk[0x20]
    0x80 u8   riv[0x10]
    0x90 u8   pub[0x28]
    0xB8 u8   priv[0x14]
    0xCC u32  ctype

`keys.py` is that table dumped verbatim.  Only `erk`/`riv` are used for
loading; `pub`/`priv`/`ctype` are kept for anyone who wants to check or forge
signatures.

## Tested on

The 4.93 firmware tree on the Desktop: all 473 SELFs under `Desktop\493`
decrypt and rebuild without a single failure (APP, ISO, IS1, LV1, LV2 key
sets), and `lv2_kernel.self`, `lv1.self`, `vsh.self`, `ps1_netemu.self`,
`bdj.self`, `libsysmodule.sprx`, `aim_spu_module.self` and a pre-extracted
`ps3swu.self.elf` all load through `idat -A` cleanly.

The naming is checked against tables read straight out of the file rather
than eyeballed: on `vsh.self` every one of the 194 import trampolines and 4415
export functions ends up with exactly the expected name, and on
`lv2_kernel.self` all 633 syscall handlers do.

(Names ending in `_0` in a kernel database are IDA's own doing: a lot of lv2
syscall entry points are one-instruction thunks, so IDA propagates the name to
the real body and adds a suffix to keep it unique.)

## The plugins

### ppc2c.py - PPC to C

Not a decompiler: it writes a C-ish comment next to the instructions that are
hard to read at a glance.

    mflr    r0                      # r0 = lr
    rlwinm  r3, r3, 28,3,31         # r3 = ((r3 << 28) | (r3 >> 4)) & 0x1FFFFFFF
    clrlwi  r0, r0, 28              # r0 = r0 & 0x0000000F
    sldi    r11, r11, 3             # r11 = r11 << 3
    srawi   r0, r3, 0x1F            # r0 = (signed)r3 >> 31 (sets carry)
    subf    r9, r0, r9              # r9 = r9 - r0
    blt     loc_275BEC              # if(cr0 is less than) goto loc_275BEC

Instructions are decoded from the raw opcode word, not from what IDA prints,
so every simplified mnemonic (sldi, srdi, clrlwi, rotlwi, extrwi, ...) is
handled without knowing how a given IDA version spells it.  Covers the rotate
and mask family (rlwinm/rlwimi/rlwnm and all four rld forms), conditional
branches, compares, the logic and shift instructions, addi/addis/li/lis and
mfspr/mtspr.

The decoder is importable and has no IDA dependency, so it can be checked
outside IDA - `python ppc2c.py --selftest` runs 19 cases whose words were
taken out of a real 4.93 `lv2_kernel.self` and whose expected text was checked
against what IDA prints at that address.

Hotkeys: `Ctrl-Alt-C` current line, `Ctrl-Alt-Shift-C` whole function.  The
plugins.cfg lines from xorloser's readme still work, `run(0)` is one line and
`run(1)` is the function.

### ppchelper.py / spuhelper.py

Read the prologue and give the stack slots and registers useful names:

    stqd    lr, var_10(sp)          ->   stqd    lr, save_lr(sp)
    stqd    r80, var_20(sp)         ->   stqd    r80, save_r80(sp)
    stw     r0, 0x110(r31)          ->   stw     r0, arg0(r31)
    lr      r84, r5                 ->   r84 becomes arg2 from here on

The rules come from the ABI: a store of a callee saved register (r14-r31 on
PPC, r80-r127 on SPU) before anything has written to it is that register's
save slot; r3-r10 (PPC) or r3-r74 (SPU) hold the incoming arguments, so those
registers, and any callee saved register the prologue copies them into, are
named `arg0`..`argN`.

Three details that matter:

* a register variable starts **after** the copy, not at the function start -
  before that the register still holds the caller's value, and naming it
  `arg0` there would be a lie
* only the first register to receive a given argument gets its name, so two
  registers never both show up as `arg0`
* a displacement is only treated as a frame access when its base register is
  really the stack pointer - `r1`, or a register the prologue copied `r1`
  into.  Without that check any `0x10(r31)` would be misread as a stack slot

Only dummy names (`var_8`, `arg_10`, ...) are touched, so IDA's own
`back_chain` / `saved_toc` / `sender_lr` and anything you named survive.  The
incoming parameter slots live above the frame and IDA does not create them by
itself, so those members are added.

Hotkeys: `Ctrl-Alt-H` current function, `Ctrl-Alt-Shift-H` every function in
the database.  Each plugin only wakes up for its own processor, so the shared
hotkey is never ambiguous.

Unlike the original SPUHelper, `spuhelper.py` works with the SPU processor
module IDA ships - it reads registers by number rather than by xorloser's
names - so there is no need to install his SPU module or rename files.

## Not carried over

* xorloser's own SPU processor module - IDA ships a perfectly good one, and
  the SPU helper here is written against it
* the Xbox 360 XEX loader
* automatic DWARF loading for debug builds - IDA's own ELF loader does that,
  and you can still point it at the extracted ELF

## Gotcha worth remembering

Do not call `ida_funcs.add_func()` from inside `load_file()`.  The analysis
engine is not up yet and IDA dies with no message at all.  Queue the address
with `ida_auto.auto_make_proc()` instead; the function appears once loading
finishes.
