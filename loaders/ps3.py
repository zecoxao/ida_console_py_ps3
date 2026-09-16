"""PlayStation 3 SELF/ELF/PRX/SPRX loader for IDA Pro (IDAPython).

A python rewrite of xorloser's ps3.dll loader from "IDA console stuff".

What it does
    * loads SELF files directly - they are decrypted in memory using the key
      table extracted from ps3.dll (see ps3lib/keys.py), no scetool step needed
    * PPU (ELF64 PowerPC) and SPU (ELF32) files, executables and relocatable
      prx/sprx modules
    * segments from the section headers when they survived, from the program
      headers otherwise, with the Sony specific section names recognised
    * applies the PT_SCE_PPURELA relocations of a prx so the disassembly is
      not full of zero operands
    * .opd function descriptors turned into real functions, rtoc set for the
      whole image
    * module info, import stubs and export tables parsed, every NID named from
      ps3.xml (the same file xorloser's loader uses, drop it next to this one)
    * lv1/lv2 syscall tables named when one can be found

Install: copy ps3.py, ps3lib/ and ps3.xml into <IDA>/loaders.
"""

import os
import re
import struct
import sys

import ida_auto
import ida_bytes
import ida_entry
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_segment
import ida_segregs
import idc

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from ps3lib import sce as ps3_self                        # noqa: E402
from ps3lib.sce import _u16, _u32, _u64                    # noqa: E402


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

PT_LOAD = 1
PT_SCE_PPURELA = 0x700000A4
PT_PROC_PARAM = 0x60000001
PT_PRX_PARAM = 0x60000002

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_NOBITS = 1, 2, 3, 8

STT_FUNC, STT_OBJECT = 2, 1

PRX_PARAM_MAGIC = 0x1B434CEC
PROC_PARAM_MAGIC = 0x13BCC5F6
MODULE_INFO_SIZE = 0x34

# a library table entry is a size byte followed by a zero; 0x1C is the short
# form used when a library only imports or exports functions
LIB_ENTRY_SIZES = (0x1C, 0x20, 0x24, 0x2C)
LIB_ENTRY_MIN = min(LIB_ENTRY_SIZES)
LIB_ENTRY_RE = re.compile(b"[" + bytes(LIB_ENTRY_SIZES) + b"]" + bytes([0]))

# the nameless library every module exports (attribute 0x8000) always uses
# these fixed NIDs
SPECIAL_NIDS = {
    0xBC9A0086: "module_start",
    0xAB779874: "module_stop",
    0x3AB9A95E: "module_exit",
    0xD7F43016: "module_info",
    0x0D10FD3F: "module_info",
}


class Elf(object):
    def __init__(self, data):
        self.d = data
        if _u32(data, 0) != ps3_self.ELF_MAGIC:
            raise ValueError("not an ELF")
        self.is64 = data[4] == 2
        self.e_type = _u16(data, 0x10)
        self.e_machine = _u16(data, 0x12)
        if self.is64:
            self.entry, self.phoff, self.shoff = struct.unpack_from(">QQQ", data, 0x18)
            self.ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum, \
                self.shstrndx = struct.unpack_from(">6H", data, 0x34)
        else:
            self.entry, self.phoff, self.shoff = struct.unpack_from(">III", data, 0x18)
            self.ehsize, self.phentsize, self.phnum, self.shentsize, self.shnum, \
                self.shstrndx = struct.unpack_from(">6H", data, 0x28)
        self.phdrs = [self._phdr(i) for i in range(self.phnum)]
        self.shdrs = [self._shdr(i) for i in range(self.shnum)]
        self._name_sections()

    def _phdr(self, i):
        o = self.phoff + i * self.phentsize
        d = self.d
        if self.is64:
            p_type, p_flags = struct.unpack_from(">II", d, o)
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from(">6Q", d, o + 8)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack_from(">8I", d, o)
        return dict(idx=i, type=p_type, offset=p_offset, vaddr=p_vaddr, paddr=p_paddr,
                    filesz=p_filesz, memsz=p_memsz, flags=p_flags, align=p_align,
                    base=p_vaddr)

    def _shdr(self, i):
        o = self.shoff + i * self.shentsize
        d = self.d
        if self.is64:
            sh_name, sh_type = struct.unpack_from(">II", d, o)
            sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(">4Q", d, o + 8)
            sh_link, sh_info = struct.unpack_from(">II", d, o + 0x28)
            sh_addralign, sh_entsize = struct.unpack_from(">QQ", d, o + 0x30)
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, \
                sh_info, sh_addralign, sh_entsize = struct.unpack_from(">10I", d, o)
        return dict(idx=i, name_off=sh_name, name="", type=sh_type, flags=sh_flags,
                    addr=sh_addr, offset=sh_offset, size=sh_size, link=sh_link,
                    info=sh_info, entsize=sh_entsize)

    def _name_sections(self):
        if not self.shdrs or self.shstrndx >= len(self.shdrs):
            return
        strtab = self.shdrs[self.shstrndx]
        base = strtab["offset"]
        if base + strtab["size"] > len(self.d):
            return
        blob = self.d[base:base + strtab["size"]]
        for sh in self.shdrs:
            o = sh["name_off"]
            if o < len(blob):
                end = blob.find(b"\0", o)
                sh["name"] = blob[o:end if end >= 0 else len(blob)].decode("latin1")

    def section(self, name):
        for sh in self.shdrs:
            if sh["name"] == name:
                return sh
        return None

    @property
    def is_prx(self):
        return self.e_type in (ps3_self.ET_SCE_PPURELEXEC, ps3_self.ET_SCE_SPURELEXEC,
                               ps3_self.ET_SCE_STUBLIB)

    # data access by virtual address -------------------------------------
    def va_to_off(self, va):
        for ph in self.phdrs:
            if ph["type"] != PT_LOAD or not ph["filesz"]:
                continue
            if ph["base"] <= va < ph["base"] + ph["filesz"]:
                return ph["offset"] + (va - ph["base"])
        return None

    def read_va(self, va, size):
        o = self.va_to_off(va)
        if o is None:
            return None
        return self.d[o:o + size]

    def u32_va(self, va):
        b = self.read_va(va, 4)
        return None if b is None or len(b) < 4 else struct.unpack(">I", b)[0]


# ---------------------------------------------------------------------------
# NID database (ps3.xml)
# ---------------------------------------------------------------------------

class NidDatabase(object):
    """Groups of {id: (type, name, mangled)} read from ps3.xml."""

    def __init__(self, path=None):
        self.groups = {}
        self.path = path or self._find()
        if self.path:
            self._load(self.path)

    @staticmethod
    def _find():
        names = ("ps3.xml",)
        dirs = [_HERE, os.path.join(idc.idadir(), "loaders"), idc.idadir()]
        for d in dirs:
            for n in names:
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    return p
        return None

    def _load(self, path):
        import xml.etree.ElementTree as ET
        try:
            root = ET.parse(path).getroot()
        except Exception as e:
            print("[ps3] cannot parse %s: %s" % (path, e))
            return
        for group in root.iter("Group"):
            name_el = group.find("Name")
            if name_el is None or not name_el.text:
                continue
            gname = name_el.text.strip()
            entries = self.groups.setdefault(gname, {})
            for ent in group.findall("Entry"):
                sid = (ent.get("id") or "").strip()
                if not sid:
                    continue
                try:
                    value = int(sid, 16) if sid.lower().startswith("0x") else int(sid, 10)
                except ValueError:
                    continue
                entries[value] = (ent.get("type") or "func",
                                  (ent.get("name") or "").strip(),
                                  (ent.get("mangled") or "").strip())

    def lookup(self, group, value):
        """Best name for `value` in `group`, or None."""
        g = self.groups.get(group)
        if not g:
            return None
        ent = g.get(value)
        if not ent:
            return None
        _type, name, mangled = ent
        return mangled or name or None

    def has_group(self, group):
        return group in self.groups


# ---------------------------------------------------------------------------
# small IDA helpers, written so the same file works on 7.5 through 9.x
# ---------------------------------------------------------------------------

def _inf_set_be(be=True):
    try:
        import ida_ida
        ida_ida.inf_set_be(be)
        return
    except Exception:
        pass
    try:
        inf = ida_idaapi.get_inf_structure()
        inf.set_be(be)
    except Exception:
        pass


def _inf_set_64bit(is64):
    try:
        import ida_ida
        ida_ida.inf_set_app_bitness(64 if is64 else 32)
        return
    except Exception:
        pass
    try:
        import ida_ida
        ida_ida.inf_set_64bit(is64)
    except Exception:
        pass


def add_segment(start, end, name, sclass, bitness, perm=None, data=None, fill=True):
    if end <= start:
        return False
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.bitness = bitness                   # 0=16, 1=32, 2=64
    seg.align = ida_segment.saRelByte
    seg.comb = ida_segment.scPub
    if perm is not None:
        seg.perm = perm
    if not ida_segment.add_segm_ex(seg, name, sclass, ida_segment.ADDSEG_NOSREG |
                                   ida_segment.ADDSEG_OR_DIE):
        print("[ps3] failed to create segment %s at %08X" % (name, start))
        return False
    if data:
        ida_loader.mem2base(bytes(data), start, -1)
    return True


def set_name(ea, name, force=True):
    if not name:
        return
    flags = ida_name.SN_NOCHECK | ida_name.SN_NOWARN
    if force:
        flags |= ida_name.SN_FORCE
    ida_name.set_name(ea, name, flags)


def name_function(ea, name):
    """Name a function, keeping the older name as a comment when two NIDs
    resolve to the same code (it happens in the vsh export tables)."""
    old = ida_name.get_name(ea)
    if old and old != name and not old.startswith(("sub_", "loc_", "unk_", "off_")):
        set_cmt(ea, "also " + name, True)
        return False
    set_name(ea, name)
    return True


def make_func(ea, name=None):
    """Queue `ea` as a procedure.

    Note for anyone extending this: calling ida_funcs.add_func() from inside
    load_file() crashes IDA, the analysis engine is not up yet.  Queueing the
    address with auto_make_proc() gets the same result once loading is done.
    """
    if ea == ida_idaapi.BADADDR or not ida_bytes.is_loaded(ea):
        return
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    ida_auto.auto_make_proc(ea)
    if name:
        set_name(ea, name)


def make_dword(ea, name=None):
    if not ida_bytes.is_loaded(ea):
        return
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    ida_bytes.create_dword(ea, 4)
    if name:
        set_name(ea, name)


def set_cmt(ea, text, rptbl=False):
    try:
        ida_bytes.set_cmt(ea, text, rptbl)
    except Exception:
        pass


def declare_types():
    decls = """
struct SceModuleInfo {
    unsigned short attributes;
    unsigned char  version[2];
    char           name[28];
    unsigned int   toc;
    unsigned int   exports_start;
    unsigned int   exports_end;
    unsigned int   imports_start;
    unsigned int   imports_end;
};
struct SceLibStub {
    unsigned char  structsize;
    unsigned char  unused;
    unsigned short version;
    unsigned short attribute;
    unsigned short num_func;
    unsigned short num_var;
    unsigned short num_tls;
    unsigned char  info0;
    unsigned char  info1;
    unsigned char  info2;
    unsigned char  info3;
    unsigned int   libname;
    unsigned int   func_nid_table;
    unsigned int   func_stub_table;
    unsigned int   var_nid_table;
    unsigned int   var_stub_table;
    unsigned int   tls_nid_table;
    unsigned int   tls_stub_table;
};
struct SceLibEnt {
    unsigned char  structsize;
    unsigned char  unused;
    unsigned short version;
    unsigned short attribute;
    unsigned short num_func;
    unsigned short num_var;
    unsigned short num_tls;
    unsigned char  hash;
    unsigned char  reserved[3];
    unsigned int   libname;
    unsigned int   nid_table;
    unsigned int   stub_table;
};
struct SysPrxParam {
    unsigned int size;
    unsigned int magic;
    unsigned int version;
    unsigned int unknown0;
    unsigned int libent_start;
    unsigned int libent_end;
    unsigned int libstub_start;
    unsigned int libstub_end;
    unsigned int unknown1;
    unsigned int unknown2;
};
struct OPDEntry {
    unsigned int func;
    unsigned int rtoc;
};
"""
    try:
        idc.parse_decls(decls, 0)
    except Exception as e:
        print("[ps3] could not declare types: %s" % e)


def apply_struct(ea, sname, size=None):
    try:
        if size:
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        idc.SetType(ea, "%s x;" % sname)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# loader
# ---------------------------------------------------------------------------

FMT_PPU_SELF = "PlayStation 3 SELF"
FMT_PPU_ELF = "PlayStation 3 ELF"
FMT_PPU_PRX = "PlayStation 3 PRX"
FMT_SPU_SELF = "PlayStation 3 SPU SELF"
FMT_SPU_ELF = "PlayStation 3 SPU ELF"


def _peek(li, size=0x1000):
    li.seek(0)
    return li.read(size)


def _describe(data):
    """(format string, is_self) or (None, None)."""
    try:
        if ps3_self.is_self(data):
            sf = ps3_self.SelfFile(data)
            if sf.e_machine == ps3_self.EM_SPU:
                return FMT_SPU_SELF, True
            if sf.e_machine == ps3_self.EM_PPC64:
                return FMT_PPU_SELF, True
            return None, None
        if ps3_self.is_elf(data):
            machine = _u16(data, 0x12)
            e_type = _u16(data, 0x10)
            if machine == ps3_self.EM_SPU:
                return FMT_SPU_ELF, False
            if machine == ps3_self.EM_PPC64:
                if e_type in (ps3_self.ET_SCE_PPURELEXEC, ps3_self.ET_SCE_STUBLIB):
                    return FMT_PPU_PRX, False
                return FMT_PPU_ELF, False
    except Exception:
        pass
    return None, None


def accept_file(li, filename):
    data = _peek(li, 0x2000)
    fmt, _is_self = _describe(data)
    if not fmt:
        return 0
    return {"format": fmt, "processor": "spu" if "SPU" in fmt else "ppc"}


class Ps3Loader(object):
    def __init__(self, elf, selfinfo, is_spu):
        self.elf = elf
        self.selfinfo = selfinfo
        self.is_spu = is_spu
        self.nids = NidDatabase()
        self.opd_range = None          # (start, end) of .opd once known
        self.rtoc = None
        self.module_name = None
        self.regions = []              # (va_start, va_end, file_offset or None)
        # user land ppu modules are ELF64 but every address fits in 32 bits,
        # the lv1/lv2 kernels are the ones that really use 64 bit pointers
        big = any(ph["vaddr"] >= 0x100000000 for ph in elf.phdrs)
        self.ptr_size = 8 if (elf.is64 and big) else 4
        self.opd_entry_size = 24 if self.ptr_size == 8 else 8

    # -- layout -----------------------------------------------------------
    def assign_bases(self, prx_base):
        """A prx has vaddr 0 everywhere, give each loadable segment a home."""
        elf = self.elf
        if not elf.is_prx:
            return
        cur = prx_base
        for ph in elf.phdrs:
            if ph["type"] != PT_LOAD:
                continue
            align = max(ph["align"], 0x100)
            cur = (cur + align - 1) & ~(align - 1)
            ph["base"] = cur
            cur += max(ph["memsz"], ph["filesz"])
        # section addresses follow their containing segment
        for sh in elf.shdrs:
            if not sh["addr"] and sh["offset"]:
                for ph in elf.phdrs:
                    if ph["type"] == PT_LOAD and ph["filesz"] and \
                            ph["offset"] <= sh["offset"] < ph["offset"] + ph["filesz"]:
                        sh["addr"] = ph["base"] + (sh["offset"] - ph["offset"])
                        break

    def create_segments(self):
        elf = self.elf
        bitness = 2 if elf.is64 else 1
        made = 0
        usable = [sh for sh in elf.shdrs
                  if sh["addr"] and sh["size"] and sh["type"] != 0]
        if usable:
            usable.sort(key=lambda s: s["addr"])
            done = []
            for sh in usable:
                start = sh["addr"]
                end = start + sh["size"]
                if any(start < e and s < end for s, e in done):
                    print("[ps3] skipping overlapping section %d at %08X"
                          % (sh["idx"], start))
                    continue
                done.append((start, end))
                if sh["type"] == SHT_NOBITS:
                    sclass, blob = "BSS", None
                else:
                    sclass = "CODE" if sh["flags"] & 0x4 else "DATA"  # SHF_EXECINSTR
                    blob = elf.d[sh["offset"]:sh["offset"] + sh["size"]]
                name = sh["name"] or "sec%02d_%s" % (sh["idx"], sclass.lower())
                if add_segment(start, end, name, sclass, bitness, data=blob):
                    made += 1
                    self.regions.append((start, end,
                                         None if blob is None else sh["offset"]))
        else:
            for ph in elf.phdrs:
                if ph["type"] != PT_LOAD or not ph["memsz"]:
                    continue
                start = ph["base"]
                blob = elf.d[ph["offset"]:ph["offset"] + ph["filesz"]]
                exec_ = bool(ph["flags"] & 1)
                name = "seg%02d_%s" % (ph["idx"], "text" if exec_ else "data")
                if add_segment(start, start + ph["memsz"], name,
                               "CODE" if exec_ else "DATA", bitness, data=blob):
                    made += 1
                    self.regions.append((start, start + ph["filesz"], ph["offset"]))
        return made

    # -- relocations ------------------------------------------------------
    def apply_relocations(self):
        elf = self.elf
        rela = [ph for ph in elf.phdrs if ph["type"] == PT_SCE_PPURELA]
        if not rela:
            return 0
        # a relocation names its segments by their PT_LOAD index, not by the
        # index of the program header
        load_bases = [ph["base"] for ph in elf.phdrs if ph["type"] == PT_LOAD]
        applied = skipped = 0
        for ph in rela:
            count = ph["filesz"] // 0x18
            for i in range(count):
                o = ph["offset"] + i * 0x18
                offset = _u64(elf.d, o)
                idx_value = elf.d[o + 0x0A]
                idx_addr = elf.d[o + 0x0B]
                rtype = _u32(elf.d, o + 0x0C)
                ptr = _u64(elf.d, o + 0x10)
                if idx_addr >= len(load_bases):
                    skipped += 1
                    continue
                addr = load_bases[idx_addr] + offset
                value = (load_bases[idx_value] + ptr) if idx_value < len(load_bases) else ptr
                if not ida_bytes.is_loaded(addr):
                    skipped += 1
                    continue
                if rtype == 1 or rtype == 11:                   # ADDR32
                    ida_bytes.patch_dword(addr, value & 0xFFFFFFFF)
                elif rtype == 4:                                # ADDR16_LO
                    ida_bytes.patch_word(addr, value & 0xFFFF)
                elif rtype == 5:                                # ADDR16_HI
                    ida_bytes.patch_word(addr, (value >> 16) & 0xFFFF)
                elif rtype == 6:                                # ADDR16_HA
                    ida_bytes.patch_word(addr, ((value + 0x8000) >> 16) & 0xFFFF)
                elif rtype == 10:                               # REL24
                    delta = (value - addr) & 0x3FFFFFF
                    insn = ida_bytes.get_dword(addr)
                    ida_bytes.patch_dword(addr, (insn & ~0x03FFFFFC) | (delta & 0x03FFFFFC))
                elif rtype == 38:                               # ADDR64
                    ida_bytes.patch_qword(addr, value)
                elif rtype == 44:                               # REL64
                    ida_bytes.patch_qword(addr, (value - addr) & 0xFFFFFFFFFFFFFFFF)
                elif rtype == 57:                               # ADDR16_LO_DS
                    ida_bytes.patch_word(addr, value & 0xFFFC)
                else:
                    skipped += 1
                    continue
                applied += 1
        if skipped:
            print("[ps3] relocations: %d applied, %d skipped" % (applied, skipped))
        else:
            print("[ps3] relocations: %d applied" % applied)
        return applied

    # -- symbols ----------------------------------------------------------
    def load_symbols(self):
        elf = self.elf
        count = 0
        for sh in elf.shdrs:
            if sh["type"] != SHT_SYMTAB or sh["link"] >= len(elf.shdrs):
                continue
            strtab = elf.shdrs[sh["link"]]
            blob = elf.d[strtab["offset"]:strtab["offset"] + strtab["size"]]
            entsize = sh["entsize"] or (0x18 if elf.is64 else 0x10)
            for i in range(sh["size"] // entsize):
                o = sh["offset"] + i * entsize
                if elf.is64:
                    st_name = _u32(elf.d, o)
                    st_info = elf.d[o + 4]
                    st_value = _u64(elf.d, o + 8)
                else:
                    st_name = _u32(elf.d, o)
                    st_value = _u32(elf.d, o + 4)
                    st_info = elf.d[o + 0x0C]
                if not st_name or not st_value:
                    continue
                end = blob.find(b"\0", st_name)
                name = blob[st_name:end if end >= 0 else len(blob)].decode("latin1")
                if not name:
                    continue
                ea = st_value
                if elf.is_prx:
                    # prx symbols are section relative, sh_shndx tells which
                    shndx = _u16(elf.d, o + 6 if elf.is64 else o + 0x0E)
                    if 0 < shndx < len(elf.shdrs):
                        ea = elf.shdrs[shndx]["addr"] + st_value
                if not ida_bytes.is_loaded(ea):
                    continue
                stype = st_info & 0xF
                if stype == STT_FUNC:
                    make_func(ea, name)
                else:
                    set_name(ea, name)
                count += 1
        if count:
            print("[ps3] %d symbols from the symbol table" % count)
        return count

    # -- opd --------------------------------------------------------------
    # -- raw image access -------------------------------------------------
    def _exec_ranges(self):
        return [(ph["base"], ph["base"] + ph["memsz"])
                for ph in self.elf.phdrs
                if ph["type"] == PT_LOAD and ph["flags"] & 1 and ph["memsz"]]

    def _data_regions(self):
        """Loaded regions that are backed by file data, as (va, bytes)."""
        out = []
        for va, end, off in self.regions:
            if off is None:
                continue
            out.append((va, self.elf.d[off:off + (end - va)]))
        return out

    def _words(self, blob):
        """blob as an array of big endian pointer sized words."""
        n = len(blob) // self.ptr_size
        fmt = ">%d%s" % (n, "Q" if self.ptr_size == 8 else "I")
        return struct.unpack_from(fmt, blob, 0), n

    # -- opd ---------------------------------------------------------------
    def find_opd(self):
        """(start, count) of the .opd table.

        An .opd entry is {function, rtoc} on 32 bit images and the standard
        ppc64 {function, rtoc, env} on the 64 bit kernels.  When the section
        names survived we just take .opd, otherwise we look for the longest
        run of entries whose function points into an executable segment and
        whose rtoc is always the same value.
        """
        elf = self.elf
        sh = elf.section(".opd")
        stride = self.opd_entry_size // self.ptr_size
        if sh and sh["addr"] and sh["size"]:
            return sh["addr"], sh["size"] // self.opd_entry_size
        execs = self._exec_ranges()
        if not execs:
            return None
        best = None
        for va, blob in self._data_regions():
            words, n = self._words(blob)
            hits = [i for i in range(n - 1)
                    if any(lo <= words[i] < hi for lo, hi in execs)]
            if len(hits) < 8:
                continue
            tocs = {}
            for i in hits:
                tocs[words[i + 1]] = tocs.get(words[i + 1], 0) + 1
            toc, votes = max(tocs.items(), key=lambda kv: kv[1])
            if votes < 8 or not toc:
                continue
            run_start = None
            run = 0
            i = 0
            while i + 1 < n:
                if any(lo <= words[i] < hi for lo, hi in execs) and words[i + 1] == toc:
                    if run_start is None:
                        run_start = i
                    run += 1
                    i += stride
                    continue
                if run and (best is None or run > best[1]):
                    best = (va + run_start * self.ptr_size, run)
                run_start = None
                run = 0
                i += 1
            if run and (best is None or run > best[1]):
                best = (va + run_start * self.ptr_size, run)
        if not best or best[1] < 16:
            return None
        # a real .opd starts where a section starts; without that check a
        # random table of function pointers (lv1 has one) gets picked up
        starts = set(sh["addr"] for sh in elf.shdrs if sh["addr"])
        if starts and best[0] not in starts:
            return None
        print("[ps3] .opd found at %08X (%d entries, section names were stripped)"
              % best)
        return best

    def process_opd(self):
        """Turn every .opd entry into a real function."""
        if self.is_spu:
            return 0
        found = self.find_opd()
        if not found:
            return 0
        start, count = found
        self.opd_range = (start, start + count * self.opd_entry_size)
        get = ida_bytes.get_qword if self.ptr_size == 8 else ida_bytes.get_dword
        made = 0
        for i in range(count):
            ea = start + i * self.opd_entry_size
            if not ida_bytes.is_loaded(ea):
                break
            func = get(ea)
            toc = get(ea + self.ptr_size)
            if not func or not ida_bytes.is_loaded(func):
                continue
            if self.ptr_size == 4:
                apply_struct(ea, "OPDEntry", 8)
            if self.rtoc is None and toc:
                self.rtoc = toc
            name = ida_name.get_name(ea)
            make_func(func)
            if name and not name.startswith(("opd_", "unk_", "byte_", "dword_",
                                             "off_", "qword_")):
                set_name(func, name)
                set_name(ea, "opd_" + name)
            made += 1
        if made:
            print("[ps3] %d .opd entries" % made)
        return made

    def set_rtoc(self):
        """Tell IDA the value of r2 so TOC relative loads are resolved."""
        if self.is_spu:
            return
        if self.rtoc is None:
            sh = self.elf.section(".toc") or self.elf.section(".got")
            if sh and sh["addr"]:
                self.rtoc = sh["addr"] + 0x8000
        if self.rtoc is None:
            return
        try:
            reg = ida_idp.str2reg("rtoc")
            if reg < 0:
                reg = ida_idp.str2reg("r2")
            if reg < 0:
                return
            for seg in map(ida_segment.getnseg, range(ida_segment.get_segm_qty())):
                if seg is None:
                    continue
                ida_segregs.set_default_sreg_value(seg, reg, self.rtoc)
            print("[ps3] rtoc = 0x%08X" % self.rtoc)
        except Exception as e:
            print("[ps3] could not set rtoc: %s" % e)

    # -- module info / imports / exports ----------------------------------
    def find_module_info(self):
        elf = self.elf
        sh = elf.section(".rodata.sceModuleInfo") or elf.section(".sceModuleInfo.rodata")
        if sh and sh["addr"]:
            return sh["addr"]
        if elf.is_prx and elf.phdrs:
            # for a prx the module info offset lives in phdr[0].p_paddr
            ph = elf.phdrs[0]
            off = ph["paddr"]
            if off and off < len(elf.d):
                return ph["base"] + (off - ph["offset"]) if off >= ph["offset"] else None
        return None

    def find_prx_param(self):
        """(libent_start, libent_end, libstub_start, libstub_end) or None."""
        elf = self.elf
        sh = elf.section(".sys_proc_prx_param")
        ea = sh["addr"] if sh and sh["addr"] else None
        if ea is None:
            for ph in elf.phdrs:
                if ph["type"] == PT_PRX_PARAM:
                    ea = ph["vaddr"] or ph["paddr"]
                    if ea:
                        break
        if ea is None or not ida_bytes.is_loaded(ea):
            return None
        if ida_bytes.get_dword(ea + 4) != PRX_PARAM_MAGIC:
            return None
        apply_struct(ea, "SysPrxParam", 0x28)
        set_name(ea, "sys_proc_prx_param")
        return (ida_bytes.get_dword(ea + 0x10), ida_bytes.get_dword(ea + 0x14),
                ida_bytes.get_dword(ea + 0x18), ida_bytes.get_dword(ea + 0x1C))

    def process_proc_param(self):
        """.sys_proc_param / PT_PROC_PARAM, holds the sdk version and the
        priority and stack size of the primary thread."""
        elf = self.elf
        sh = elf.section(".sys_proc_param")
        ea = sh["addr"] if sh and sh["addr"] else None
        if ea is None:
            for ph in elf.phdrs:
                if ph["type"] == PT_PROC_PARAM:
                    ea = ph["vaddr"] or ph["paddr"]
                    if ea:
                        break
        if not ea or not ida_bytes.is_loaded(ea):
            return
        if ida_bytes.get_dword(ea + 4) != PROC_PARAM_MAGIC:
            return
        set_name(ea, "sys_process_param")
        sdk = ida_bytes.get_dword(ea + 0x0C)
        prio = ida_bytes.get_dword(ea + 0x10)
        stack = ida_bytes.get_dword(ea + 0x14)
        set_cmt(ea, "sdk version %06X, primary thread prio %d, stack size 0x%X"
                % (sdk, prio, stack))
        print("[ps3] sdk version %06X, primary thread prio %d, stack size 0x%X"
              % (sdk, prio, stack))

    def process_module_info(self):
        ea = self.find_module_info()
        if ea is None or not ida_bytes.is_loaded(ea):
            return None
        raw = ida_bytes.get_bytes(ea, MODULE_INFO_SIZE)
        if not raw:
            return None
        name = raw[4:0x20].split(b"\0")[0].decode("latin1", "replace")
        toc, ent_start, ent_end, stub_start, stub_end = struct.unpack_from(">5I", raw, 0x20)
        apply_struct(ea, "SceModuleInfo", MODULE_INFO_SIZE)
        set_name(ea, "sceModuleInfo")
        self.module_name = name or None
        if toc and self.rtoc is None:
            self.rtoc = toc
        print("[ps3] module '%s' toc=%08X exports=%08X..%08X imports=%08X..%08X"
              % (name, toc, ent_start, ent_end, stub_start, stub_end))
        return ent_start, ent_end, stub_start, stub_end

    # -- finding .lib.ent / .lib.stub the hard way -------------------------
    def scan_lib_tables(self):
        """(ent_range, stub_range) found by walking the image.

        vsh.self has a full .lib.ent and .lib.stub but an *empty*
        sys_prx_param, and its section names are stripped, so nothing points
        at either table.  Both are arrays of structures that are easy to
        recognise: a size byte, a zero, counts, and three pointers that have
        to land inside the image.
        """
        runs = []
        for va, blob in self._data_regions():
            for start, end in self._lib_runs(va, blob):
                runs.append((start, end))
        if not runs:
            return None, None
        runs.sort()
        ent = stub = None
        for start, end in runs:
            if self._run_is_export(start):
                if ent is None or end - start > ent[1] - ent[0]:
                    ent = (start, end)
            else:
                if stub is None or end - start > stub[1] - stub[0]:
                    stub = (start, end)
        return ent, stub

    def _lib_runs(self, va, blob):
        """Runs of back to back library structures inside one region."""
        hits = {}
        for m in LIB_ENTRY_RE.finditer(blob):
            o = m.start()
            if o & 3:
                continue
            size = blob[o]
            if self._is_lib_entry(va, blob, o, size):
                hits[o] = size
        out = []
        used = set()
        for o in sorted(hits):
            if o in used:
                continue
            end = o
            while end in hits:
                used.add(end)
                end += hits[end]
            count = 0
            p = o
            while p < end:
                count += 1
                p += hits[p]
            starts = set(sh["addr"] for sh in self.elf.shdrs if sh["addr"])
            if count >= 2 or (va + o) in starts:
                out.append((va + o, va + end))
        return out

    def _is_lib_entry(self, va, blob, o, size):
        if o + size > len(blob):
            return False
        num_func, num_var, num_tls = struct.unpack_from(">3H", blob, o + 6)
        total = num_func + num_var + num_tls
        if not total or total > 0x4000:
            return False
        libname, tbl1, tbl2 = struct.unpack_from(">3I", blob, o + 0x10)
        attribute = struct.unpack_from(">H", blob, o + 4)[0]
        if libname:
            if not self._raw_string(libname):
                return False
        elif not attribute & 0x8000:
            return False
        if not self._raw_at(tbl1) or not self._raw_at(tbl2):
            return False
        return True

    def _raw_at(self, va):
        """(blob, offset) for a virtual address, straight out of the file."""
        for start, end, off in self.regions:
            if off is not None and start <= va < end:
                return self.elf.d, off + (va - start)
        return None

    def _raw_string(self, va, limit=64):
        got = self._raw_at(va)
        if not got:
            return None
        blob, o = got
        end = blob.find(b"\0", o, o + limit)
        if end <= o:
            return None
        text = blob[o:end]
        if not all(0x20 <= c < 0x7F for c in text):
            return None
        return text.decode("latin1")

    def _run_is_export(self, start):
        """Export tables point into .opd, import tables point at trampolines."""
        got = self._raw_at(start)
        if not got:
            return False
        blob, o = got
        tbl2 = struct.unpack_from(">I", blob, o + 0x18)[0]
        first = self._raw_at(tbl2)
        if not first:
            return False
        ptr = struct.unpack_from(">I", first[0], first[1])[0]
        if self.opd_range:
            return self.opd_range[0] <= ptr < self.opd_range[1]
        # no .opd to compare against: an import trampoline is executable
        for ph in self.elf.phdrs:
            if ph["type"] == PT_LOAD and ph["flags"] & 1 and \
                    ph["base"] <= ptr < ph["base"] + ph["memsz"]:
                return False
        return True

    def _cstring(self, ea):
        if not ea or not ida_bytes.is_loaded(ea):
            return None
        raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if raw:
            return raw.decode("latin1")
        out = bytearray()
        while ida_bytes.is_loaded(ea) and len(out) < 128:
            c = ida_bytes.get_byte(ea)
            if not c:
                break
            out.append(c)
            ea += 1
        return out.decode("latin1") if out else None

    def _nid_name(self, library, nid, kind, special=False):
        if special:
            return SPECIAL_NIDS.get(nid, "module_%08X" % nid)
        name = self.nids.lookup(library, nid)
        if name:
            return name
        return "%s_%08X" % (library or "unk", nid)

    def process_imports(self, stub_start, stub_end):
        if not stub_start or stub_end <= stub_start:
            return 0
        libs = 0
        ea = stub_start
        while ea + LIB_ENTRY_MIN <= stub_end:
            size = ida_bytes.get_byte(ea)
            if size not in LIB_ENTRY_SIZES:
                break
            num_func = ida_bytes.get_word(ea + 6)
            num_var = ida_bytes.get_word(ea + 8)
            num_tls = ida_bytes.get_word(ea + 0x0A)
            libname_ea = ida_bytes.get_dword(ea + 0x10)
            fnid_tbl = ida_bytes.get_dword(ea + 0x14)
            fstub_tbl = ida_bytes.get_dword(ea + 0x18)
            # a library that imports only functions gets the short 0x1C form
            vnid_tbl = ida_bytes.get_dword(ea + 0x1C) if size >= 0x24 else 0
            vstub_tbl = ida_bytes.get_dword(ea + 0x20) if size >= 0x24 else 0
            tnid_tbl = ida_bytes.get_dword(ea + 0x24) if size >= 0x2C else 0
            tstub_tbl = ida_bytes.get_dword(ea + 0x28) if size >= 0x2C else 0
            library = self._cstring(libname_ea) or "unknown"
            apply_struct(ea, "SceLibStub", size)
            set_name(ea, "_stub_%s" % _ident(library))
            if libname_ea:
                set_name(libname_ea, "_libname_%s" % _ident(library))
            self._import_table(library, fnid_tbl, fstub_tbl, num_func, "func")
            self._import_table(library, vnid_tbl, vstub_tbl, num_var, "var")
            self._import_table(library, tnid_tbl, tstub_tbl, num_tls, "tls")
            libs += 1
            ea += size
        if libs:
            print("[ps3] %d imported libraries" % libs)
        return libs

    def _import_table(self, library, nid_tbl, stub_tbl, count, kind):
        if not count or not nid_tbl or not stub_tbl:
            return
        for i in range(count):
            nid_ea = nid_tbl + i * 4
            stub_ea = stub_tbl + i * 4
            if not ida_bytes.is_loaded(nid_ea) or not ida_bytes.is_loaded(stub_ea):
                return
            nid = ida_bytes.get_dword(nid_ea)
            target = ida_bytes.get_dword(stub_ea)
            name = self._nid_name(library, nid, kind)
            make_dword(nid_ea, "%s_nid_%s" % (kind, _ident(name)))
            set_cmt(nid_ea, "NID=0x%08X %s" % (nid, name))
            make_dword(stub_ea, "_imp_%s" % _ident(name))
            if not target or not ida_bytes.is_loaded(target):
                continue
            if kind == "func":
                # the stub table points straight at the trampoline in
                # .sceStub.text, which the kernel patches at load time -
                # naming it is what turns a call site into "bl cellFsOpen"
                make_func(target)
                name_function(target, _ident(name))
            else:
                set_name(target, _ident(name))

    def process_exports(self, ent_start, ent_end):
        if not ent_start or ent_end <= ent_start:
            return 0
        libs = 0
        ea = ent_start
        while ea + LIB_ENTRY_MIN <= ent_end:
            size = ida_bytes.get_byte(ea)
            if size not in LIB_ENTRY_SIZES:
                break
            attribute = ida_bytes.get_word(ea + 4)
            num_func = ida_bytes.get_word(ea + 6)
            num_var = ida_bytes.get_word(ea + 8)
            num_tls = ida_bytes.get_word(ea + 0x0A)
            libname_ea = ida_bytes.get_dword(ea + 0x10)
            nid_tbl = ida_bytes.get_dword(ea + 0x14)
            stub_tbl = ida_bytes.get_dword(ea + 0x18)
            special = bool(attribute & 0x8000) and not libname_ea
            library = self._cstring(libname_ea) or self.module_name or "exports"
            apply_struct(ea, "SceLibEnt", size)
            set_name(ea, "_export_%s" % _ident(library))
            if libname_ea:
                set_name(libname_ea, "_expname_%s" % _ident(library))
            total = num_func + num_var + num_tls
            for i in range(total):
                nid_ea = nid_tbl + i * 4
                ptr_ea = stub_tbl + i * 4
                if not ida_bytes.is_loaded(nid_ea) or not ida_bytes.is_loaded(ptr_ea):
                    break
                nid = ida_bytes.get_dword(nid_ea)
                target = ida_bytes.get_dword(ptr_ea)
                kind = "func" if i < num_func else ("var" if i < num_func + num_var else "tls")
                name = self._nid_name(library, nid, kind, special)
                make_dword(nid_ea, "%s_export_nid_%s" % (kind, _ident(name)))
                set_cmt(nid_ea, "NID=0x%08X %s" % (nid, name))
                make_dword(ptr_ea, "_exp_%s" % _ident(name))
                if target and ida_bytes.is_loaded(target):
                    if kind == "func":
                        apply_struct(target, "OPDEntry", 8)
                        func = ida_bytes.get_dword(target)
                        if func and ida_bytes.is_loaded(func):
                            make_func(func)
                            if name_function(func, _ident(name)):
                                set_name(target, "opd_%s" % _ident(name))
                                ida_entry.add_entry(nid, func, _ident(name), True)
                            else:
                                ida_entry.add_entry(nid, func, "", False)
                    else:
                        set_name(target, _ident(name))
            libs += 1
            ea += size
        if libs:
            print("[ps3] %d exported libraries" % libs)
        return libs

    def name_spu_note(self):
        """spu images carry their module name in a .note.spu_name note."""
        if not self.is_spu:
            return
        sh = self.elf.section(".note.spu_name")
        if not sh or not sh["size"]:
            return
        blob = self.elf.d[sh["offset"]:sh["offset"] + sh["size"]]
        # note: namesz, descsz, type, name, desc
        try:
            namesz, descsz = struct.unpack_from(">II", blob, 0)
            desc = blob[0x0C + ((namesz + 3) & ~3):][:descsz]
            name = desc.split(b"\0")[0].decode("latin1")
        except Exception:
            return
        if name:
            self.module_name = name
            print("[ps3] spu module '%s'" % name)

    # -- syscalls ---------------------------------------------------------
    def name_syscall_table(self):
        """lv1/lv2 keep an array of pointers to the .opd entry of every
        syscall handler, find it and name the handlers from ps3.xml."""
        if self.is_spu or self.selfinfo is None or not self.opd_range:
            return 0
        group = {2: "Syscall_lv1", 3: "Syscall_lv2"}.get(self.selfinfo.self_type)
        if not group or not self.nids.has_group(group):
            return 0
        table = self._find_syscall_table()
        if table is None:
            print("[ps3] no syscall table found")
            return 0
        start, count = table
        set_name(start, "syscall_table")
        get = ida_bytes.get_qword if self.ptr_size == 8 else ida_bytes.get_dword
        prefix = "lv1" if self.selfinfo.self_type == 2 else "lv2"

        # every syscall number the firmware does not implement points at one
        # shared stub.  Without this the names of the 88 syscalls that ps3.xml
        # still lists but 4.93 dropped would all land on that one function.
        handlers = {}
        for i in range(count):
            opd = get(start + i * self.ptr_size)
            func = get(opd) if opd and ida_bytes.is_loaded(opd) else 0
            handlers[i] = func if func and ida_bytes.is_loaded(func) else 0
        counts = {}
        for func in handlers.values():
            counts[func] = counts.get(func, 0) + 1
        shared = set(f for f, c in counts.items() if f and c >= 8)
        for func in shared:
            set_name(func, "%s_invalid_syscall" % prefix)

        named = dropped = 0
        claimed = {}
        for i in range(count):
            ea = start + i * self.ptr_size
            name = self.nids.lookup(group, i)
            func = handlers[i]
            if name:
                set_cmt(ea, "%d: %s" % (i, name))
                first = claimed.get(name)
                if first is not None and handlers[first] != func:
                    # ps3.xml gives 802 and 803 the same name (803 is really
                    # sys_fs_write) - say so instead of quietly making a
                    # "name_0" out of the second one
                    print("[ps3] ps3.xml names both syscall %d and %d '%s', "
                          "they are different functions" % (first, i, name))
                claimed.setdefault(name, i)
            if not func:
                continue
            if func in shared:
                if name:
                    dropped += 1
                continue
            if name:
                if name_function(func, _ident(name)):
                    opd = get(ea)
                    set_name(opd, "opd_" + _ident(name))
                named += 1
            elif not ida_name.get_name(func):
                set_name(func, "%s_syscall_%d" % (prefix, i))
        print("[ps3] syscall table at %08X with %d entries, %d handlers named, "
              "%d unimplemented" % (start, count, named, dropped))
        return named

    def _find_syscall_table(self):
        """The longest run of pointers into .opd that is not the .opd itself."""
        lo, hi = self.opd_range
        best = None
        for va, blob in self._data_regions():
            if va == lo:
                continue
            words, n = self._words(blob)
            run_start = None
            run = 0
            for i in range(n):
                if lo <= words[i] < hi:
                    if run_start is None:
                        run_start = i
                    run += 1
                    continue
                if run >= 128 and (best is None or run > best[1]):
                    best = (va + run_start * self.ptr_size, run)
                run_start = None
                run = 0
            if run >= 128 and (best is None or run > best[1]):
                best = (va + run_start * self.ptr_size, run)
        return best


def _ident(name):
    """Turn an sdk name into something IDA accepts as an identifier.

    Leading underscores are kept: `_sys_strncmp` is not `sys_strncmp`, and the
    mangled names in ps3.xml (`_ZdlPv`) only demangle with theirs intact.
    """
    if not name:
        return "unknown"
    out = []
    for c in name:
        out.append(c if (c.isalnum() or c in "_:.$?@") else "_")
    res = "".join(out)
    if res[:1].isdigit():
        res = "_" + res
    return res or "unknown"


def load_file(li, neflags, format):
    li.seek(0)
    data = li.read(li.size())

    selfinfo = None
    if ps3_self.is_self(data):
        try:
            elf_data, selfinfo = ps3_self.self_to_elf(data)
        except ps3_self.SceError as e:
            ida_kernwin.warning("Cannot decrypt this SELF:\n%s" % e)
            return 0
        for line in selfinfo.describe():
            print("[ps3] %s" % line)
        for line in selfinfo.log:
            print("[ps3] note: %s" % line)
    else:
        elf_data = data
        print("[ps3] plain ELF - load the original SELF instead if you have it, "
              "it carries names and info that the ELF does not")

    try:
        elf = Elf(elf_data)
    except Exception as e:
        ida_kernwin.warning("Not a usable PS3 ELF: %s" % e)
        return 0

    is_spu = elf.e_machine == ps3_self.EM_SPU
    ida_idp.set_processor_type("spu" if is_spu else "ppc", ida_idp.SETPROC_LOADER)
    _inf_set_be(True)
    _inf_set_64bit(elf.is64 and not is_spu)
    try:
        ida_nalt.set_compiler_id(ida_idp.COMP_GNU)
    except Exception:
        pass
    declare_types()

    ldr = Ps3Loader(elf, selfinfo, is_spu)

    prx_base = 0x10000
    if elf.is_prx:
        ldr.assign_bases(prx_base)

    if not ldr.create_segments():
        ida_kernwin.warning("No segment could be created from this file")
        return 0

    if elf.is_prx:
        ldr.apply_relocations()

    ldr.load_symbols()
    ldr.process_opd()

    ldr.process_proc_param()
    prx_param = ldr.find_prx_param()
    modinfo = ldr.process_module_info()
    if modinfo:
        ent_start, ent_end, stub_start, stub_end = modinfo
    elif prx_param:
        ent_start, ent_end, stub_start, stub_end = prx_param
    else:
        ent_start = ent_end = stub_start = stub_end = 0
    if not stub_start or not ent_start:
        # vsh.self and friends: tables are there but nothing points at them
        ent, stub = ldr.scan_lib_tables()
        if ent and not ent_start:
            ent_start, ent_end = ent
            print("[ps3] .lib.ent found at %08X..%08X" % ent)
        if stub and not stub_start:
            stub_start, stub_end = stub
            print("[ps3] .lib.stub found at %08X..%08X" % stub)
    ldr.process_imports(stub_start, stub_end)
    ldr.process_exports(ent_start, ent_end)

    ldr.set_rtoc()

    # entry point
    entry = elf.entry
    if entry and elf.is_prx:
        entry = 0
    if entry and ida_bytes.is_loaded(entry):
        if ldr.opd_range and ldr.opd_range[0] <= entry < ldr.opd_range[1]:
            get = ida_bytes.get_qword if ldr.ptr_size == 8 else ida_bytes.get_dword
            func = get(entry)
            if func and ida_bytes.is_loaded(func):
                entry = func
        make_func(entry, "start")
        ida_entry.add_entry(entry, entry, "start", True)
        try:
            import ida_ida
            ida_ida.inf_set_start_ea(entry)
            ida_ida.inf_set_start_ip(entry)
        except Exception:
            pass

    ldr.name_spu_note()
    ldr.name_syscall_table()

    if selfinfo is not None:
        # leave the SELF header summary on the first byte of the image
        seg = ida_segment.getnseg(0)
        if seg is not None:
            set_cmt(seg.start_ea, "\n".join(selfinfo.describe()), True)

    print("[ps3] done")
    return 1
