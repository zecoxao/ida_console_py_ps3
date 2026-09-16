"""PS3 SCE/SELF container handling: parse, decrypt and rebuild an ELF.

This module is deliberately free of any IDA dependency so it can be tested from
a plain command line:

    python ps3lib/sce.py lv2_kernel.self lv2_kernel.elf

It understands retail SELFs (all key revisions shipped in keys.py), debug
SELFs (se_flags & 0x8000, nothing is encrypted), fake-signed SELFs and NPDRM
SELFs whose content is free (klicensee derived from the free klic).

Key selection does not rely on a self-type/revision table: every key set is
tried and the right one is recognised by the two padding fields of the
decrypted metadata info being zero.  That is what makes this work on firmware
revisions that are newer than the key table (4.90+ reuses the 4.20-4.81 keys).
"""

import binascii
import struct
import zlib

try:
    from . import keys as ps3_keys
except ImportError:  # running this file directly for a command line test
    import keys as ps3_keys


# ---------------------------------------------------------------------------
# AES
# ---------------------------------------------------------------------------

class _AES(object):
    """AES-256/128 in ECB/CBC/CTR.

    Uses pycryptodome or `cryptography` when available and falls back to a
    small pure-python implementation so the loader keeps working in an IDA
    install with a bare interpreter.
    """

    @staticmethod
    def _backend():
        if getattr(_AES, "_cached", None) is not None:
            return _AES._cached
        backend = None
        try:
            from Crypto.Cipher import AES as _pyaes
            backend = ("pycrypto", _pyaes)
        except Exception:
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                backend = ("cryptography", (Cipher, algorithms, modes))
            except Exception:
                backend = ("pure", None)
        _AES._cached = backend
        return backend

    @staticmethod
    def ecb_decrypt(key, data):
        kind, mod = _AES._backend()
        if kind == "pycrypto":
            return mod.new(key, mod.MODE_ECB).decrypt(data)
        if kind == "cryptography":
            Cipher, algorithms, modes = mod
            c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            return c.update(data) + c.finalize()
        return _PurePyAES(key).decrypt_ecb(data)

    @staticmethod
    def ecb_encrypt(key, data):
        kind, mod = _AES._backend()
        if kind == "pycrypto":
            return mod.new(key, mod.MODE_ECB).encrypt(data)
        if kind == "cryptography":
            Cipher, algorithms, modes = mod
            c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return c.update(data) + c.finalize()
        return _PurePyAES(key).encrypt_ecb(data)

    @staticmethod
    def cbc_decrypt(key, iv, data):
        kind, mod = _AES._backend()
        if kind == "pycrypto":
            return mod.new(key, mod.MODE_CBC, iv).decrypt(data)
        if kind == "cryptography":
            Cipher, algorithms, modes = mod
            c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return c.update(data) + c.finalize()
        out = bytearray()
        prev = iv
        aes = _PurePyAES(key)
        for i in range(0, len(data), 16):
            blk = data[i:i + 16]
            dec = aes.decrypt_ecb(blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        return bytes(out)

    @staticmethod
    def ctr_crypt(key, ctr, data):
        """AES-128-CTR with a full 16 byte big-endian counter."""
        kind, mod = _AES._backend()
        if kind == "pycrypto":
            from Crypto.Util import Counter
            initial = int.from_bytes(ctr, "big")
            c = Counter.new(128, initial_value=initial)
            return mod.new(key, mod.MODE_CTR, counter=c).decrypt(data)
        if kind == "cryptography":
            Cipher, algorithms, modes = mod
            c = Cipher(algorithms.AES(key), modes.CTR(ctr)).decryptor()
            return c.update(data) + c.finalize()
        aes = _PurePyAES(key)
        out = bytearray()
        counter = int.from_bytes(ctr, "big")
        for i in range(0, len(data), 16):
            ks = aes.encrypt_ecb(counter.to_bytes(16, "big"))
            counter = (counter + 1) & ((1 << 128) - 1)
            blk = data[i:i + 16]
            out += bytes(a ^ b for a, b in zip(blk, ks))
        return bytes(out)


class _PurePyAES(object):
    """Minimal table driven AES, only used when no crypto module is present."""

    _sbox = None
    _inv_sbox = None

    def __init__(self, key):
        if _PurePyAES._sbox is None:
            _PurePyAES._build_tables()
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.rk = self._expand(key)
        self.drk = list(self.rk)

    @classmethod
    def _build_tables(cls):
        p = 1
        q = 1
        sbox = [0] * 256
        inv = [0] * 256
        while True:
            # multiply p by 3
            p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
            # divide q by 3
            q ^= (q << 1) & 0xFF
            q ^= (q << 2) & 0xFF
            q ^= (q << 4) & 0xFF
            if q & 0x80:
                q ^= 0x09
            x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
                  ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
            x = (x & 0xFF) ^ 0x63
            sbox[p] = x
            inv[x] = p
            if p == 1:
                break
        sbox[0] = 0x63
        inv[0x63] = 0
        cls._sbox = sbox
        cls._inv_sbox = inv

    @staticmethod
    def _xtime(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    @classmethod
    def _mul(cls, a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = cls._xtime(a)
            b >>= 1
        return r

    def _expand(self, key):
        s = _PurePyAES._sbox
        w = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
        rcon = 1
        for i in range(self.nk, 4 * (self.nr + 1)):
            t = list(w[i - 1])
            if i % self.nk == 0:
                t = t[1:] + t[:1]
                t = [s[x] for x in t]
                t[0] ^= rcon
                rcon = self._xtime(rcon)
            elif self.nk > 6 and i % self.nk == 4:
                t = [s[x] for x in t]
            w.append([a ^ b for a, b in zip(w[i - self.nk], t)])
        return w

    def _add_rk(self, st, rnd):
        for c in range(4):
            k = self.rk[rnd * 4 + c]
            for r in range(4):
                st[r][c] ^= k[r]

    def encrypt_ecb(self, block):
        s = _PurePyAES._sbox
        st = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_rk(st, 0)
        for rnd in range(1, self.nr + 1):
            for r in range(4):
                for c in range(4):
                    st[r][c] = s[st[r][c]]
            for r in range(1, 4):
                st[r] = st[r][r:] + st[r][:r]
            if rnd != self.nr:
                for c in range(4):
                    a = [st[r][c] for r in range(4)]
                    st[0][c] = self._mul(a[0], 2) ^ self._mul(a[1], 3) ^ a[2] ^ a[3]
                    st[1][c] = a[0] ^ self._mul(a[1], 2) ^ self._mul(a[2], 3) ^ a[3]
                    st[2][c] = a[0] ^ a[1] ^ self._mul(a[2], 2) ^ self._mul(a[3], 3)
                    st[3][c] = self._mul(a[0], 3) ^ a[1] ^ a[2] ^ self._mul(a[3], 2)
            self._add_rk(st, rnd)
        return bytes(st[r][c] for c in range(4) for r in range(4))

    def decrypt_ecb(self, block):
        inv = _PurePyAES._inv_sbox
        st = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
        self._add_rk(st, self.nr)
        for rnd in range(self.nr - 1, -1, -1):
            for r in range(1, 4):
                st[r] = st[r][-r:] + st[r][:-r]
            for r in range(4):
                for c in range(4):
                    st[r][c] = inv[st[r][c]]
            self._add_rk(st, rnd)
            if rnd != 0:
                for c in range(4):
                    a = [st[r][c] for r in range(4)]
                    st[0][c] = self._mul(a[0], 14) ^ self._mul(a[1], 11) ^ self._mul(a[2], 13) ^ self._mul(a[3], 9)
                    st[1][c] = self._mul(a[0], 9) ^ self._mul(a[1], 14) ^ self._mul(a[2], 11) ^ self._mul(a[3], 13)
                    st[2][c] = self._mul(a[0], 13) ^ self._mul(a[1], 9) ^ self._mul(a[2], 14) ^ self._mul(a[3], 11)
                    st[3][c] = self._mul(a[0], 11) ^ self._mul(a[1], 13) ^ self._mul(a[2], 9) ^ self._mul(a[3], 14)
        return bytes(st[r][c] for c in range(4) for r in range(4))


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

SCE_MAGIC = 0x53434500          # 'SCE\0'
ELF_MAGIC = 0x7F454C46          # '\x7fELF'

HDR_SELF, HDR_RVK, HDR_PKG, HDR_SPP = 1, 2, 3, 4

SELF_TYPE_NAMES = {
    1: "LV0", 2: "LV1", 3: "LV2", 4: "APP",
    5: "ISO", 6: "LDR", 7: "UNK7", 8: "NPDRM",
}

CTRL_FLAGS, CTRL_DIGEST, CTRL_NPDRM = 1, 2, 3

# e_type values Sony added on top of the standard ones
ET_SCE_EXEC = 0xFFA0            # ppu exec (some sdk builds)
ET_SCE_PPURELEXEC = 0xFFA4      # .sprx / relocatable prx
ET_SCE_STUBLIB = 0xFFA5
ET_SCE_SPURELEXEC = 0xFFA6

EM_PPC64 = 21
EM_SPU = 23


class SceError(Exception):
    pass


def _u16(d, o):
    return struct.unpack_from(">H", d, o)[0]


def _u32(d, o):
    return struct.unpack_from(">I", d, o)[0]


def _u64(d, o):
    return struct.unpack_from(">Q", d, o)[0]


# ---------------------------------------------------------------------------
# SELF
# ---------------------------------------------------------------------------

class ControlInfo(object):
    def __init__(self, type_, size, payload):
        self.type = type_
        self.size = size
        self.payload = payload

    @property
    def npdrm(self):
        """(license_type, app_type, content_id) for a CTRL_NPDRM entry."""
        if self.type != CTRL_NPDRM or len(self.payload) < 0x40:
            return None
        magic = _u32(self.payload, 0)
        if magic != 0x4E504400:      # 'NPD\0'
            return None
        lic = _u32(self.payload, 8)
        app = _u32(self.payload, 0x0C)
        cid = self.payload[0x10:0x40].split(b"\0")[0].decode("latin1")
        return lic, app, cid


class SelfFile(object):
    def __init__(self, data):
        self.data = data
        self.keyset = None          # (id, description) actually used
        self.log = []
        self._parse()

    # -- parsing ----------------------------------------------------------
    def _note(self, msg):
        self.log.append(msg)

    def _parse(self):
        d = self.data
        if len(d) < 0x70 or _u32(d, 0) != SCE_MAGIC:
            raise SceError("not an SCE file")
        self.version = _u32(d, 4)
        self.se_flags = _u16(d, 8)          # aka key revision
        self.key_revision = self.se_flags & 0x7FFF
        self.is_debug = bool(self.se_flags & 0x8000)
        self.header_type = _u16(d, 0x0A)
        self.metadata_offset = _u32(d, 0x0C)
        self.header_len = _u64(d, 0x10)
        self.data_len = _u64(d, 0x18)
        if self.header_type != HDR_SELF:
            raise SceError("SCE file is not a SELF (header type %d)" % self.header_type)

        (self.self_hdr_type, self.app_info_offset, self.elf_offset,
         self.phdr_offset, self.shdr_offset, self.seg_info_offset,
         self.sce_version_offset, self.ctrl_info_offset,
         self.ctrl_info_size) = struct.unpack_from(">9Q", d, 0x20)

        o = self.app_info_offset
        self.auth_id = _u64(d, o)
        self.vendor_id = _u32(d, o + 8)
        self.self_type = _u32(d, o + 0x0C)
        self.app_version = _u64(d, o + 0x10)

        # elf header
        eo = self.elf_offset
        if _u32(d, eo) != ELF_MAGIC:
            raise SceError("no ELF header inside the SELF")
        self.elf_class = d[eo + 4]           # 1 = 32bit, 2 = 64bit
        self.is64 = self.elf_class == 2
        self.e_type = _u16(d, eo + 0x10)
        self.e_machine = _u16(d, eo + 0x12)
        if self.is64:
            self.e_entry = _u64(d, eo + 0x18)
            self.e_phoff = _u64(d, eo + 0x20)
            self.e_shoff = _u64(d, eo + 0x28)
            self.e_ehsize = _u16(d, eo + 0x34)
            self.e_phentsize = _u16(d, eo + 0x36)
            self.e_phnum = _u16(d, eo + 0x38)
            self.e_shentsize = _u16(d, eo + 0x3A)
            self.e_shnum = _u16(d, eo + 0x3C)
        else:
            self.e_entry = _u32(d, eo + 0x18)
            self.e_phoff = _u32(d, eo + 0x1C)
            self.e_shoff = _u32(d, eo + 0x20)
            self.e_ehsize = _u16(d, eo + 0x28)
            self.e_phentsize = _u16(d, eo + 0x2A)
            self.e_phnum = _u16(d, eo + 0x2C)
            self.e_shentsize = _u16(d, eo + 0x2E)
            self.e_shnum = _u16(d, eo + 0x30)

        # per segment info
        self.seg_infos = []
        for i in range(self.e_phnum):
            o = self.seg_info_offset + i * 0x20
            off, size = struct.unpack_from(">QQ", d, o)
            comp, _u1, _u2, enc = struct.unpack_from(">IIII", d, o + 0x10)
            self.seg_infos.append(dict(offset=off, size=size,
                                       compressed=comp == 2, encrypted=enc == 1))

        # control info
        self.ctrl_infos = []
        o = self.ctrl_info_offset
        end = self.ctrl_info_offset + self.ctrl_info_size
        while o + 0x10 <= end:
            ci_type = _u32(d, o)
            ci_size = _u32(d, o + 4)
            if ci_size < 0x10 or o + ci_size > end:
                break
            self.ctrl_infos.append(ControlInfo(ci_type, ci_size, d[o + 0x10:o + ci_size]))
            o += ci_size

    # -- properties -------------------------------------------------------
    @property
    def self_type_name(self):
        return SELF_TYPE_NAMES.get(self.self_type, "0x%X" % self.self_type)

    @property
    def version_string(self):
        v = self.app_version
        return "%X.%02X" % ((v >> 48) & 0xFFFF, (v >> 32) & 0xFFFF)

    @property
    def npdrm_info(self):
        for ci in self.ctrl_infos:
            n = ci.npdrm
            if n:
                return n
        return None

    # -- metadata ---------------------------------------------------------
    def _klicensee(self, klicensee=None):
        np = self.npdrm_info
        if np is None:
            return None
        lic, _app, cid = np
        if klicensee is not None:
            return klicensee
        if lic == 3 or lic == 0:       # free content
            key = binascii.unhexlify(ps3_keys.NP_KLIC_KEY)
            free = binascii.unhexlify(ps3_keys.NP_KLIC_FREE)
            return _AES.ecb_decrypt(key, free)
        self._note("NPDRM license type %d (content id %s) needs a klicensee" % (lic, cid))
        return None

    def _decrypt_metadata(self, klicensee=None):
        """Returns (metadata_info, metadata_headers) in plain text."""
        d = self.data
        mo = self.metadata_offset + 0x20
        minfo = d[mo:mo + 0x40]
        mhdrs = d[mo + 0x40:self.header_len]

        if self.is_debug:
            self.keyset = ("DEBUG", "Debug SELF (nothing is encrypted)")
            return minfo, mhdrs

        if self.self_type == 8:
            klic = self._klicensee(klicensee)
            if klic is not None:
                minfo = _AES.cbc_decrypt(klic, b"\0" * 16, minfo)

        for kid, name, erk, riv, _ctype in ps3_keys.iter_keysets():
            plain = _AES.cbc_decrypt(erk, riv, minfo)
            if plain[0x10:0x20] == b"\0" * 16 and plain[0x30:0x40] == b"\0" * 16:
                self.keyset = (kid, name)
                key, iv = plain[0:0x10], plain[0x20:0x30]
                return plain, _AES.ctr_crypt(key, iv, mhdrs)

        raise SceError("no key set decrypts this SELF (self type %s, key revision 0x%X)"
                       % (self.self_type_name, self.key_revision))

    def metadata(self, klicensee=None):
        minfo, mh = self._decrypt_metadata(klicensee)
        sig_len, _unk0, sec_count, key_count, opt_size = struct.unpack_from(">QIIII", mh, 0)
        sections = []
        for i in range(sec_count):
            o = 0x20 + i * 0x30
            (data_offset, data_size, stype, prog_idx, hashed, sha1_idx,
             encrypted, key_idx, iv_idx, compressed) = struct.unpack_from(">QQIIIIIIII", mh, o)
            sections.append(dict(offset=data_offset, size=data_size, type=stype,
                                 program_idx=prog_idx, sha1_idx=sha1_idx,
                                 encrypted=encrypted == 3, key_idx=key_idx,
                                 iv_idx=iv_idx, compressed=compressed == 2))
        keys_off = 0x20 + sec_count * 0x30
        keys = [mh[keys_off + i * 0x10:keys_off + (i + 1) * 0x10] for i in range(key_count)]
        return minfo, sections, keys

    # -- rebuild ----------------------------------------------------------
    def to_elf(self, klicensee=None):
        d = self.data
        sections = keys = None
        try:
            _minfo, sections, keys = self.metadata(klicensee)
        except SceError as e:
            # Fake-signed / already plain SELFs can still be rebuilt from the
            # segment info table alone as long as nothing is encrypted.
            if any(s["encrypted"] for s in self.seg_infos):
                raise
            self._note(str(e) + " - falling back to the segment info table")

        phent = self.e_phentsize or (0x38 if self.is64 else 0x20)
        shent = self.e_shentsize or (0x40 if self.is64 else 0x28)

        # collect the pieces that go into the output file
        pieces = []           # (offset, bytes)
        ehsize = self.e_ehsize or (0x40 if self.is64 else 0x34)
        pieces.append((0, d[self.elf_offset:self.elf_offset + ehsize]))
        if self.e_phnum:
            pieces.append((self.e_phoff,
                           d[self.phdr_offset:self.phdr_offset + self.e_phnum * phent]))
        if self.e_shnum and self.shdr_offset:
            pieces.append((self.e_shoff,
                           d[self.shdr_offset:self.shdr_offset + self.e_shnum * shent]))

        phdrs = self.phdrs()

        if sections is not None:
            for sec in sections:
                if sec["type"] != 2:                 # 2 = described by a phdr
                    continue
                if sec["program_idx"] >= len(phdrs):
                    continue
                blob = d[sec["offset"]:sec["offset"] + sec["size"]]
                if sec["encrypted"]:
                    if sec["key_idx"] >= len(keys) or sec["iv_idx"] >= len(keys):
                        self._note("segment %d: bad key index" % sec["program_idx"])
                        continue
                    blob = _AES.ctr_crypt(keys[sec["key_idx"]], keys[sec["iv_idx"]], blob)
                if sec["compressed"]:
                    try:
                        blob = zlib.decompress(blob)
                    except zlib.error as e:
                        self._note("segment %d: inflate failed (%s)" % (sec["program_idx"], e))
                        continue
                pieces.append((phdrs[sec["program_idx"]]["offset"], blob))
        else:
            for i, si in enumerate(self.seg_infos):
                if i >= len(phdrs) or not si["size"]:
                    continue
                blob = d[si["offset"]:si["offset"] + si["size"]]
                if si["compressed"]:
                    try:
                        blob = zlib.decompress(blob)
                    except zlib.error:
                        continue
                pieces.append((phdrs[i]["offset"], blob))

        size = max(off + len(blob) for off, blob in pieces)
        out = bytearray(size)
        for off, blob in pieces:
            out[off:off + len(blob)] = blob
        return bytes(out)

    def phdrs(self):
        d = self.data
        res = []
        phent = self.e_phentsize or (0x38 if self.is64 else 0x20)
        for i in range(self.e_phnum):
            o = self.phdr_offset + i * phent
            if self.is64:
                p_type, p_flags = struct.unpack_from(">II", d, o)
                p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                    struct.unpack_from(">6Q", d, o + 8)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                    struct.unpack_from(">8I", d, o)
            res.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr, paddr=p_paddr,
                            filesz=p_filesz, memsz=p_memsz, flags=p_flags, align=p_align))
        return res

    def describe(self):
        lines = ["SELF: %s, auth id 0x%016X, vendor id 0x%08X, version %s"
                 % (self.self_type_name, self.auth_id, self.vendor_id, self.version_string)]
        if self.is_debug:
            lines.append("      debug SELF (se_flags 0x%04X)" % self.se_flags)
        else:
            lines.append("      key revision 0x%04X" % self.key_revision)
        if self.keyset:
            lines.append("      key set: %s (%s)" % (self.keyset[1], self.keyset[0]))
        np = self.npdrm_info
        if np:
            lines.append("      NPDRM: license type %d, app type %d, content id %s" % np)
        return lines


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------

def is_self(data):
    return len(data) >= 4 and _u32(data, 0) == SCE_MAGIC


def is_elf(data):
    return len(data) >= 4 and _u32(data, 0) == ELF_MAGIC


def self_to_elf(data, klicensee=None):
    """(elf bytes, SelfFile) for a SELF, or (data, None) for a plain ELF."""
    if is_elf(data):
        return data, None
    sf = SelfFile(data)
    return sf.to_elf(klicensee), sf


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    data = open(argv[1], "rb").read()
    if is_elf(data):
        print("already an ELF")
        return 0
    sf = SelfFile(data)
    elf = sf.to_elf()
    for line in sf.describe():
        print(line)
    for line in sf.log:
        print("      note: %s" % line)
    print("      elf: %d bytes, machine %d, type 0x%04X, %d phdrs, %d shdrs"
          % (len(elf), sf.e_machine, sf.e_type, sf.e_phnum, sf.e_shnum))
    if len(argv) > 2:
        open(argv[2], "wb").write(elf)
        print("wrote %s" % argv[2])
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
