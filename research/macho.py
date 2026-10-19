#!/usr/bin/env python3
"""Minimal Mach-O parser for static analysis of arm64e tweaks."""
import struct, sys, os

MH_MAGIC_64 = 0xfeedfacf
LC_REQ_DYLD = 0x80000000
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xc
LC_ID_DYLIB = 0xd
LC_UUID = 0x1b
LC_BUILD_VERSION = 0x32
LC_SOURCE_VERSION = 0x2a
LC_ENCRYPTION_INFO_64 = 0x2c
LC_RPATH = 0x1c | LC_REQ_DYLD
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DYLD_ENVIRONMENT = 0x27
LC_LINKER_OPTION = 0x2d

def u32(b, o): return struct.unpack_from('<I', b, o)[0]

class MachO:
    def __init__(self, path, slice_at=0):
        self.path = path
        self.data = open(path, 'rb').read()
        d = self.data
        self.fat_slices = None
        magic = struct.unpack_from('>I', d, 0)[0]
        if magic == 0xcafebabe:  # fat binary
            nfat = struct.unpack_from('>I', d, 4)[0]
            self.fat_slices = []
            for i in range(nfat):
                o = 8 + i * 20
                cputype, cpusubtype, off, size, align = struct.unpack_from('>iiIII', d, o)
                self.fat_slices.append((cputype, cpusubtype, off, size, align))
            if slice_at is None:
                return
            off = self.fat_slices[slice_at][2]
        else:
            off = 0
        d = d[off:]
        self.slice_off = off
        self.magic = struct.unpack_from('<I', d, 0)[0]
        assert self.magic in (0xfeedface, 0xfeedfacf), "not macho"
        self.is64 = self.magic == MH_MAGIC_64
        hdr = 32 if self.is64 else 28
        self.cputype, self.cpusubtype = struct.unpack_from('<ii', d, 4)
        self.filetype, self.ncmds, self.sizeofcmds = struct.unpack_from('<III', d, 12 if self.is64 else 12)
        off = hdr
        self.lcs = []
        self.segments = []
        self.dylibs = []       # (cmd, name, timestamp, cur, compat)
        self.rpaths = []
        self.uuid = None
        self.minos = None
        self.sdkver = None
        self.enc = None
        self.entryoff = None
        self.func_starts_off = None
        self.linker_opts = []
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            body = d[off:off+cmdsize]
            if cmd == LC_SEGMENT_64:
                segname = body[8:24].rstrip(b'\0').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', body, 24)
                self.segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB):
                name_off = u32(body, 8)
                ts, cur, compat = struct.unpack_from('<III', body, 12)
                name = body[name_off:].split(b'\0')[0].decode()
                self.dylibs.append((cmd, name, ts, cur, compat))
            elif cmd == LC_UUID:
                self.uuid = body[8:24].hex()
            elif cmd == LC_BUILD_VERSION:
                platform, minos, sdk, ntools = struct.unpack_from('<IIII', body, 8)
                self.minos = minos
                self.sdkver = sdk
            elif cmd == (0x1c | LC_REQ_DYLD):
                o = u32(body, 8)
                self.rpaths.append(body[o:].split(b'\0')[0].decode())
            elif cmd == LC_ENCRYPTION_INFO_64:
                cryptoff, cryptsize, cryptid, pad = struct.unpack_from('<IIII', body, 8)
                self.enc = (cryptoff, cryptsize, cryptid)
            elif cmd == LC_MAIN:
                entryoff, stacksize = struct.unpack_from('<QQ', body, 8)
                self.entryoff = entryoff
            elif cmd == LC_FUNCTION_STARTS:
                self.func_starts_off = u32(body, 8)
            elif cmd == LC_LINKER_OPTION:
                o = u32(body, 8)
                self.linker_opts.append(body[o:].split(b'\0')[0].decode())
            self.lcs.append((cmd, cmdsize))
            off += cmdsize
        # parse sections within segments
        self.sections = []
        for segname, vmaddr, vmsize, fileoff, filesize in self.segments:
            # find the segment command again to walk nsects
            pass
        # re-walk to find section headers
        off = 32 if self.is64 else 28
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            if cmd == LC_SEGMENT_64:
                segname = d[off+8:off+24].rstrip(b'\0').decode()
                nsects = u32(d, off+64)
                so = off + 72
                for i in range(nsects):
                    sect = d[so:so+80]
                    sname = sect[0:16].rstrip(b'\0').decode()
                    sseg = sect[16:32].rstrip(b'\0').decode()
                    addr, size = struct.unpack_from('<QQ', sect, 32)
                    soffset = u32(sect, 40+16) if False else struct.unpack_from('<I', sect, 48)[0]
                    self.sections.append((sseg, sname, addr, size, soffset))
                    so += 80
            off += cmdsize

    def section_data(self, seg, sect):
        for sseg, sname, addr, size, soffset in self.sections:
            if sseg == seg and sname == sect:
                return self.data[self.slice_off+soffset:self.slice_off+soffset+size]
        return None

    def symbols(self):
        """Parse LC_SYMTAB: return (defined, undefined) symbol name lists."""
        import struct as st
        d = self.data[self.slice_off:]
        symoff, nsyms, stroff, strsize = None, None, None, None
        dysymoff, ndysym = None, None
        off = 32 if self.is64 else 28
        for _ in range(self.ncmds):
            cmd, cmdsize = st.unpack_from('<II', d, off)
            if cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = st.unpack_from('<IIII', d, off+8)
            elif cmd == 0xb:  # LC_DYSYMTAB
                dysymoff = st.unpack_from('<I', d, off+32+64)[0] if False else None
            off += cmdsize
        if symoff is None: return [], []
        def cstr(o):
            e = d.index(b'\0', stroff+o)
            return d[stroff+o:e].decode('utf-8', 'replace')
        defined, undefined = [], []
        for i in range(nsyms):
            so = symoff + i * 16  # nlist_64
            n_strx, n_type, n_sect, n_desc, n_value = st.unpack_from('<IBBHQ', d, so)
            name = cstr(n_strx)
            if n_type & 0x0e == 0x0:  # N_UNDF
                undefined.append(name)
            else:
                defined.append(name)
        return defined, undefined

    def codesig(self):
        """Extract code signature super blob info: find LC_CODE_SIGNANCE, parse CMS + entitlements."""
        import struct as st
        d = self.data[self.slice_off:]
        off = 32 if self.is64 else 28
        for _ in range(self.ncmds):
            cmd, cmdsize = st.unpack_from('<II', d, off)
            if cmd == 0x1d:  # LC_CODE_SIGNATURE
                sigoff = st.unpack_from('<I', d, off+8)[0]
                return d[sigoff:]
            off += cmdsize
        return None

    def strings_from(self, seg, sect):
        blob = self.section_data(seg, sect)
        if blob is None: return []
        out = []
        cur = b''
        for b in blob:
            if 32 <= b < 127:
                cur += bytes([b])
            else:
                if len(cur) >= 3: out.append(cur.decode())
                cur = b''
        if len(cur) >= 3: out.append(cur.decode())
        return out

    def ver(self, v):
        return f"{v>>16 & 0xffff}.{v>>8 & 0xff}.{v & 0xff}"

    def summary(self):
        lines = []
        cpus = {0x0100000c: 'arm64e', 0x0100000b: 'arm64', 0x0200000c: 'arm64e(sim)', 0x7: 'i386', 0x01000007: 'x86_64'}
        if self.fat_slices:
            lines.append(f"file: {os.path.basename(self.path)}  size={len(self.data)}  FAT with {len(self.fat_slices)} slices")
            for cputype, cpusubtype, off, size, align in self.fat_slices:
                lines.append(f"  fat slice: {cpus.get(cputype, hex(cputype))} off={off:#x} size={size}")
        lines.append(f"file: {os.path.basename(self.path)}  size={len(self.data)}")
        lines.append(f"arch: {cpus.get(self.cputype, hex(self.cputype))} (cpusubtype={self.cpusubtype:#x}) 64bit={self.is64}")
        ftypes = {2:'MH_EXECUTE', 6:'MH_DYLIB', 8:'MH_BUNDLE'}
        lines.append(f"filetype: {ftypes.get(self.filetype, self.filetype)}")
        if self.minos: lines.append(f"minOS: {self.ver(self.minos)}  SDK: {self.ver(self.sdkver)}")
        if self.uuid: lines.append(f"uuid: {self.uuid}")
        if self.enc: lines.append(f"encryption: cryptid={self.enc[2]} cryptoff={self.enc[0]} cryptsize={self.enc[1]}")
        if self.entryoff is not None: lines.append(f"entryoff: {self.entryoff:#x}")
        if self.func_starts_off: lines.append(f"function_starts: present (offset {self.func_starts_off:#x})")
        if self.linker_opts: lines.append(f"linker options: {self.linker_opts}")
        lines.append("segments:")
        for s in self.segments:
            lines.append(f"  {s[0]:<16} vm={s[1]:#x} vmsize={s[2]:#x} fileoff={s[3]:#x} filesize={s[4]:#x}")
        lines.append(f"rpaths: {self.rpaths}")
        lines.append("dylibs:")
        for cmd, name, ts, cur, compat in self.dylibs:
            tag = 'ID' if cmd == LC_ID_DYLIB else '  '
            lines.append(f"  [{tag}] {name}")
        return "\n".join(lines)

if __name__ == '__main__':
    for p in sys.argv[1:]:
        m = MachO(p)
        print(m.summary())
        print()
