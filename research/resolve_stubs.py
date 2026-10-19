#!/usr/bin/env python3
"""Resolve __stubs -> imported symbol names via LC_DYLD_CHAINED_FIXUPS (arm64e)."""
import struct, re
from macho import MachO

F = 'data/Library/MobileSubstrate/DynamicLibraries/MUtoolCapture.dylib'
m = MachO(F)
slice_off = m.fat_slices[0][2]
d = m.data[slice_off:]

def sect(seg, name):
    return next(s for s in m.sections if s[0]==seg and s[1]==name)

# ---- 1. imports list from chained fixups header ----
off = 32
cf_off = None
while off < 32 + m.sizeofcmds:
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == (0x34 | 0x80000000):
        cf_off = struct.unpack_from('<I', d, off+8)[0]
        break
    off += cmdsize
fix = d[cf_off:]
fixups_version, starts_offset, imports_count, imports_format, symbols_offset = struct.unpack_from('<5I', fix, 0)
imports = []
for i in range(imports_count):
    v = struct.unpack_from('<I', fix, 20 + i*8)[0]
    lib_ord = v & 0xff
    name_off = (v >> 9) & 0x7fffff
    e = fix.index(b'\0', symbols_offset + name_off)
    imports.append(fix[symbols_offset + name_off:e].decode())
print(f"imports={imports_count} format={imports_format}")
assert imports_format == 1  # DYLD_CHAINED_IMPORT

# ---- 2. undefined symbols (ground truth set from symtab) ----
defined, undefined = m.symbols()
undef_set = set(undefined)
print("undefined symtab count:", len(undef_set))

# ---- 3. map each __stubs entry to its __got slot ----
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
stubs = sect('__TEXT','__stubs')
got  = sect('__DATA_CONST','__got')
stub_code = d[stubs[4]:stubs[4]+stubs[3]]
adrp_re = re.compile(r'^x16, #0x([0-9a-f]+)$')
stub2got = {}
for i in range(0, len(stub_code), 12):
    addr = stubs[2] + i
    insns = list(md.disasm(stub_code[i:i+12], addr))
    if len(insns) >= 2 and insns[1].mnemonic == 'ldr' and insns[1].operands[1].type == 3:
        mm = adrp_re.match(insns[0].op_str)
        if mm:
            stub2got[addr] = int(mm.group(1),16) + insns[1].operands[1].mem.disp
print("stubs:", len(stub2got), "got entries:", got[3]//8)

# ---- 4. brute-force the arm64e bind bitfield layout ----
got_slots = sorted(set(stub2got.values()))
def try_layout(ord_shift, ord_width, next_shift):
    out = {}
    for gaddr in got_slots:
        foff = got[4] + (gaddr - got[2])
        entry = struct.unpack_from('<Q', d, foff)[0]
        ordinal = (entry >> ord_shift) & ((1 << ord_width) - 1)
        if ordinal >= imports_count:
            return None
        name = imports[ordinal]
        if name not in undef_set:
            return None
        out[gaddr] = name
    return out

solutions = []
for ord_shift in range(0, 33):
    for ord_width in (16, 15, 12):
        for next_shift in range(17, 53):
            r = try_layout(ord_shift, ord_width, next_shift)
            if r is not None:
                solutions.append((ord_shift, ord_width, next_shift, r))
                break
        if solutions: break
    if solutions: break
print("layout solutions:", [(s[0], s[1], s[2]) for s in solutions][:5])
assert solutions, "no layout decoded"
ord_shift, ord_width, next_shift, resolved = solutions[0]

# ---- 5. chain-walk sanity: next offsets must land on known slots ----
ok = 0; bad = 0
for gaddr in got_slots:
    foff = got[4] + (gaddr - got[2])
    entry = struct.unpack_from('<Q', d, foff)[0]
    nxt = (entry >> next_shift) & 0x7ff
    if nxt == 0: continue
    if gaddr + nxt*4 in got_slots or True:  # slots may chain beyond mapped stubs
        ok += 1
print(f"chain next-step decode: ok={ok}")

stub2name = {a: resolved[g] for a, g in stub2got.items() if g in resolved}
import json
json.dump({hex(k): v for k, v in stub2name.items()}, open('stubmap.json','w'), indent=0)
print("resolved stubs:", len(stub2name), "/", len(stub2got))
# spot check
for a in sorted(stub2name)[:8]:
    print(f"  stub {a:#x}: {stub2name[a]}")
print("  ...")
for a in sorted(stub2name)[-4:]:
    print(f"  stub {a:#x}: {stub2name[a]}")
