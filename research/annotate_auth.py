#!/usr/bin/env python3
"""Build __objc_stubs entry -> selector map, then annotate license functions."""
import struct, re, json
from macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

m = MachO('data/Library/MobileSubstrate/DynamicLibraries/MUtoolCapture.dylib')
slice_off = m.fat_slices[0][2]
d = m.data[slice_off:]
def sect(seg, name):
    return next(s for s in m.sections if s[0]==seg and s[1]==name)
text = sect('__TEXT','__text')
code = d[text[4]:text[4]+text[3]]
cstr = sect('__TEXT','__cstring'); cfs = sect('__DATA_CONST','__cfstring')
meth = sect('__TEXT','__objc_methname')
selrefs = sect('__DATA','__objc_selrefs')
ostubs = sect('__TEXT','__objc_stubs')
stubs = sect('__TEXT','__stubs')

def cstr_at(vm, sec):
    off = sec[4] + (vm - sec[2]); e = d.index(b'\0', off)
    return d[off:e].decode('utf-8','replace')

# selref table -> selector name
selref_map = {}
for i in range(selrefs[3]//8):
    addr = selrefs[2] + i*8
    p = struct.unpack_from('<Q', d, selrefs[4]+i*8)[0] & ((1<<48)-1)
    selref_map[addr] = cstr_at(p, meth)

# import stubs (C functions) from earlier resolution
stub2name = {int(k,16): v for k,v in json.load(open('stubmap.json')).items()}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
adrp_re = re.compile(r'^x(\d+), #0x([0-9a-f]+)$')

# objc_stubs: entries are 32 bytes: adrp x1,page; ldr x1,[x1,#off]; adrp x16; ldr x16; br x16; padding
ostub2sel = {}
oc = d[ostubs[4]:ostubs[4]+ostubs[3]]
for i in range(0, len(oc), 32):
    addr = ostubs[2] + i
    insns = list(md.disasm(oc[i:i+32], addr))
    if len(insns) >= 2:
        mm = adrp_re.match(insns[0].op_str)
        if mm and insns[0].op_str.startswith('x1,') and insns[1].mnemonic == 'ldr' and insns[1].operands[1].type == 3:
            t = int(mm.group(2),16) + insns[1].operands[1].mem.disp
            if t in selref_map:
                ostub2sel[addr] = selref_map[t]
print("objc_stubs entries:", len(ostub2sel))
json.dump({hex(k): v for k,v in ostub2sel.items()}, open('ostubmap.json','w'))
for a in (0x25160, 0x21760, 0x21f40, 0x21f60, 0x251a0, 0x251c0, 0x25000, 0x25140, 0x23480, 0x24e80, 0x255a0):
    print(f"  {a:#x}: {ostub2sel.get(a, stub2name.get(a, '?'))}")

# cfstring annotation
addr2name = {}
for i in range(cfs[3] // 32):
    addr = cfs[2] + i*32
    isa, info, data_ptr, length = struct.unpack_from('<QQQQ', d, cfs[4]+i*32)
    dp = data_ptr & ((1<<48)-1)
    if cstr[2] <= dp < cstr[2] + cstr[3]:
        addr2name[addr] = cstr_at(dp, cstr)

adrp_g = re.compile(r'^x(\d+), #0x([0-9a-f]+)$')
def dump(start, end, label):
    print(f"\n{'='*74}\n{label}: {start:#x} - {end:#x}\n{'='*74}")
    fn = code[start - text[2]: end - text[2]]
    for insn in md.disasm(fn, start):
        note = ''
        mm = adrp_g.match(insn.op_str)
        if mm:
            page = int(mm.group(2), 16); reg = int(mm.group(1))
            for j in range(1, 3):
                nxt = fn[insn.address - start + 4*j: insn.address - start + 4*j + 4]
                for i2 in md.disasm(nxt, insn.address + 4*j):
                    if i2.mnemonic in ('add','ldr') and len(i2.operands) >= 2 and i2.operands[1].type == 1 and i2.operands[1].reg == reg:
                        if i2.mnemonic == 'add' and i2.operands[2].type == 2: val = page + i2.operands[2].imm
                        elif i2.mnemonic == 'ldr' and i2.operands[1].type == 3: val = page + i2.operands[1].mem.disp
                        else: break
                        if val in addr2name: note = f'  ; CFSTR {addr2name[val]!r}'
                        elif cstr[2] <= val < cstr[2]+cstr[3]: note = f'  ; CSTR {cstr_at(val, cstr)!r}'
                        break
                    break
        if insn.mnemonic in ('bl','b') and insn.operands and insn.operands[0].type == 2:
            t = insn.operands[0].imm
            if t in ostub2sel: note += f'  ; [{ostub2sel[t]}]'
            elif t in stub2name: note += f'  ; {stub2name[t]}'
        print(f"{insn.address:#08x}: {insn.mnemonic:<9} {insn.op_str:<40}{note}")

dump(0x96e8, 0x98e8, 'LICENSE GENERATOR')
