#!/usr/bin/env python3
"""Disassemble license-check functions in MUtoolCapture.dylib."""
import struct, re, bisect, json, sys
from macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

F = 'data/Library/MobileSubstrate/DynamicLibraries/MUtoolCapture.dylib'
m = MachO(F)
slice_off = m.fat_slices[0][2]
d = m.data[slice_off:]

def sect(seg, name):
    return next(s for s in m.sections if s[0]==seg and s[1]==name)

text = sect('__TEXT','__text')
text_addr, text_size, text_foff = text[2], text[3], text[4]
code = d[text_foff:text_foff+text_size]

# function starts
def uleb(buf, pos):
    result = 0; shift = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return result, pos

fs = d[m.func_starts_off:]
funcs = []
pos = 0; addr = text_addr
while pos < len(fs):
    delta, pos = uleb(fs, pos)
    if delta == 0: break
    addr += delta
    funcs.append(addr)

import os
if os.path.exists('stubmap.json'):
    STUBS = {int(k, 16): v for k, v in json.load(open('stubmap.json')).items()}
else:
    STUBS = {}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
adrp_re = re.compile(r'^x(\d+), #0x([0-9a-f]+)$')

# rebuild cfstring map for annotation
cstr = sect('__TEXT','__cstring')
cfs = sect('__DATA_CONST','__cfstring')
def cstr_at(vm):
    off = cstr[4] + (vm - cstr[2])
    e = d.index(b'\0', off)
    return d[off:e].decode('utf-8','replace')
addr2name = {}
for i in range(cfs[3] // 32):
    addr = cfs[2] + i*32
    off = cfs[4] + i*32
    isa, info, data_ptr, length = struct.unpack_from('<QQQQ', d, off)
    dp = data_ptr & ((1<<48)-1)
    if cstr[2] <= dp < cstr[2] + cstr[3]:
        addr2name[addr] = cstr_at(dp)

def func_of(target):
    idx = bisect.bisect_right(funcs, target) - 1
    start = funcs[idx]
    end = funcs[idx+1] if idx+1 < len(funcs) else text_addr + text_size
    return start, end

def disasm(start, end, label):
    print(f"\n{'='*70}\n{label}: {start:#x} - {end:#x}\n{'='*70}")
    fn = code[start - text_addr: end - text_addr]
    for insn in md.disasm(fn, start):
        note = ''
        # string const refs
        mm = adrp_re.match(insn.op_str)
        if mm:
            page = int(mm.group(2), 16)
            for j in range(1, 3):
                nxt = fn[insn.address - start + 4*j: insn.address - start + 4*j + 4]
                for i2 in md.disasm(nxt, insn.address + 4*j):
                    if i2.mnemonic in ('add','ldr') and len(i2.operands) >= 2 and i2.operands[1].type == 1 and i2.operands[1].reg == int(mm.group(1)):
                        if i2.mnemonic == 'add' and i2.operands[2].type == 2:
                            val = page + i2.operands[2].imm
                        elif i2.mnemonic == 'ldr' and i2.operands[1].type == 3:
                            val = page + i2.operands[1].mem.disp
                        else:
                            break
                        if val in addr2name:
                            note = f'  ; CFSTR {addr2name[val]!r}'
                        break
                    break
        # bl targets -> resolve to imported symbol names
        if insn.mnemonic == 'bl' and insn.operands and insn.operands[0].type == 2:
            t = insn.operands[0].imm
            if t in STUBS:
                note += f'  ; -> {STUBS[t]}'
            elif t in set(funcs):
                note += f'  ; func_{t:x}'
            else:
                note += f'  ; sub_{t:x}'
        print(f"{insn.address:#08x}: {insn.mnemonic:<9} {insn.op_str:<40}{note}")

for start, end, label in [(0x9684, 0x9c40, 'LICENSE CODE GENERATOR (UDID -> code)'),
                          (0x7860, 0x7aa0, 'LICENSE VERIFIER (prefs licenseCode check)')]:
    disasm(start, end, label)
