#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MUtool (roothide) 2.2.18 授权码离线生成器 / 验证器模拟
=====================================================
从 MUtoolCapture.dylib (arm64e) 反汇编 1:1 还原，无任何猜测成分：

  生成器  @ 0x96e8  (MUtoolCapture.dylib)
    data = stringWithFormat(@"%@|%@", @"com.muzi.mutool", UDID)
    mac  = CCHmac(kCCHmacAlgSHA256,                      # w0 = 2
                  key   = "MuziSource-Auth-2026-v1-Secret-Key",
                  data  = data.UTF8String)
    hex  = mac[0..31] 逐字节 appendFormat(@"%02X")        # 64 位大写十六进制
    body = hex 前 16 字符按 4 字分组、"-" 连接              # 取前 16 个十六进制字符（分 4 组）
    code = stringWithFormat(@"MUZI-%@-%@", @"MUTOOL", body)

  验证器  @ 0x9414
    norm(s) = s.replace("-", "").uppercaseString          # 大小写/短横线不敏感
    licensed = norm(用户输入的 code).isEqualToString(norm(expected(UDID)))

  UDID 来源 @ 0x9598
    dlopen("/usr/lib/libMobileGestalt.dylib") -> dlsym("MGCopyAnswer")
        -> MGCopyAnswer(@"UniqueDeviceID")
    回退: CFPreferences "com.muzi.mutoolprefs" 键 "MUToolUDID"
    再回退: @""（空串，此时 HMAC data = "com.muzi.mutool|"）

  已知绕过路径（反汇编 @0x7a34 证实）:
    UDID 取不到时，只要 com.muzi.mutoolprefs 的 licenseCode 非空即判定已授权。

用法:
    python keygen_mutool.py <UDID>          # 生成授权码
    python keygen_mutool.py --verify <UDID> <code>
"""
import hashlib
import hmac
import sys

# ---- 从二进制中提取的常量（CFSTR，见 __DATA_CONST,__cfstring） ----
BUNDLE_ID  = "com.muzi.mutool"                    # CFSTR@0x35550
SECRET_KEY = b"MuziSource-Auth-2026-v1-Secret-Key"  # CFSTR@0x35570 (34 bytes)
PREFIX     = "MUZI-MUTOOL-"                       # stringWithFormat:@"MUZI-%@-%@", @"MUTOOL", body


def expected_code(udid: str) -> str:
    """复刻 0x96e8 生成器：UDID -> 授权码"""
    data = f"{BUNDLE_ID}|{udid}".encode("utf-8")
    mac = hmac.new(SECRET_KEY, data, hashlib.sha256).digest()   # CCHmac(SHA256) == HMAC-SHA256
    hex64 = "".join("%02X" % b for b in mac)                     # appendFormat:@"%02X" x32
    body16 = hex64[:16]                                          # substringToIndex:16
    grouped = "-".join(body16[i:i + 4] for i in range(0, 16, 4)) # 4 组 x 4 字符
    return PREFIX + grouped


def normalize(s: str) -> str:
    """复刻 0x9414 验证器的归一化：去短横线 + 大写"""
    return s.replace("-", "").upper()


def verify(udid: str, code: str) -> bool:
    """复刻 0x9414 验证器"""
    return normalize(code) == normalize(expected_code(udid))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    if args[0] == "--verify":
        if len(args) != 3:
            print("用法: python keygen_mutool.py --verify <UDID> <code>")
            return 1
        udid, code = args[1], args[2]
        ok = verify(udid, code)
        exp = expected_code(udid)
        print(f"UDID        : {udid}")
        print(f"待验证授权码: {code}")
        print(f"期望授权码  : {exp}")
        print(f"归一化比对  : {normalize(code)!r} vs {normalize(exp)!r}")
        print("结果        :", "通过 ( licensed )" if ok else "失败")
        return 0 if ok else 2
    if len(args) != 1:
        print("用法: python keygen_mutool.py <UDID>")
        return 1
    udid = args[0]
    code = expected_code(udid)
    print(f"UDID  : {udid}")
    print(f"授权码: {code}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
