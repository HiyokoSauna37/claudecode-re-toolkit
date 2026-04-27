#!/usr/bin/env python3
"""
AdaptixC2 beacon embedded profile extractor.

Run inside ghidra-headless container against a decrypted agent.x64.exe.
Reads .rdata, finds embedded profile blob (size from getProfileSize() return),
decrypts it via RC4 (key is appended at end), then unpacks the structure.

Layout matches AdaptixC2 source: AdaptixServer/extenders/beacon_agent/src_beacon/beacon/
  - AgentConfig.cpp (unpack order)
  - Packer.cpp      (big-endian uint32/uint8)
  - Crypt.cpp       (RC4)

Usage:
    python3 adaptix_profile_extract.py <decrypted.exe> [--profile-rva 0x1a000] [--profile-size 0x115]
"""
import argparse
import json
import struct
import sys


def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


class Packer:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def u8(self) -> int:
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def u32(self) -> int:
        v = struct.unpack("<I", self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def bytes_lp(self) -> bytes:
        n = self.u32()
        v = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        return v

    def cstr(self) -> str:
        b = self.bytes_lp()
        return b.rstrip(b"\x00").decode("utf-8", errors="replace")


def parse_pe_section(data: bytes, want: bytes):
    if data[:2] != b"MZ":
        sys.exit("not a PE")
    pe_off = struct.unpack("<I", data[0x3c:0x40])[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        sys.exit("PE signature missing")
    coff = pe_off + 4
    nsections = struct.unpack("<H", data[coff + 2:coff + 4])[0]
    opt_size = struct.unpack("<H", data[coff + 16:coff + 18])[0]
    sec_off = coff + 20 + opt_size
    img_base_off = pe_off + 4 + 20 + 24
    image_base = struct.unpack("<Q", data[img_base_off:img_base_off + 8])[0]
    for i in range(nsections):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\x00")
        if name != want:
            continue
        vsize = struct.unpack("<I", data[s + 8:s + 12])[0]
        vaddr = struct.unpack("<I", data[s + 12:s + 16])[0]
        rsize = struct.unpack("<I", data[s + 16:s + 20])[0]
        raw = struct.unpack("<I", data[s + 20:s + 24])[0]
        return {
            "name": name.decode(),
            "vaddr": vaddr,
            "vsize": vsize,
            "raw": raw,
            "rsize": rsize,
            "image_base": image_base,
        }
    sys.exit(f"section {want!r} not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--profile-rva", type=lambda x: int(x, 0), default=0x1a000)
    ap.add_argument("--profile-size", type=lambda x: int(x, 0), default=0x115)
    ap.add_argument("--key-size", type=int, default=16)
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        pe = f.read()

    rdata = parse_pe_section(pe, b".rdata")
    image_base = rdata["image_base"]
    file_off = rdata["raw"] + (args.profile_rva - rdata["vaddr"])
    blob = pe[file_off:file_off + args.profile_size]
    if len(blob) != args.profile_size:
        sys.exit(f"failed to read profile blob: got {len(blob)} bytes")

    declared = struct.unpack("<I", blob[:4])[0]
    encrypted_end = 4 + declared
    expected_total = encrypted_end + args.key_size
    consistent = expected_total == args.profile_size

    encrypted = blob[4:encrypted_end]
    key = blob[encrypted_end:encrypted_end + args.key_size]
    if len(key) == 0 or not consistent:
        sys.exit(f"layout mismatch (declared={declared}, blob_len={len(blob)})")

    decrypted = rc4(key, encrypted)

    p = Packer(decrypted)
    cfg = {}
    cfg["agent_type"] = p.u32()
    cfg["kill_date"] = p.u32()
    cfg["working_time"] = p.u32()
    cfg["sleep_delay"] = p.u32()
    cfg["jitter_delay"] = p.u32()

    cfg["listener_type"] = p.u32()
    cfg["use_ssl"] = p.u8()

    sc = p.u32()
    servers = []
    for _ in range(sc):
        host = p.cstr()
        port = p.u32() & 0xFFFF
        servers.append({"host": host, "port": port})
    cfg["servers"] = servers

    cfg["http_method"] = p.cstr()
    uc = p.u32()
    cfg["uris"] = [p.cstr() for _ in range(uc)]
    cfg["parameter"] = p.cstr()
    uac = p.u32()
    cfg["user_agents"] = [p.cstr() for _ in range(uac)]
    cfg["http_headers"] = p.cstr()
    cfg["ans_pre_size"] = p.u32()
    cfg["ans_size"] = p.u32() + cfg["ans_pre_size"]
    hhc = p.u32()
    cfg["host_headers"] = [p.cstr() for _ in range(hhc)]
    cfg["rotation_mode"] = p.u32() & 0xFF
    cfg["proxy_type"] = p.u32() & 0xFF
    cfg["proxy_host"] = p.cstr()
    cfg["proxy_port"] = p.u32() & 0xFFFF
    cfg["proxy_username"] = p.cstr()
    cfg["proxy_password"] = p.cstr()
    cfg["_remaining_bytes"] = p.remaining()

    out = {
        "image_base": f"0x{image_base:x}",
        "profile_rva": f"0x{args.profile_rva:x}",
        "profile_va": f"0x{image_base + args.profile_rva:x}",
        "profile_size": args.profile_size,
        "declared_encrypted_size": declared,
        "key_size": args.key_size,
        "size_consistent": consistent,
        "rc4_key_hex": key.hex(),
        "config": cfg,
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
