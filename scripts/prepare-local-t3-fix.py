"""Prepare a reversible, version-pinned copy of the installed macOS T3 app."""

import argparse
import ctypes
import hashlib
import json
import os
import plistlib
import struct
import subprocess
from pathlib import Path

ASSET = "apps/server/dist/client/assets/ChatMarkdown-CBT2vtCS.js"
EXPECTED = "f51f7c3589262f10f200135a7878690dfaea04d62b0e0beec0310f9a210f985d"
OLD = 'function rO(e){return Array.from(e,(e,t)=>(0,H.jsxs)(B.Fragment,{children:[e,(0,H.jsx)(`wbr`,{})]},`${t}:${e}`))}'
NEW = 'function rO(e){return Array.from(e.matchAll(/\\s+|\\S+/g),({0:e,index:t})=>e.length<=16?e:(0,H.jsx)("span",{style:{overflowWrap:"anywhere"},children:e},t))}'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source, output):
    if output.exists() or source.resolve() == output.resolve():
        raise ValueError("Output must be a new path, separate from the installed app")
    plist_path = source / "Contents/Info.plist"
    plist = plistlib.loads(plist_path.read_bytes())
    if plist["CFBundleShortVersionString"] != "0.1.3":
        raise ValueError("This patch is qualified only for T3 Code 0.1.3")
    archive = source / "Contents/Resources/app.asar"
    original = archive.read_bytes()
    header_size = struct.unpack_from("<I", original, 4)[0]
    json_size = struct.unpack_from("<I", original, 12)[0]
    header_bytes = original[16 : 16 + json_size]
    header = json.loads(header_bytes)
    if sha(header_bytes) != plist["ElectronAsarIntegrity"]["Resources/app.asar"]["hash"]:
        raise ValueError("Installed archive header does not match the app manifest")
    entry = header
    for part in ASSET.split("/"):
        entry = entry["files"][part]
    start = 8 + header_size + int(entry["offset"])
    end = start + entry["size"]
    code = original[start:end]
    if sha(code) != EXPECTED or code.count(OLD.encode()) != 1:
        raise ValueError("Installed renderer differs from the verified upstream asset")
    footer = b"//# sourceMappingURL=ChatMarkdown-CBT2vtCS.js.map"
    if code.count(footer) != 1:
        raise ValueError("Expected source-map footer is missing")
    patched = code.replace(OLD.encode(), NEW.encode()).replace(footer, b"")
    if len(patched) > len(code):
        raise ValueError("Patch cannot preserve archive offsets")
    patched += b" " * (len(code) - len(patched))
    integrity = entry["integrity"]
    integrity["hash"] = sha(patched)
    block_size = integrity["blockSize"]
    integrity["blocks"] = [
        sha(patched[i : i + block_size]) for i in range(0, len(patched), block_size)
    ]
    new_header = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode()
    if len(new_header) != len(header_bytes):
        raise ValueError("Archive metadata changed size")
    result = bytearray(original)
    result[16 : 16 + json_size] = new_header
    result[start:end] = patched
    if result[16 + json_size : start] != original[16 + json_size : start] or result[end:] != original[end:]:
        raise ValueError("An unrelated archive payload changed")
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["/usr/bin/ditto", str(source), str(output)], check=True)
    (output / "Contents/Resources/app.asar").write_bytes(result)
    plist["ElectronAsarIntegrity"]["Resources/app.asar"]["hash"] = sha(new_header)
    (output / "Contents/Info.plist").write_bytes(plistlib.dumps(plist, sort_keys=False))
    entitlements = subprocess.run(
        ["/usr/bin/codesign", "-d", "--entitlements", ":-", str(source)],
        capture_output=True, check=True,
    ).stdout
    entitlements = plistlib.loads(entitlements[entitlements.index(b"<?xml") :])
    # Apple team, associated-domain and keychain-group grants cannot transfer to a local signature.
    entitlements = {k: v for k, v in entitlements.items() if k.startswith("com.apple.security.")}
    signing_file = output.parent / "local-entitlements.plist"
    signing_file.write_bytes(plistlib.dumps(entitlements))
    subprocess.run(
        ["/usr/bin/codesign", "--force", "--deep", "--sign", "-", "--options", "runtime",
         "--entitlements", str(signing_file), str(output)], check=True,
    )
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(output)], check=True)
    report = {
        "source": str(source), "prepared": str(output), "version": "0.1.3",
        "changedAsset": ASSET, "originalAssetSha256": EXPECTED,
        "patchedAssetSha256": sha(patched), "archiveHeaderSha256": sha(new_header),
        "originalArchiveSha256": sha(original), "patchedArchiveSha256": sha(result),
        "unchangedPayloadOutsideAsset": True, "signature": "local ad-hoc; not Apple notarized",
        "installed": False,
    }
    (output.parent / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def activate(source, prepared):
    executable_directory = str(source / "Contents/MacOS") + "/"
    processes = subprocess.check_output(["/bin/ps", "-axo", "command="], text=True)
    if any(executable_directory in command for command in processes.splitlines()):
        raise ValueError("Quit T3 Code before activation; its archive and module caches survive a window reload")
    report_path = prepared.parent / "verification.json"
    report = json.loads(report_path.read_text())
    relative = "Contents/Resources/app.asar"
    if sha((source / relative).read_bytes()) != report["originalArchiveSha256"]:
        raise ValueError("Installed app changed after preparation")
    if sha((prepared / relative).read_bytes()) != report["patchedArchiveSha256"]:
        raise ValueError("Prepared app changed after verification")
    backup = prepared.parent.parent / "backups" / source.name
    if backup.exists():
        raise ValueError("Backup already exists; refusing to overwrite it")
    backup.parent.mkdir(parents=True, exist_ok=True)
    for app in (source, prepared):
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    if source.stat().st_dev != prepared.stat().st_dev:
        raise ValueError("Atomic exchange requires the same filesystem")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    exchange = libc.renamex_np
    exchange.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    exchange.restype = ctypes.c_int
    # RENAME_SWAP changes the app atomically and keeps the original available for rollback.
    if exchange(os.fsencode(source), os.fsencode(prepared), 2) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    prepared.rename(backup)
    report.update(installed=True, backup=str(backup), activation="atomic directory exchange")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--activate", action="store_true")
    args = parser.parse_args()
    prepare(args.source, args.output)
    if args.activate:
        activate(args.source, args.output)
