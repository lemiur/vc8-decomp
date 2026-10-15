"""Extract a minimal x86 VC8 RTM toolchain from the user's ISO; never install it.

Uses existing 7-Zip plus read-only Windows Installer database access. Payloads,
MSI and provenance remain in ignored ref-rtm. The SDK libraries are explicitly
borrowed from the installed SP1 SDK; this is not a complete RTM installation.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from probe_toolchain import CONFIG, inventory, sha256

CAB_GROUPS = {
    "194": "bin", "195": "bin", "196": "bin", "2029": "bin", "260": "bin",
    "4071": "bin", "18932": "bin/Microsoft.VC80.CRT",
    "182": "lib", "2025": "lib", "2021": "lib",
    "185": "include", "3356": "include", "225": "include",
    "3370": "include", "184": "include/sys",
}


def run(command, timeout=120):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                            errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout[-1500:] + result.stderr[-1500:])
    return result.stdout


def safe_filename(name):
    name = name.rsplit("|", 1)[-1]
    if not name or name in (".", "..") or re.search(r'[\\/:\x00]', name):
        raise ValueError("unsafe MSI filename: " + repr(name))
    return name


def file_map(msi):
    # Read only: OpenDatabase mode 0. No msiexec, install or administrative install.
    script = r'''
param([string]$Database)
$wi=New-Object -ComObject WindowsInstaller.Installer
$db=$wi.OpenDatabase($Database,0)
$view=$db.OpenView('SELECT `File`,`FileName` FROM `File`')
$view.Execute()
$names=@{}
while($rec=$view.Fetch()) {$names[$rec.StringData(1)]=$rec.StringData(2)}
$names | ConvertTo-Json -Compress
'''
    script_path = msi.parent / "read-file-map.ps1"
    script_path.write_text(script, encoding="utf-8")
    text = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path, msi])
    return json.loads(text)


def extract(iso, output, seven_zip, config):
    iso, output = Path(iso).resolve(), Path(output).resolve()
    if output == iso.parent or output == Path(output.anchor):
        raise ValueError("choose a dedicated ref-rtm output directory")
    output.mkdir(parents=True, exist_ok=True)
    cabs = output / "cabs"
    cabs.mkdir(exist_ok=True)
    listing = run([seven_zip, "l", "-ba", iso])
    members = []
    for key in CAB_GROUPS:
        hits = re.findall(r"vs[\\/]_" + key + r"_[^\r\n]*?\.cab", listing)
        if len(hits) != 1:
            raise ValueError("expected one ISO cabinet for " + key)
        members.append(hits[0])
    run([seven_zip, "e", iso, "-o" + str(cabs), "vs/vs_setup.msi", *members, "-y"])
    msi = cabs / "vs_setup.msi"
    names = file_map(msi)
    payload = []
    for member in members:
        cab = cabs / member.replace("\\", "/").split("/")[-1]
        key = cab.name.split("_", 2)[1]
        stage = output / "stage" / key
        stage.mkdir(parents=True, exist_ok=True)
        run([seven_zip, "e", cab, "-o" + str(stage), "-y"])
        for path in sorted(stage.iterdir()):
            if not path.is_file():
                continue
            if path.name not in names:
                raise ValueError("cabinet file absent from MSI File table: " + path.name)
            filename = safe_filename(names[path.name])
            dest = output / CAB_GROUPS[key]
            if key == "4071" and filename.endswith(".lib"):
                dest = output / "lib"
            elif key == "4071" and filename.endswith(".h"):
                dest = output / "include"
            elif key in ("195", "2029", "4071") and filename.endswith("ui.dll"):
                dest = output / "bin/1033"
            dest.mkdir(parents=True, exist_ok=True)
            target = dest / filename
            shutil.copyfile(path, target)
            payload.append({"cabinet": cab.name, "file_id": path.name,
                            "path": target.as_posix(), "sha256": sha256(target)})
    provenance = {"iso": iso.as_posix(), "iso_sha256": sha256(iso),
                  "msi_sha256": sha256(msi), "cabinet_sha256": {p.name: sha256(p) for p in cabs.glob("*.cab")},
                  "method": "7-Zip extraction; MSI File table read-only; no installation",
                  "files": payload}
    (output / "bootstrap-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    data = json.loads(config.read_text(encoding="utf-8-sig"))
    sdk = "C:/Program Files (x86)/Microsoft Visual Studio 8/VC/PlatformSDK"
    tc = {"kind": "extracted-local-iso", "source_iso": iso.as_posix(), "source_iso_sha256": provenance["iso_sha256"],
          "bin": (output / "bin").as_posix(), "runtime": [(output / "bin/Microsoft.VC80.CRT").as_posix()],
          "include": [(output / "include").as_posix(), sdk + "/include"],
          "lib": [(output / "lib").as_posix(), sdk + "/lib"],
          "limitations": ["PlatformSDK headers and libraries borrowed from installed SP1; not a complete RTM SDK", "SxS runtime binding not traced; private RTM CRT files supplied"]}
    previous = data["toolchains"].get("rtm", {})
    if previous.get("source_iso_sha256") == tc["source_iso_sha256"] and previous.get("bin") == tc["bin"]:
        for field in ("observed_runtime_files", "runtime_observation"):
            if field in previous:
                tc[field] = previous[field]
        if tc.get("runtime_observation"):
            tc["limitations"][-1] = "Previously observed CRT bytes retained; repeat runtime trace after assembly policy changes."
    tc["files"] = inventory(tc)
    data["toolchains"]["rtm"] = tc
    config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("Extracted %d files; pinned %d RTM tools; no installation" % (len(payload), len(tc["files"])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, default=Path("E:/vc8-decomp/en_vs_2005_pro_dvd.iso"))
    parser.add_argument("--out", type=Path, default=Path("E:/vc8-decomp/ref-rtm"))
    parser.add_argument("--seven-zip", type=Path, default=Path("C:/Program Files/7-Zip/7z.exe"))
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    extract(args.iso, args.out, args.seven_zip, args.config)


if __name__ == "__main__":
    main()
