"""Install one reusable WSL network laboratory through Microsoft's installer.

Run from the ReverseResearch root. Each mutation has one exclusive receipt;
an uncertain operation is inspected, never silently repeated. No host restart.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import winreg

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "runtime/network-lab/debian"
EVIDENCE = ROOT / "evidence/network-lab"
DISTRO = "Debian"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(raw):
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if b"\0" in raw[:200]:
        return raw.decode("utf-16le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def persist(path, record):
    pending = path.with_suffix(".pending.json")
    pending.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pending.replace(path)


def owned_distro():
    parent = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent) as key:
        for index in range(winreg.QueryInfoKey(key)[0]):
            with winreg.OpenKey(key, winreg.EnumKey(key, index)) as entry:
                if winreg.QueryValueEx(entry, "DistributionName")[0] != DISTRO:
                    continue
                base = winreg.QueryValueEx(entry, "BasePath")[0]
                version = winreg.QueryValueEx(entry, "Version")[0]
                base = base.removeprefix("\\\\?\\")
                if Path(base).resolve() != RUNTIME.resolve() or version != 2:
                    raise RuntimeError("DISTRO_PATH_OR_VERSION_NOT_OWNED")
                return {"basePath": base, "version": version}
    raise RuntimeError("OWNED_DISTRO_NOT_REGISTERED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("admit", "status", "core", "distro", "packages"), required=True)
    parser.add_argument("--operation", required=True)
    args = parser.parse_args()
    if os.name != "nt" or Path.cwd().resolve() != ROOT:
        raise RuntimeError("EXPLICIT_WINDOWS_REVERSE_RESEARCH_ROOT_REQUIRED")
    if not re.fullmatch(r"[a-z0-9-]{1,80}", args.operation):
        raise RuntimeError("INVALID_OPERATION")
    if args.action == "admit":
        print(json.dumps(owned_distro(), ensure_ascii=False))
        return 0
    wsl = shutil.which("wsl.exe")
    if not wsl:
        raise RuntimeError("WINDOWS_WSL_ENTRY_UNAVAILABLE")
    commands = {
        "status": [wsl, "--list", "--verbose"],
        "core": [wsl, "--install", "--no-distribution", "--web-download"],
        "distro": [wsl, "--install", "--distribution", DISTRO, "--web-download",
                   "--location", str(RUNTIME), "--no-launch"],
        "packages": [wsl, "--distribution", DISTRO, "--user", "root", "--exec", "sh", "-ec",
                     "export DEBIAN_FRONTEND=noninteractive; apt-get update; "
                     "apt-get install -y --no-install-recommends python3 iproute2 nftables conntrack iputils-ping; "
                     "apt-get clean"],
    }
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    receipt = EVIDENCE / (args.operation + ".json")
    if receipt.exists():
        old = json.loads(receipt.read_bytes())
        print(json.dumps({"operationId": args.operation, "phase": old["phase"],
                          "receipt": str(receipt), "replayed": False}, ensure_ascii=False))
        return 2
    if args.action == "distro":
        result = subprocess.run([wsl, "--list", "--quiet"], capture_output=True, check=False)
        if result.returncode != 0:
            raise RuntimeError("WSL_CORE_NOT_READY")
        names = [name.strip() for name in decode(result.stdout).splitlines() if name.strip()]
        if DISTRO in names or RUNTIME.exists():
            raise RuntimeError("EXISTING_DISTRO_OR_RUNTIME_MUST_BE_INSPECTED_NOT_REINSTALLED")
        RUNTIME.parent.mkdir(parents=True, exist_ok=True)
    ownership = owned_distro() if args.action == "packages" else None
    source_hash = digest(Path(__file__))
    record = {"schema": "RR_REUSABLE_WSL_NETWORK_LAB_INSTALL_V1", "operationId": args.operation,
              "action": args.action, "phase": "STARTED", "startedUTC": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "source": {"path": str(Path(__file__)), "sha256": source_hash},
              "wslEntry": {"path": wsl, "sha256": digest(Path(wsl))}, "argv": commands[args.action],
              "distro": DISTRO, "runtime": str(RUNTIME), "automaticReboot": False,
              "gameCopies": 0, "networkImpairmentApplied": False}
    record["distroOwnership"] = ownership
    persist(receipt, record)
    stdout = EVIDENCE / (args.operation + ".stdout.log")
    stderr = EVIDENCE / (args.operation + ".stderr.log")
    start = time.monotonic()
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(commands[args.action], cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err)
            record["installerPID"] = process.pid
            persist(receipt, record)
            try:
                exit_code = process.wait(timeout=600)
            except subprocess.TimeoutExpired:
                # The original child remains the owner. Never kill/relaunch an
                # installer whose external side effects may already be committed.
                record.update(phase="INSTALL_RESULT_UNKNOWN_INSPECT_ORIGINAL_OPERATION", exitCode=None)
                persist(receipt, record)
                print(json.dumps({"operationId": args.operation, "phase": record["phase"],
                                  "installerPID": process.pid, "receipt": str(receipt)}))
                return 3
        record.update(exitCode=exit_code, elapsedSeconds=round(time.monotonic() - start, 3),
                      sourceAfter=digest(Path(__file__)), phase="COMMAND_COMPLETED_VERIFY_READINESS")
        for name, path in (("stdout", stdout), ("stderr", stderr)):
            raw = path.read_bytes()
            record[name] = {"path": str(path), "sha256": digest(path), "bytes": len(raw),
                            "tail": decode(raw)[-2200:]}
        if record["sourceAfter"] != source_hash:
            record["phase"] = "SOURCE_CHANGED_REVIEW_REQUIRED"
        persist(receipt, record)
        print(json.dumps({"operationId": args.operation, "action": args.action, "phase": record["phase"],
                          "exitCode": exit_code, "elapsedSeconds": record["elapsedSeconds"],
                          "stdoutTail": record["stdout"]["tail"][-1400:], "stderrTail": record["stderr"]["tail"][-800:],
                          "receipt": str(receipt)}, ensure_ascii=False))
        return 0 if exit_code == 0 and record["sourceAfter"] == source_hash else 1
    except BaseException as exc:
        record.update(phase="INSTALL_RESULT_UNKNOWN_INSPECT_ORIGINAL_OPERATION", error=type(exc).__name__)
        persist(receipt, record)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
