#!/usr/bin/env python3
"""npm ci for DVAA. Allows TCP only to registry.npmjs.org. Does not edit source."""

import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

LAB = Path("/Users/klambros/github_projects/vulnerable_agents/damn-vulnerable-ai-agent")
WORK = Path("/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/work")
LOG = WORK / "dvaa-npm-ci.log"
NET = WORK / "dvaa-npm-ci-net.txt"
META = WORK / "dvaa-npm-ci-meta.txt"
REGISTRY = "registry.npmjs.org"


def tree_pids(root: int) -> list[str]:
    seen = []
    stack = [root]
    while stack:
        pid = stack.pop()
        seen.append(str(pid))
        out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True, check=False)
        for line in out.stdout.splitlines():
            if line.strip().isdigit():
                stack.append(int(line.strip()))
    return seen


def registry_ips() -> set[str]:
    ips = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(REGISTRY, 443, family, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for info in infos:
            ips.add(info[4][0])
    return ips


def remote_host(addr: str) -> str:
    if addr.startswith("["):
        end = addr.find("]")
        return addr[1:end] if end != -1 else addr
    if addr.count(":") == 1:
        return addr.rsplit(":", 1)[0]
    return addr


def offending(text: str, allowed: set[str]) -> list[str]:
    bad = []
    for line in text.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        arrow = re.search(r"->(\S+)", line)
        if not arrow:
            continue
        remote = arrow.group(1).split("(", 1)[0].strip()
        host = remote_host(remote)
        if host in allowed or host.startswith("127.") or host in {"::1", "localhost"}:
            continue
        # Name resolution for registry.npmjs.org. Not a package host.
        if remote.endswith(":53") or ":53 " in line:
            continue
        bad.append(line)
    return bad


def main() -> int:
    env = os.environ.copy()
    env.pop("GITHUB_PERSONAL_ACCESS_TOKEN", None)
    env["OPENA2A_TELEMETRY"] = "off"
    env["NO_UPDATE_NOTIFIER"] = "1"
    env["npm_config_update_notifier"] = "false"
    env["npm_config_fund"] = "false"
    env["npm_config_audit"] = "false"
    env["ONNXRUNTIME_NODE_INSTALL"] = "skip"

    allowed = registry_ips()
    killed = []
    chunks = []
    with LOG.open("w") as logf:
        start = time.time()
        proc = subprocess.Popen(
            ["npm", "ci"],
            cwd=LAB,
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # ONNXRUNTIME_NODE_INSTALL=skip makes the only install script exit before nuget.
        while proc.poll() is None:
            allowed |= registry_ips()
            pids = tree_pids(proc.pid)
            lsof = subprocess.run(
                ["lsof", "-nP", "-i", "-a", "-p", ",".join(pids)],
                capture_output=True,
                text=True,
                check=False,
            )
            text = lsof.stdout or ""
            if text.strip():
                chunks.append(f"--- t={time.time() - start:.3f} ---\n{text}")
            bad = offending(text, allowed)
            if bad:
                killed.extend(bad)
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                time.sleep(0.4)
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                break
            time.sleep(0.15)
        code = proc.wait()
        end = time.time()

    NET.write_text("".join(chunks) if chunks else "(no TCP/UDP sockets)\n")
    META.write_text(
        "\n".join(
            [
                f"exit_code={code}",
                f"wall_s={end - start:.3f}",
                f"killed={'yes' if killed else 'no'}",
                f"allowed_ips={','.join(sorted(allowed))}",
                "command=npm ci",
                "onnxruntime_postinstall=ONNXRUNTIME_NODE_INSTALL=skip so the script exits before nuget",
            ]
            + (["killed_lines:"] + killed if killed else [])
        )
        + "\n"
    )
    print(f"exit_code={code}")
    print(f"wall_s={end - start:.3f}")
    print(f"killed={'yes' if killed else 'no'}")
    print(f"log_bytes={LOG.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
