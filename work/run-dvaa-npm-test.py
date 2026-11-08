#!/usr/bin/env python3
"""Re-run DVAA npm test after install. Kill the tree on a non-loopback socket."""

import os
import re
import signal
import subprocess
import time
from pathlib import Path

LAB = Path("/Users/klambros/github_projects/vulnerable_agents/damn-vulnerable-ai-agent")
WORK = Path("/Users/klambros/github_projects/vulnerable_agents/aivss_experiment/work")
TMP = WORK / "dvaa-tmp"
XDG = TMP / "xdg"
LOG = WORK / "dvaa-npm-test.log"
NET = WORK / "dvaa-npm-test-net.txt"
META = WORK / "dvaa-npm-test-meta.txt"
LISTEN_BEFORE = WORK / "dvaa-listen-before.txt"
LISTEN_AFTER = WORK / "dvaa-listen-after.txt"


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


def remote_host(addr: str) -> str:
    if addr.startswith("["):
        end = addr.find("]")
        return addr[1:end] if end != -1 else addr
    if addr.count(":") == 1:
        return addr.rsplit(":", 1)[0]
    return addr


def is_loopback(host: str) -> bool:
    host = host.strip("[]")
    return host in {"127.0.0.1", "::1", "localhost"} or host.startswith("127.")


def offending(text: str) -> list[str]:
    bad = []
    for line in text.splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        arrow = re.search(r"->(\S+)", line)
        if arrow:
            remote = arrow.group(1).split("(", 1)[0].strip()
            if remote.endswith(":53"):
                continue
            if not is_loopback(remote_host(remote)):
                bad.append(line)
            continue
        if "(LISTEN)" in line:
            m = re.search(r"(TCP|UDP)\s+(\S+)\s+\(LISTEN\)", line)
            local = m.group(2) if m else ""
            if local.startswith("*") or local.startswith("0.0.0.0:") or local.startswith("[::]:"):
                bad.append(line)
            elif local and not is_loopback(remote_host(local)):
                bad.append(line)
    return bad


def snapshot(path: Path) -> None:
    proc = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], capture_output=True, text=True, check=False)
    path.write_text(proc.stdout or "")


def main() -> int:
    TMP.mkdir(parents=True, exist_ok=True)
    XDG.mkdir(parents=True, exist_ok=True)
    snapshot(LISTEN_BEFORE)
    env = os.environ.copy()
    env.pop("GITHUB_PERSONAL_ACCESS_TOKEN", None)
    env["OPENA2A_TELEMETRY"] = "off"
    env["TMPDIR"] = str(TMP)
    env["XDG_CONFIG_HOME"] = str(XDG)
    env["NO_UPDATE_NOTIFIER"] = "1"
    env["npm_config_update_notifier"] = "false"
    env["npm_config_fund"] = "false"
    env["npm_config_audit"] = "false"

    killed = []
    chunks = []
    with LOG.open("w") as logf:
        start = time.time()
        proc = subprocess.Popen(
            ["npm", "test"],
            cwd=LAB,
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        while proc.poll() is None:
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
            bad = offending(text)
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
            time.sleep(0.2)
        code = proc.wait()
        end = time.time()

    NET.write_text("".join(chunks) if chunks else "(no TCP/UDP sockets)\n")
    snapshot(LISTEN_AFTER)
    META.write_text(
        "\n".join(
            [
                f"exit_code={code}",
                f"wall_s={end - start:.3f}",
                f"killed={'yes' if killed else 'no'}",
                f"log_bytes={LOG.stat().st_size}",
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
