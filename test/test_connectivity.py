"""Connectivity smoke tests for test/config.ini.

Run this FIRST when wiring up a new lab. It isolates "my config.ini is wrong"
from "the filter test failed" by checking each leg of the harness on its own,
with a diagnostic message pointing at the specific config.ini key to fix:
  - SSH to the Linux server, and that test_dir / the UDC actually exist there,
  - WinRM to the Windows client, and that helpers.ps1 / usbip.exe are there,
  - that the Windows client can reach the USB/IP server's TCP port.

Skipped (like every other integration test) unless test/config.ini exists.
Run: pytest test/test_connectivity.py -v
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

DEFAULT_USBIP_PORT = 3240

# The directory whose contents must match what's deployed to the server's
# [linux] test_dir. This is the checkout the harness runs from.
_LOCAL_LINUX_DIR = Path(__file__).parent / "linux"

# A self-contained digest of a directory tree: for every file (sorted, skipping
# __pycache__/*.pyc) it folds in the relative path and a sha256 of the contents.
# Run identically on both ends -- in-process here and over SSH on the server --
# so the algorithm can never drift between them.
_DIGEST_PY = r'''
import hashlib, os, sys
root = sys.argv[1]
h = hashlib.sha256()
for dp, dns, fns in os.walk(root):
    dns[:] = [d for d in sorted(dns) if d != "__pycache__"]
    for fn in sorted(fns):
        if fn.endswith(".pyc"):
            continue
        p = os.path.join(dp, fn)
        rel = os.path.relpath(p, root)
        h.update(rel.encode()); h.update(b"\0")
        with open(p, "rb") as f:
            h.update(hashlib.sha256(f.read()).digest())
print(h.hexdigest())
'''


def test_config_sections_present(config):
    required = {
        "linux": ("host", "user", "test_dir"),
        "windows": ("host", "user", "password", "helpers"),
        "server": ("address",),
    }
    for section, keys in required.items():
        assert config.has_section(section), f"config.ini is missing [{section}]"
        for key in keys:
            assert config.has_option(section, key) and config[section][key], (
                f"config.ini [{section}] is missing a value for '{key}'")


@pytest.fixture()
def ssh(config):
    import paramiko

    s = config["linux"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {"username": s["user"]}
    if s.get("password"):
        kwargs["password"] = s["password"]
    if s.get("key_filename"):
        kwargs["key_filename"] = os.path.expanduser(s["key_filename"])
    try:
        client.connect(s["host"], timeout=10, **kwargs)
    except Exception as e:
        pytest.fail(f"SSH to [linux] host={s['host']!r} user={s['user']!r} failed: {e}")
    yield client
    client.close()


def _ssh_run(client, cmd: str) -> tuple[int, str, str]:
    _in, out, err = client.exec_command(cmd, timeout=10)
    rc = out.channel.recv_exit_status()
    return rc, out.read().decode(), err.read().decode()


def test_linux_ssh_connects(ssh):
    rc, out, err = _ssh_run(ssh, "echo connectivity-ok")
    assert rc == 0 and "connectivity-ok" in out, f"unexpected SSH output: {out!r} {err!r}"


def test_linux_test_dir_present(config, ssh):
    test_dir = config["linux"]["test_dir"]
    rc, out, _err = _ssh_run(ssh, f"test -f {test_dir}/gadget_lib.sh && echo found")
    assert rc == 0 and "found" in out, (
        f"[linux] test_dir={test_dir!r} does not contain gadget_lib.sh -- "
        f"did you copy test/linux/ to the server at this path?")


def test_linux_udc_available(config, ssh):
    udc = config["linux"].get("udc_name", "usbip-vudc.0")
    rc, out, _err = _ssh_run(ssh, f"test -e /sys/class/udc/{udc} && echo found")
    assert rc == 0 and "found" in out, (
        f"[linux] udc_name={udc!r} not found under /sys/class/udc -- "
        f"is the gadget UDC module (usbip-vudc / dummy_hcd) loaded?")


def test_linux_usbipd_listening(config, ssh):
    port = config.getint("server", "port", fallback=DEFAULT_USBIP_PORT)
    # Check for a LISTEN socket on the port via ss (with a netstat fallback);
    # both report listening sockets portably, unlike bash's /dev/tcp which only
    # works when the SSH login shell happens to be bash.
    rc, out, _err = _ssh_run(
        ssh,
        f"(ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':{port} ' "
        f"&& echo found")
    assert rc == 0 and "found" in out, (
        f"no process is listening on TCP {port} on the [linux] host -- "
        f"is usbipd running?")


def test_linux_usbipd_device_mode(config, ssh):
    # vudc gadgets are only offered by a usbipd running in *device* mode
    # (usbipd --device); a host-mode daemon will silently not offer them. This
    # is a no-op assertion for a dummy_hcd / real-hardware busid (host mode).
    udc = config["linux"].get("udc_name", "usbip-vudc.0")
    if "vudc" not in udc:
        pytest.skip(f"udc_name={udc!r} is not a vudc; device-mode check N/A")
    rc, out, _err = _ssh_run(
        ssh,
        "pgrep -af usbipd | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)' "
        "&& echo found")
    assert rc == 0 and "found" in out, (
        f"no usbipd in device mode found for vudc udc_name={udc!r} -- vudc gadgets "
        f"are only offered by 'usbipd --device'. The harness starts it on demand, "
        f"but you can start it manually on the [linux] host with: usbipd --device -D")


def test_linux_deploy_in_sync(config, ssh):
    # Guard against the "fixed in git but stale on the server" trap: the harness
    # runs gadget scripts and payloads from the server's test_dir, not from this
    # checkout, so a forgotten re-deploy means you debug code that isn't running.
    # Compare a digest of this checkout's test/linux/ against the server copy and
    # fail with a re-sync hint if they differ. (This asserts the server matches
    # THIS checkout; run `git pull` here first so "this checkout" is current.)
    test_dir = config["linux"]["test_dir"]

    local = subprocess.run(
        [sys.executable, "-c", _DIGEST_PY, str(_LOCAL_LINUX_DIR)],
        capture_output=True, text=True)
    assert local.returncode == 0, f"local digest failed: {local.stderr}"
    local_digest = local.stdout.strip()

    rc, out, err = _ssh_run(
        ssh, f"python3 -c {shlex.quote(_DIGEST_PY)} {shlex.quote(test_dir)}")
    assert rc == 0, (
        f"could not digest server test_dir={test_dir!r} (rc={rc}): {out}{err} -- "
        f"does the path exist and is python3 installed on the server?")
    remote_digest = out.strip()

    assert remote_digest == local_digest, (
        f"server test_dir={test_dir!r} is OUT OF SYNC with this checkout's "
        f"test/linux/ (local {local_digest[:12]}... != server "
        f"{remote_digest[:12]}...). Re-deploy before running gadget/payload "
        f"tests, e.g.:\n"
        f"    rsync -a --delete test/linux/ <user>@<host>:{test_dir}/")


@pytest.fixture()
def win_session(config):
    import winrm

    w = config["windows"]
    try:
        session = winrm.Session(
            w["host"],
            auth=(w["user"], w["password"]),
            transport=w.get("transport", "ntlm"),
        )
        session.run_ps("Write-Output connectivity-precheck")
    except Exception as e:
        pytest.fail(f"WinRM to [windows] host={w['host']!r} user={w['user']!r} failed: {e}")
    return session


def _ps(session, script: str) -> str:
    r = session.run_ps(script)
    if r.status_code != 0:
        pytest.fail(f"PowerShell over WinRM failed:\n{r.std_out.decode()}\n{r.std_err.decode()}")
    return r.std_out.decode().strip()


def test_windows_winrm_connects(win_session):
    assert _ps(win_session, "Write-Output connectivity-ok") == "connectivity-ok"


def test_windows_helpers_script_present(config, win_session):
    helpers = config["windows"]["helpers"]
    out = _ps(win_session, f"Test-Path -LiteralPath '{helpers}'")
    assert out.lower() == "true", (
        f"[windows] helpers={helpers!r} not found on the client -- "
        f"did you copy test/windows/helpers.ps1 to this path?")


def test_windows_usbip_exe_present(config, win_session):
    usbip_exe = config["windows"].get("usbip_exe", "usbip.exe")
    out = _ps(win_session,
              f"[bool](Get-Command '{usbip_exe}' -ErrorAction SilentlyContinue)")
    assert out.lower() == "true", (
        f"[windows] usbip_exe={usbip_exe!r} not found/not on PATH on the client")


def test_windows_can_reach_usbip_server(config, win_session):
    addr = config["server"]["address"]
    port = config.getint("server", "port", fallback=DEFAULT_USBIP_PORT)
    out = _ps(win_session,
              f"(Test-NetConnection -ComputerName '{addr}' -Port {port} "
              f"-InformationLevel Quiet).ToString()")
    assert out.lower() == "true", (
        f"Windows client cannot reach [server] address={addr!r} on TCP {port} -- "
        f"check the USB/IP server is listening (usbipd) and not firewalled")
