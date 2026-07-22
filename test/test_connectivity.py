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

import hashlib
import json
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

DEFAULT_USBIP_PORT = 3240
USBIP_AUTO_FIX_ENV = "USBIP_TEST_AUTO_FIX"

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


_LINUX_USBIP_FIX_ATTEMPTED = False


def _linux_uses_vudc(config) -> bool:
    return "vudc" in config["linux"].get("udc_name", "usbip-vudc.0")


def _linux_usbip_issues(config, ssh, *, require_device_mode: bool = False) -> list[str]:
    udc = config["linux"].get("udc_name", "usbip-vudc.0")
    port = config.getint("server", "port", fallback=DEFAULT_USBIP_PORT)
    check_device_mode = require_device_mode and "vudc" in udc
    script = textwrap.dedent(f"""
        set -u
        udc={shlex.quote(udc)}
        port={port}
        need_device_mode={'1' if check_device_mode else '0'}

        if [ ! -d /sys/kernel/config/usb_gadget ]; then
          echo "libcomposite: /sys/kernel/config/usb_gadget is absent"
        fi

        if [ ! -e "/sys/class/udc/$udc" ]; then
          echo "udc: /sys/class/udc/$udc is absent"
        fi

        if [ ! -e /dev/raw-gadget ]; then
          echo "raw_gadget: /dev/raw-gadget is absent"
        fi

        if printf '%s\n' "$udc" | grep -q dummy; then
          if [ ! -e /sys/bus/platform/devices/dummy_hcd.0 ] && \
             ! ls /sys/class/udc/dummy* >/dev/null 2>&1; then
            echo "dummy_hcd: no dummy UDC detected"
          fi
          if ! lsmod | grep -q '^usbip_host[[:space:]]'; then
            echo "usbip_host: module is not loaded"
          fi
        fi

        device_mode() {{
          ps -C usbipd -o args= 2>/dev/null | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'
        }}
        listening() {{
          (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ":$port "
        }}
        if [ "$need_device_mode" = 1 ]; then
          if ! device_mode; then
            echo "usbipd: no device-mode daemon found"
          fi
        else
          if ! pgrep -x usbipd >/dev/null; then
            echo "usbipd: no host-mode daemon found"
          elif device_mode; then
            echo "usbipd: running in device mode, but host mode is required for udc=$udc"
          fi
        fi
        if ! listening; then
          echo "usbipd: no listener on TCP $port"
        fi
    """)
    rc, out, err = _ssh_run(ssh, f"bash -c {shlex.quote(script)}")
    if rc != 0:
        return [f"preflight check failed: {out}{err}".strip()]
    return [line.strip() for line in out.splitlines() if line.strip()]

def _linux_usbip_fix_script(config, *, require_device_mode: bool) -> str:
    need_device_mode = require_device_mode and _linux_uses_vudc(config)
    return textwrap.dedent(f"""
        set -u
        as_root() {{
          if [ "$(id -u)" -eq 0 ]; then
            "$@"
          else
            sudo -n "$@"
          fi
        }}
        log() {{ printf '[fix] %s\\n' "$*"; }}

        mountpoint -q /sys/kernel/config 2>/dev/null \
          || {{ log "configfs: not mounted; mounting..."; as_root mount -t configfs none /sys/kernel/config; }}

        log "libcomposite: loading/checking..."
        as_root modprobe libcomposite
        log "usbip-vudc: loading/checking..."
        as_root modprobe usbip_vudc 2>/dev/null || as_root modprobe usbip-vudc 2>/dev/null || true
        log "raw_gadget: loading/checking..."
        as_root modprobe raw_gadget
        log "dummy_hcd: loading/checking..."
        as_root modprobe dummy_hcd 2>/dev/null || true
        log "usbip_host: loading/checking..."
        as_root modprobe usbip_host 2>/dev/null || as_root modprobe usbip-host 2>/dev/null || true

        device_mode() {{
          ps -C usbipd -o args= 2>/dev/null | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'
        }}
        if [ {'1' if need_device_mode else '0'} = 1 ]; then
          if pgrep -x usbipd >/dev/null && ! device_mode; then
            log "usbipd: host-mode daemon found; stopping before device-mode start..."
            as_root pkill -x usbipd 2>/dev/null || true
            sleep 0.5
          fi
          if ! device_mode; then
            log "usbipd: starting device mode with 'usbipd --device -D'..."
            as_root usbipd --device -D
            sleep 0.5
          fi
        else
          if pgrep -x usbipd >/dev/null && device_mode; then
            log "usbipd: device-mode daemon found; stopping before host-mode start..."
            as_root pkill -x usbipd 2>/dev/null || true
            sleep 0.5
          fi
          if ! pgrep -x usbipd >/dev/null; then
            log "usbipd: starting host mode with 'usbipd -D'..."
            as_root usbipd -D
            sleep 0.5
          fi
        fi

        echo USBIP-LINUX-FIX-DONE
    """)

def _read_linux_usbip_fix_answer(prompt: str, pytestconfig=None) -> str:
    capman = None
    if pytestconfig is not None:
        capman = pytestconfig.pluginmanager.getplugin("capturemanager")
    if capman is not None:
        try:
            with capman.global_and_fixture_disabled():
                return input(prompt).strip().lower()
        except (AttributeError, EOFError, OSError):
            pass

    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline().strip().lower()
    except OSError:
        try:
            return input(prompt).strip().lower()
        except (EOFError, OSError):
            return ""


def _linux_usbip_fix_allowed(config, ssh, issues: list[str], pytestconfig=None) -> bool:
    auto = os.environ.get(USBIP_AUTO_FIX_ENV, "").strip().lower()
    if auto in {"1", "true", "yes", "y"}:
        return True
    if auto in {"0", "false", "no", "n"}:
        return False

    rc, out, _err = _ssh_run(ssh, "id -u")
    if rc == 0 and out.strip() == "0":
        return True

    prompt = (
        "\nLinux USB/IP prerequisites look incomplete:\n"
        + "".join(f"  - {issue}\n" for issue in issues)
        + "\nRun the automatic Linux-side fix over SSH?\n"
        + "It will run: modprobe libcomposite, raw_gadget, dummy_hcd, "
          "usbip-vudc if available, and start usbipd in the mode required "
          "by the configured UDC.\n"
        + "This requires root SSH or passwordless sudo. Apply fix? [y/N] "
    )
    return _read_linux_usbip_fix_answer(prompt, pytestconfig) in {"y", "yes"}


def _maybe_fix_linux_usbip(config, ssh, *, require_device_mode: bool = False,
                           pytestconfig=None) -> None:
    global _LINUX_USBIP_FIX_ATTEMPTED

    issues = _linux_usbip_issues(config, ssh, require_device_mode=require_device_mode)
    if not issues or _LINUX_USBIP_FIX_ATTEMPTED:
        return

    if not _linux_usbip_fix_allowed(config, ssh, issues, pytestconfig):
        return

    _LINUX_USBIP_FIX_ATTEMPTED = True
    script = _linux_usbip_fix_script(config, require_device_mode=require_device_mode)
    rc, out, err = _ssh_run(ssh, f"bash -c {shlex.quote(script)}")
    assert rc == 0 and "USBIP-LINUX-FIX-DONE" in out, (
        "automatic Linux USB/IP fix failed. The SSH user must be root or have "
        f"passwordless sudo.\nstdout:\n{out}\nstderr:\n{err}")


def _linux_usbip_issue_message(issues: list[str]) -> str:
    return (
        "Linux USB/IP prerequisites are incomplete:\n"
        + "".join(f"  - {issue}\n" for issue in issues)
        + "If the Linux SSH user is root, the connectivity test attempts the fix "
          f"automatically. Otherwise re-run interactively and accept the prompt, or set "
          f"{USBIP_AUTO_FIX_ENV}=1 to let it run the root setup commands over SSH.")


def test_linux_ssh_connects(ssh):
    rc, out, err = _ssh_run(ssh, "echo connectivity-ok")
    assert rc == 0 and "connectivity-ok" in out, f"unexpected SSH output: {out!r} {err!r}"


def test_linux_test_dir_present(config, ssh):
    test_dir = config["linux"]["test_dir"]
    rc, out, _err = _ssh_run(ssh, f"test -f {test_dir}/gadget_lib.sh && echo found")
    assert rc == 0 and "found" in out, (
        f"[linux] test_dir={test_dir!r} does not contain gadget_lib.sh -- "
        f"did you copy test/linux/ to the server at this path?")


def test_linux_udc_available(config, ssh, pytestconfig):
    _maybe_fix_linux_usbip(config, ssh, require_device_mode=_linux_uses_vudc(config),
                           pytestconfig=pytestconfig)
    udc = config["linux"].get("udc_name", "usbip-vudc.0")
    rc, out, _err = _ssh_run(ssh, f"test -e /sys/class/udc/{udc} && echo found")
    assert rc == 0 and "found" in out, (
        f"[linux] udc_name={udc!r} not found under /sys/class/udc -- "
        f"is the gadget UDC module (usbip-vudc / dummy_hcd) loaded?")


def test_linux_usbip_gadget_prereqs(config, ssh, pytestconfig):
    _maybe_fix_linux_usbip(config, ssh, require_device_mode=_linux_uses_vudc(config),
                           pytestconfig=pytestconfig)
    issues = _linux_usbip_issues(config, ssh, require_device_mode=_linux_uses_vudc(config))
    assert not issues, _linux_usbip_issue_message(issues)


def test_linux_usbipd_listening(config, ssh, pytestconfig):
    _maybe_fix_linux_usbip(config, ssh, require_device_mode=_linux_uses_vudc(config),
                           pytestconfig=pytestconfig)
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


def test_linux_usbipd_device_mode(config, ssh, pytestconfig):
    # vudc gadgets are only offered by a usbipd running in *device* mode
    # (usbipd --device); a host-mode daemon will silently not offer them. This
    # is a no-op assertion for a dummy_hcd / real-hardware busid (host mode).
    udc = config["linux"].get("udc_name", "usbip-vudc.0")
    if "vudc" not in udc:
        pytest.skip(f"udc_name={udc!r} is not a vudc; device-mode check N/A")
    _maybe_fix_linux_usbip(config, ssh, require_device_mode=True, pytestconfig=pytestconfig)
    rc, out, _err = _ssh_run(
        ssh,
        "ps -C usbipd -o args= 2>/dev/null | "
        "grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)' "
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


def test_windows_artifacts_identified_and_helpers_in_sync(config, win_session):
    """Attest the exact helper, CLI, and driver binaries used by the lab.

    The helper must match this checkout. Optional expected SHA256 values in
    config.ini pin the executable/drivers to a reviewed build; without pins we
    still require paths + hashes so every run is attributable.
    """
    w = config["windows"]
    helpers = w["helpers"]
    usbip_exe = w.get("usbip_exe", "usbip.exe")
    script = (
        f"$h = Get-Content -Raw -LiteralPath {helpers!r}; "
        ". ([scriptblock]::Create($h)); "
        f"Get-WindowsArtifactManifest -UsbipExe {usbip_exe!r} -Helpers {helpers!r}"
    )
    raw = _ps(win_session, script).splitlines()[-1]
    manifest = json.loads(raw)
    if isinstance(manifest, dict):
        manifest = [manifest]
    by_name = {item["Name"]: item for item in manifest}

    required = {"usbip.exe", "helpers.ps1", "usbip2_ude.sys", "usbip2_filter.sys"}
    assert required <= by_name.keys(), f"artifact manifest incomplete: {manifest}"
    for name in required:
        assert by_name[name].get("Path") and by_name[name].get("Sha256"), (
            f"Windows artifact {name} missing or unhashable: {by_name[name]}")

    local_helpers_hash = hashlib.sha256(
        (Path(__file__).parent / "windows" / "helpers.ps1").read_bytes()).hexdigest()
    assert by_name["helpers.ps1"]["Sha256"].lower() == local_helpers_hash, (
        "Windows helpers.ps1 is out of sync with this checkout: "
        f"local={local_helpers_hash}, remote={by_name['helpers.ps1']['Sha256']}")

    optional_pins = {
        "usbip.exe": "expected_usbip_sha256",
        "usbip2_ude.sys": "expected_ude_sha256",
        "usbip2_filter.sys": "expected_filter_sha256",
    }
    for name, key in optional_pins.items():
        expected = w.get(key, "").strip().lower()
        if expected:
            assert by_name[name]["Sha256"].lower() == expected, (
                f"{name} hash mismatch: expected [{key}]={expected}, "
                f"actual={by_name[name]['Sha256']}")


def test_windows_can_reach_usbip_server(config, win_session):
    addr = config["server"]["address"]
    port = config.getint("server", "port", fallback=DEFAULT_USBIP_PORT)
    out = _ps(win_session,
              f"(Test-NetConnection -ComputerName '{addr}' -Port {port} "
              f"-InformationLevel Quiet).ToString()")
    assert out.lower() == "true", (
        f"Windows client cannot reach [server] address={addr!r} on TCP {port} -- "
        f"check the USB/IP server is listening (usbipd) and not firewalled")
