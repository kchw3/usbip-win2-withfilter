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

import pytest

DEFAULT_USBIP_PORT = 3240


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
