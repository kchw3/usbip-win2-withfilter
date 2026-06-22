"""pytest fixtures for the usbip2_ude device-type filter integration tests.

The harness drives two remote machines:
  - a Linux USB/IP server (builds gadgets, exports over USB/IP) via SSH (paramiko),
  - a Windows client (sets policy, attaches, checks PnP + Event Log) via WinRM.

If test/config.ini is absent, all integration tests are skipped, so a checkout
without lab access still collects cleanly. The pure-unit tests
(test_descriptors.py) always run.
"""

from __future__ import annotations

import configparser
import os
import shlex
from pathlib import Path

import pytest

CONFIG_PATH = Path(__file__).with_name("config.ini")


def pytest_addoption(parser):
    parser.addoption(
        "--run-efficacy", action="store_true", default=False,
        help="run the destructive efficacy (negative-control) tests that execute "
             "real payloads on the Windows client (filter OFF).",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-efficacy"):
        return
    skip = pytest.mark.skip(reason="efficacy tests are opt-in; pass --run-efficacy")
    for item in items:
        if "efficacy" in item.keywords:
            item.add_marker(skip)


def _load_config() -> configparser.ConfigParser | None:
    if not CONFIG_PATH.exists():
        return None
    cp = configparser.ConfigParser()
    cp.read(CONFIG_PATH)
    return cp


@pytest.fixture(scope="session")
def config() -> configparser.ConfigParser:
    cp = _load_config()
    if cp is None:
        pytest.skip("test/config.ini not present; integration tests skipped")
    return cp


class LinuxServer:
    """Thin SSH wrapper around the gadget scripts on the server."""

    def __init__(self, cp: configparser.ConfigParser):
        import paramiko  # imported lazily so unit tests don't need it

        s = cp["linux"]
        self.test_dir = s["test_dir"]
        self.udc = s.get("udc_name", "usbip-vudc.0")
        self.busid = s.get("busid", self.udc)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"username": s["user"]}
        if s.get("password"):
            kwargs["password"] = s["password"]
        if s.get("key_filename"):
            kwargs["key_filename"] = os.path.expanduser(s["key_filename"])
        self.client.connect(s["host"], **kwargs)

    def run(self, cmd: str, check: bool = True) -> str:
        _in, out, err = self.client.exec_command(cmd)
        rc = out.channel.recv_exit_status()
        stdout = out.read().decode()
        stderr = err.read().decode()
        if check and rc != 0:
            raise RuntimeError(f"[linux] {cmd!r} exit {rc}\n{stdout}\n{stderr}")
        return stdout + stderr

    def build_gadget(self, name: str, vid: str | None = None, pid: str | None = None,
                     extra_env: dict[str, str] | None = None) -> None:
        env = f"UDC_NAME={shlex.quote(self.udc)}"
        if vid:
            env += f" VID={shlex.quote(vid)}"
        if pid:
            env += f" PID={shlex.quote(pid)}"
        for k, v in (extra_env or {}).items():
            env += f" {k}={shlex.quote(v)}"
        self.run(f"{env} bash {shlex.quote(self.test_dir)}/gadgets/{name}.sh")
        self.run(f"UDC_NAME={shlex.quote(self.udc)} "
                 f"bash -c 'source {shlex.quote(self.test_dir)}/gadget_lib.sh; "
                 f"usbip_export {shlex.quote(self.busid)}'")

    def fire_hid_marker(self, token: str, device: str = "/dev/hidg0") -> str:
        """Inject keystrokes via the attached HID gadget to drop a marker file."""
        return self.run(
            f"python3 {shlex.quote(self.test_dir)}/payloads/hid_type.py "
            f"--device {shlex.quote(device)} --run-marker {shlex.quote(token)}")

    def fire_hid_text(self, text: str, device: str = "/dev/hidg0") -> str:
        return self.run(
            f"python3 {shlex.quote(self.test_dir)}/payloads/hid_type.py "
            f"--device {shlex.quote(device)} --text {shlex.quote(text)}")

    def start_raw_gadget(self, profile: str, env: dict[str, str] | None = None) -> None:
        """Launch a Tier B raw_gadget profile in the background and export the UDC.

        profile: file under raw_gadget/ without .py (e.g. 'toctou').
        """
        envstr = " ".join(f"{k}={shlex.quote(v)}" for k, v in (env or {}).items())
        rg = f"{self.test_dir}/raw_gadget"
        self.run(
            f"cd {shlex.quote(rg)} && {envstr} nohup python3 {shlex.quote(profile)}.py "
            f">/tmp/{profile}.log 2>&1 & echo started",
        )
        self.run(f"UDC_NAME={shlex.quote(self.udc)} "
                 f"bash -c 'source {shlex.quote(self.test_dir)}/gadget_lib.sh; "
                 f"usbip_export {shlex.quote(self.busid)}'", check=False)

    def stop_raw_gadget(self, profile: str) -> str:
        log = self.run(f"cat /tmp/{profile}.log 2>/dev/null || true", check=False)
        self.run(f"pkill -f {shlex.quote(profile + '.py')} || true", check=False)
        return log

    def teardown(self) -> None:
        self.run(f"UDC_NAME={shlex.quote(self.udc)} "
                 f"bash {shlex.quote(self.test_dir)}/gadgets/teardown.sh", check=False)


class WindowsClient:
    """Thin WinRM wrapper that runs PowerShell with helpers.ps1 dot-sourced."""

    def __init__(self, cp: configparser.ConfigParser):
        import winrm  # imported lazily

        w = cp["windows"]
        self.helpers = w["helpers"]
        self.usbip = w.get("usbip_exe", "usbip.exe")
        self.server = cp["server"]["address"]
        self.session = winrm.Session(
            w["host"],
            auth=(w["user"], w["password"]),
            transport=w.get("transport", "ntlm"),
        )

    def ps(self, script: str) -> "winrm.Response":
        full = f". {self.helpers!r}\n$UsbipExe = {self.usbip!r}\n{script}"
        r = self.session.run_ps(full)
        if r.status_code != 0:
            raise RuntimeError(f"[win] ps failed\n{r.std_out.decode()}\n{r.std_err.decode()}")
        return r

    def set_policy(self, *, allow=None, deny_all=False, disable=False) -> None:
        if disable:
            self.ps("Set-FilterPolicy -Disable -UsbipExe $UsbipExe")
        elif deny_all:
            self.ps("Set-FilterPolicy -DenyAll -UsbipExe $UsbipExe")
        else:
            joined = ",".join(f"'{c}'" for c in (allow or []))
            self.ps(f"Set-FilterPolicy -Allow {joined} -UsbipExe $UsbipExe")

    def attach(self, busid: str) -> bool:
        r = self.ps(f"(Invoke-Attach -Server '{self.server}' -BusId '{busid}' "
                    f"-UsbipExe $UsbipExe).Ok")
        return r.std_out.decode().strip().lower().startswith("true")

    def pnp_present(self, vid: str, pid: str) -> bool:
        r = self.ps(f"Test-PnpPresent -Vid '{vid}' -Pid '{pid}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def rejection_logged(self, contains: str) -> bool:
        r = self.ps(f"Test-RejectionLogged -Contains '{contains}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def hid_instance_ids(self) -> set[str]:
        r = self.ps("Get-PresentHidInstanceIds")
        return {ln.strip() for ln in r.std_out.decode().splitlines() if ln.strip()}

    def removable_marker(self, filename: str) -> str | None:
        r = self.ps(f"Get-RemovableMarker -FileName '{filename}'")
        out = r.std_out.decode().strip()
        return out or None

    def public_marker_present(self, token: str) -> bool:
        r = self.ps(f"Test-PublicMarker -Token '{token}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def remove_public_marker(self, token: str) -> None:
        self.ps(f"Remove-PublicMarker -Token '{token}'")

    def net_adapter_names(self) -> set[str]:
        r = self.ps("Get-PresentNetAdapterNames")
        return {ln.strip() for ln in r.std_out.decode().splitlines() if ln.strip()}

    def cleanup(self) -> None:
        self.ps("Clear-UsbipState -UsbipExe $UsbipExe")


@pytest.fixture()
def linux(config) -> LinuxServer:
    srv = LinuxServer(config)
    yield srv
    srv.teardown()


@pytest.fixture()
def win(config) -> WindowsClient:
    cli = WindowsClient(config)
    cli.cleanup()
    yield cli
    cli.cleanup()
