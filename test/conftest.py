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
import textwrap
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

    def ensure_vudc_ready(self) -> None:
        """Server-side preflight for the usbip-vudc gadget path.

        Builds run on a remote Linux server, so a missing kernel module or a
        usbipd in the wrong mode surfaces as a cryptic failure deep inside the
        gadget script (e.g. mkdir EPERM on /sys/kernel/config/usb_gadget, or
        'device not offered'). This checks the prerequisites up front, fixes
        what it safely can (mount configfs, modprobe, start usbipd --device),
        and otherwise raises a message naming the exact command to run.

        Only meaningful for the vudc path; it is a no-op for a dummy_hcd busid.
        """
        if "vudc" not in self.udc:
            return
        script = textwrap.dedent(f"""
            set -u
            udc={shlex.quote(self.udc)}

            # 1. libcomposite publishes /sys/kernel/config/usb_gadget. Without it
            #    the gadget mkdir fails with 'Operation not permitted'.
            if [ ! -d /sys/kernel/config/usb_gadget ]; then
              mountpoint -q /sys/kernel/config 2>/dev/null \\
                || mount -t configfs none /sys/kernel/config 2>/dev/null || true
              modprobe libcomposite 2>/dev/null || true
            fi
            if [ ! -d /sys/kernel/config/usb_gadget ]; then
              echo "PREFLIGHT-FAIL libcomposite not loaded: /sys/kernel/config/usb_gadget is absent." >&2
              echo "  fix on the [linux] server (as root): modprobe libcomposite" >&2
              exit 11
            fi

            # 2. the vudc UDC must exist to bind/export the gadget.
            if [ ! -e "/sys/class/udc/$udc" ]; then
              modprobe usbip_vudc 2>/dev/null || modprobe usbip-vudc 2>/dev/null || true
            fi
            if [ ! -e "/sys/class/udc/$udc" ]; then
              echo "PREFLIGHT-FAIL UDC $udc not present under /sys/class/udc." >&2
              echo "  fix on the [linux] server (as root): modprobe usbip-vudc" >&2
              exit 12
            fi

            # 3. usbipd must run in DEVICE mode (usbipd --device) to offer vudc
            #    gadgets; a host-mode daemon will not. Swap/start it if needed.
            device_mode() {{ pgrep -af usbipd | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'; }}
            if pgrep -x usbipd >/dev/null && ! device_mode; then
              pkill -x usbipd 2>/dev/null || true; sleep 0.5
            fi
            if ! device_mode; then
              usbipd --device -D 2>/dev/null || true; sleep 0.5
            fi
            if ! device_mode; then
              echo "PREFLIGHT-FAIL usbipd is not running in device mode (usbipd --device)" >&2
              echo "  and could not be started automatically." >&2
              echo "  fix on the [linux] server: usbipd --device -D" >&2
              exit 13
            fi

            echo PREFLIGHT-OK
        """)
        out = self.run(f"bash -c {shlex.quote(script)}", check=False)
        if "PREFLIGHT-OK" not in out:
            raise RuntimeError(
                "usbip-vudc preflight failed on the Linux server "
                f"(udc={self.udc!r}):\n{out.strip()}")

    def build_gadget(self, name: str, vid: str | None = None, pid: str | None = None,
                     extra_env: dict[str, str] | None = None) -> None:
        self.ensure_vudc_ready()
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

    def fire_hid_marker(self, token: str, device: str = "auto") -> str:
        """Inject keystrokes via the attached HID gadget to drop a marker file.

        device defaults to "auto": hid_type.py resolves the /dev/hidgN backing
        the bound HID gadget rather than assuming hidg0, which can be a stale
        node left by a previous gadget (writes to it fail with ESHUTDOWN).
        """
        return self.run(
            f"python3 {shlex.quote(self.test_dir)}/payloads/hid_type.py "
            f"--device {shlex.quote(device)} --run-marker {shlex.quote(token)}")

    def fire_hid_text(self, text: str, device: str = "auto") -> str:
        return self.run(
            f"python3 {shlex.quote(self.test_dir)}/payloads/hid_type.py "
            f"--device {shlex.quote(device)} --text {shlex.quote(text)}")

    def start_raw_gadget(self, profile: str, env: dict[str, str] | None = None) -> None:
        """Launch a Tier B raw_gadget profile in the background and export the UDC.

        profile: file under raw_gadget/ without .py (e.g. 'toctou').
        """
        self.ensure_vudc_ready()
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
        # Dot-source the helpers by *content*, not by path. Loading a .ps1 file
        # is gated by PowerShell's execution policy (which may be locked to
        # Restricted/AllSigned by Group Policy on a hardened client and cannot be
        # overridden per-user); creating a script block from a string is not.
        # This keeps the harness working without requiring Set-ExecutionPolicy.
        full = (
            f"$__helpers = Get-Content -Raw -LiteralPath {self.helpers!r}\n"
            f". ([scriptblock]::Create($__helpers))\n"
            f"$UsbipExe = {self.usbip!r}\n"
            f"{script}"
        )
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
        r = self.ps(f"Test-PnpPresent -Vid '{vid}' -ProductId '{pid}'")
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
