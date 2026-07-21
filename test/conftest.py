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
import json
import os
import queue
import shlex
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass
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


@dataclass(frozen=True)
class RawGadgetRun:
    """Handle to a verified-live Tier B raw_gadget producer on the server."""

    run_id: str
    profile: str
    pid: int
    run_dir: str
    vid: str
    product_id: str
    busid: str


@dataclass(frozen=True)
class AttachResult:
    ok: bool
    exit_code: int
    output: str


@dataclass(frozen=True)
class FilterPolicyState:
    mode: str
    categories: tuple[str, ...]


class LinuxServer:
    """Thin SSH wrapper around the gadget scripts on the server."""

    def __init__(self, cp: configparser.ConfigParser):
        import paramiko  # imported lazily so unit tests don't need it

        s = cp["linux"]
        self._linux_section = s
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

    def probe_hid_endpoint(self, device: str = "auto") -> dict:
        """Diagnose the gadget HID interrupt-IN endpoint state.

        Returns hid_type.py's JSON classification (endpoint_disabled /
        no_host_polling / live / unknown). The JSON is the last stdout line.
        """
        out = self.run(
            f"python3 {shlex.quote(self.test_dir)}/payloads/hid_type.py "
            f"--device {shlex.quote(device)} --probe")
        return json.loads(out.strip().splitlines()[-1])

    def _raw_udc_names(self) -> tuple[str, str]:
        """raw_gadget INIT driver_name/device_name for the UDC it binds to.

        These are the platform driver/device names, NOT the USB/IP busid. For
        usbip-vudc they default to ('usbip_vudc', self.udc); for dummy_hcd to
        ('dummy_udc', 'dummy_udc.0'). Override in config.ini [linux] via
        raw_udc_driver / raw_udc_device for other kernels.
        """
        sec = self._linux_section
        if "vudc" in self.udc:
            driver, device = "usbip_vudc", self.udc
        else:
            driver, device = "dummy_udc", "dummy_udc.0"
        return sec.get("raw_udc_driver", driver), sec.get("raw_udc_device", device)

    def start_raw_gadget(
        self, profile: str, *, expected_vid: str, expected_pid: str,
        env: dict[str, str] | None = None, timeout: float = 20.0,
    ) -> "RawGadgetRun":
        """Launch a Tier B raw_gadget profile and return only once it is proven
        live and exported.

        This never treats a startup/export failure as success: the caller gets a
        RawGadgetRun with a verified live producer, or this raises. profile is a
        file under raw_gadget/ without .py (e.g. 'toctou').
        """
        self.ensure_vudc_ready()
        run_id = uuid.uuid4().hex
        run_dir = f"/run/usbip-tierb/{run_id}"
        driver, device = self._raw_udc_names()
        full_env = {
            "RUN_DIR": run_dir, "RUN_ID": run_id,
            "UDC_DRIVER": driver, "UDC_DEVICE": device,
            **(env or {}),
        }
        envstr = " ".join(f"{k}={shlex.quote(v)}" for k, v in full_env.items())
        rg = f"{self.test_dir}/raw_gadget"

        self.run(f"mkdir -p {shlex.quote(run_dir)}")
        out = self.run(
            f"cd {shlex.quote(rg)} && setsid env {envstr} python3 "
            f"{shlex.quote(profile)}.py >{shlex.quote(run_dir)}/stdout.log "
            f"2>{shlex.quote(run_dir)}/stderr.log & echo $!")
        pid = int(out.strip().splitlines()[-1])

        run = RawGadgetRun(run_id=run_id, profile=profile, pid=pid, run_dir=run_dir,
                           vid=expected_vid, product_id=expected_pid, busid=self.busid)
        self._await_raw_ready(run, timeout)
        self._export_verified(expected_vid, expected_pid, timeout)
        return run

    def _await_raw_ready(self, run: "RawGadgetRun", timeout: float) -> None:
        deadline = time.time() + timeout
        last = "(no status.json yet)"
        while time.time() < deadline:
            alive = self.run(f"kill -0 {run.pid} 2>/dev/null && echo alive || echo dead",
                             check=False).strip().endswith("alive")
            raw = self.run(f"cat {shlex.quote(run.run_dir)}/status.json 2>/dev/null || true",
                           check=False).strip()
            if raw:
                last = raw
                st = json.loads(raw)
                if st.get("run_id") != run.run_id:
                    raise RuntimeError(f"stale raw_gadget status (run_id mismatch): {raw}")
                if st.get("state") == "error":
                    err = self.run(f"cat {shlex.quote(run.run_dir)}/stderr.log 2>/dev/null || true",
                                   check=False)
                    raise RuntimeError(f"raw_gadget producer error: {st.get('error')}\n{err}")
                if st.get("state") in ("run_ok", "connect") and alive:
                    return
            if not alive:
                err = self.run(f"cat {shlex.quote(run.run_dir)}/stderr.log 2>/dev/null || true",
                               check=False)
                raise RuntimeError(f"raw_gadget producer died before ready.\n{err}")
            time.sleep(0.5)
        raise RuntimeError(f"raw_gadget {run.profile!r} not ready in {timeout:g}s; "
                           f"last status: {last}")

    def _export_verified(self, vid: str, pid: str, timeout: float) -> None:
        self.run(f"UDC_NAME={shlex.quote(self.udc)} "
                 f"bash -c 'source {shlex.quote(self.test_dir)}/gadget_lib.sh; "
                 f"usbip_export {shlex.quote(self.busid)}'")
        want = f"{vid.lower()}:{pid.lower()}"
        deadline = time.time() + timeout
        listing = ""
        while time.time() < deadline:
            listing = self.run("usbip list -r 127.0.0.1 2>/dev/null || true", check=False)
            if self.busid in listing and want in listing.lower():
                return
            time.sleep(1)
        raise RuntimeError(
            f"exported device not visible with busid {self.busid} and {want}:\n{listing}")

    def read_raw_transcript(self, run: "RawGadgetRun") -> list[dict]:
        raw = self.run(f"cat {shlex.quote(run.run_dir)}/transcript.jsonl 2>/dev/null || true",
                       check=False)
        return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]

    def stop_raw_gadget(self, run: "RawGadgetRun") -> str:
        log = self.run(f"cat {shlex.quote(run.run_dir)}/stdout.log "
                       f"{shlex.quote(run.run_dir)}/stderr.log 2>/dev/null || true",
                       check=False)
        self.run(f"kill {run.pid} 2>/dev/null || true", check=False)
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
        self.cleanup_timeout = w.getfloat("cleanup_timeout", fallback=60.0)
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

    @staticmethod
    def _json_output(response) -> dict | list:
        lines = [ln for ln in response.std_out.decode().splitlines() if ln.strip()]
        if not lines:
            raise RuntimeError("expected JSON output from Windows helper, got empty stdout")
        return json.loads(lines[-1])

    def set_policy(self, *, allow=None, deny_all=False, disable=False) -> FilterPolicyState:
        expected_mode = "whitelist"
        expected_categories: tuple[str, ...] = ()
        if disable:
            expected_mode = "disabled"
            r = self.ps("Set-FilterPolicy -Disable -UsbipExe $UsbipExe")
        elif deny_all:
            r = self.ps("Set-FilterPolicy -DenyAll -UsbipExe $UsbipExe")
        else:
            expected_categories = tuple(sorted(allow or []))
            joined = ",".join(f"'{c}'" for c in expected_categories)
            r = self.ps(f"Set-FilterPolicy -Allow {joined} -UsbipExe $UsbipExe")

        raw = self._json_output(r)
        state = FilterPolicyState(
            mode=raw["Mode"].lower(),
            categories=tuple(sorted(raw.get("Categories") or [])),
        )
        expected = FilterPolicyState(expected_mode, expected_categories)
        if state != expected:
            raise RuntimeError(
                f"filter policy readback mismatch: intended={expected}, actual={state}")
        return state

    def attach_result(self, busid: str) -> AttachResult:
        r = self.ps(f"Invoke-Attach -Server '{self.server}' -BusId '{busid}' "
                    f"-UsbipExe $UsbipExe | ConvertTo-Json -Compress")
        raw = self._json_output(r)
        return AttachResult(ok=bool(raw["Ok"]), exit_code=int(raw["ExitCode"]),
                            output=str(raw["Output"]))

    def attach(self, busid: str) -> bool:
        return self.attach_result(busid).ok

    def pnp_present(self, vid: str, pid: str) -> bool:
        """True only for a present, started node (allow-path usability)."""
        r = self.ps(f"Test-PnpPresent -Vid '{vid}' -ProductId '{pid}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def pnp_exposure(self, vid: str, pid: str) -> list[dict]:
        """Any present node, regardless of status (deny-path security oracle)."""
        r = self.ps(f"Get-PnpExposure -Vid '{vid}' -ProductId '{pid}'")
        return [json.loads(ln) for ln in r.std_out.decode().splitlines() if ln.strip()]

    def event_cursor(self) -> int:
        r = self.ps("Get-FilterEventCursor")
        return int(r.std_out.decode().strip())

    def rejection_event_after(
        self, cursor: int, vid: str, pid: str, busid: str | None = None,
    ) -> dict | None:
        bus_arg = f" -BusId '{busid}'" if busid else ""
        r = self.ps(f"Find-FilterRejectionAfter -AfterRecordId {cursor} "
                    f"-Vid '{vid}' -ProductId '{pid}'{bus_arg}")
        out = r.std_out.decode().strip()
        return json.loads(out.splitlines()[-1]) if out else None

    def hid_instance_ids(self) -> set[str]:
        r = self.ps("Get-PresentHidInstanceIds")
        return {ln.strip() for ln in r.std_out.decode().splitlines() if ln.strip()}

    def hid_child_status(self, vid: str, pid: str) -> list[dict]:
        """HID/keyboard child-stack status for a VID/PID."""
        r = self.ps(f"Get-HidChildStatus -Vid '{vid}' -ProductId '{pid}'")
        out = r.std_out.decode()
        return [json.loads(ln) for ln in out.splitlines() if ln.strip()]

    def keyboard_child_ready(self, vid: str, pid: str) -> bool:
        for node in self.hid_child_status(vid, pid):
            if (node.get("Class") == "Keyboard" and
                    node.get("Status") == "OK" and
                    str(node.get("Problem")) in ("0", "", "None")):
                return True
        return False

    def removable_marker(self, filename: str) -> str | None:
        r = self.ps(f"Get-RemovableMarker -FileName '{filename}'")
        out = r.std_out.decode().strip()
        return out or None

    def public_marker_present(self, token: str) -> bool:
        r = self.ps(f"Test-PublicMarker -Token '{token}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def remove_public_marker(self, token: str) -> None:
        self.ps(f"Remove-PublicMarker -Token '{token}'")

    def net_child_status(self, vid: str, pid: str) -> list[dict]:
        """Network child-stack status for a VID/PID."""
        r = self.ps(f"Get-NetChildStatus -Vid '{vid}' -ProductId '{pid}'")
        out = r.std_out.decode()
        return [json.loads(ln) for ln in out.splitlines() if ln.strip()]

    def net_child_ready(self, vid: str, pid: str) -> bool:
        for node in self.net_child_status(vid, pid):
            if (node.get("Class") == "Net" and
                    node.get("Status") == "OK" and
                    str(node.get("Problem")) in ("0", "", "None")):
                return True
        return False

    def net_adapter_names(self) -> set[str]:
        r = self.ps("Get-PresentNetAdapterNames")
        return {ln.strip() for ln in r.std_out.decode().splitlines() if ln.strip()}

    def artifact_manifest(self) -> list[dict]:
        r = self.ps(
            "Get-WindowsArtifactManifest -UsbipExe $UsbipExe "
            f"-Helpers {self.helpers!r}")
        raw = self._json_output(r)
        return raw if isinstance(raw, list) else [raw]

    def _ps_with_timeout(self, script: str, timeout: float, label: str):
        results: queue.Queue = queue.Queue(maxsize=1)

        def worker() -> None:
            try:
                results.put((True, self.ps(script)))
            except BaseException as exc:  # preserve remote traceback/error text
                results.put((False, exc))

        thread = threading.Thread(target=worker, name=f"winrm-{label}", daemon=True)
        thread.start()
        try:
            ok, value = results.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(
                f"Windows {label} did not complete within {timeout:g}s. "
                "If this is cleanup, verify the deployed helpers.ps1 prints "
                "'[cleanup] helpers.ps1 native-timeout revision: async-v2'.") from exc
        if ok:
            return value
        raise value

    def cleanup(self) -> None:
        print(f"[cleanup] starting Windows cleanup (timeout={self.cleanup_timeout:g}s)",
              flush=True)
        r = self._ps_with_timeout(
            "Clear-UsbipState -UsbipExe $UsbipExe", self.cleanup_timeout, "cleanup")
        for line in r.std_out.decode().splitlines():
            if line.startswith("[cleanup]"):
                print(line, flush=True)
        raw = self._json_output(r)
        if not raw.get("Clean") or raw.get("Remaining") != 0:
            raise RuntimeError(f"Windows cleanup did not reach a clean state: {raw}")


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
