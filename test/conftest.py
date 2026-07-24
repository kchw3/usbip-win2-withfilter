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
import base64
import gzip
import io
import json
import os
import queue
import re
import shlex
import tarfile
import textwrap
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

CONFIG_PATH = Path(__file__).with_name("config.ini")
LOCAL_LINUX_DIR = Path(__file__).parent / "linux"
LOCAL_WINDOWS_HELPERS = Path(__file__).parent / "windows" / "helpers.ps1"


def pytest_addoption(parser):
    parser.addoption(
        "--run-efficacy", action="store_true", default=False,
        help="run the destructive efficacy (negative-control) tests that execute "
             "real payloads on the Windows client (filter OFF).",
    )
    parser.addoption(
        "--run-tierb-canaries", action="store_true", default=False,
        help="run Raw Gadget Tier B lab bring-up canaries.",
    )


def pytest_collection_modifyitems(config, items):
    skip_efficacy = pytest.mark.skip(
        reason="efficacy tests are opt-in; pass --run-efficacy")
    skip_canary = pytest.mark.skip(
        reason="Tier B Raw Gadget canaries are opt-in; pass --run-tierb-canaries")
    for item in items:
        if "efficacy" in item.keywords and not config.getoption("--run-efficacy"):
            item.add_marker(skip_efficacy)
        if ("tierb_canary" in item.keywords and
                not config.getoption("--run-tierb-canaries")):
            item.add_marker(skip_canary)


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
        self.configured_busid = s.get("busid", self.udc)
        self.busid = self.configured_busid
        self.command_timeout = s.getfloat("command_timeout", fallback=60.0)
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"username": s["user"]}
        if s.get("password"):
            kwargs["password"] = s["password"]
        if s.get("key_filename"):
            kwargs["key_filename"] = os.path.expanduser(s["key_filename"])
        self.client.connect(s["host"], **kwargs)
        self._ensure_linux_helpers_available()

    def run(
        self, cmd: str, check: bool = True, timeout: float | None = None,
        label: str | None = None,
    ) -> str:
        limit = self.command_timeout if timeout is None else timeout
        phase = label or cmd
        if label:
            print(f"[linux] phase: {phase} (timeout={limit:g}s)", flush=True)

        _in, out, err = self.client.exec_command(cmd)
        channel = out.channel
        deadline = time.time() + limit
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        def drain() -> None:
            while channel.recv_ready():
                stdout_chunks.append(channel.recv(65535).decode(errors="replace"))
            while channel.recv_stderr_ready():
                stderr_chunks.append(channel.recv_stderr(65535).decode(errors="replace"))

        while not channel.exit_status_ready():
            drain()
            if time.time() >= deadline:
                drain()
                channel.close()
                stdout = "".join(stdout_chunks)
                stderr = "".join(stderr_chunks)
                raise TimeoutError(
                    f"[linux] phase {phase!r} did not complete within {limit:g}s\n"
                    f"cmd: {cmd}\nstdout:\n{stdout}\nstderr:\n{stderr}")
            time.sleep(0.1)

        drain()
        rc = channel.recv_exit_status()
        drain()
        stdout = "".join(stdout_chunks)
        stderr = "".join(stderr_chunks)
        if check and rc != 0:
            raise RuntimeError(f"[linux] {cmd!r} exit {rc}\n{stdout}\n{stderr}")
        return stdout + stderr

    def _test_dir_has_helpers(self, path: str) -> bool:
        out = self.run(
            f"test -f {shlex.quote(path)}/gadget_lib.sh && "
            f"test -f {shlex.quote(path)}/gadgets/teardown.sh && echo ok",
            check=False, timeout=10.0)
        return out.strip().endswith("ok")

    def _ensure_linux_helpers_available(self) -> None:
        """Use configured [linux] test_dir, or deploy a temp copy if missing.

        The harness executes Linux helper scripts from the remote host. If the
        configured test_dir is absent on a fresh lab, first try a normal SFTP
        copy into a user-writable temp directory. If SFTP/file copy is blocked,
        fall back to an encoded tarball decoded/extracted by a remote Python
        script. Either way, subsequent commands run from self.test_dir.
        """
        if self._test_dir_has_helpers(self.test_dir):
            return

        fallback = f"/tmp/usbip-filter-test-linux-{uuid.uuid4().hex[:8]}"
        print(
            f"[linux] configured test_dir={self.test_dir!r} is missing helpers; "
            f"trying temp deployment at {fallback!r}",
            flush=True)
        errors: list[str] = []

        try:
            self._copy_linux_helpers_sftp(fallback)
            if self._test_dir_has_helpers(fallback):
                self.test_dir = fallback
                print(f"[linux] using temp helper copy {fallback}", flush=True)
                return
            errors.append("SFTP copy completed but helper files were not present")
        except Exception as exc:  # noqa: BLE001 - preserve fallback diagnostics
            errors.append(f"SFTP copy failed: {type(exc).__name__}: {exc}")

        try:
            self._copy_linux_helpers_encoded(fallback)
            if self._test_dir_has_helpers(fallback):
                self.test_dir = fallback
                print(f"[linux] using encoded temp helper copy {fallback}", flush=True)
                return
            errors.append("encoded copy completed but helper files were not present")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"encoded copy failed: {type(exc).__name__}: {exc}")

        raise RuntimeError(
            f"[linux] configured test_dir={self.test_dir!r} is missing helpers "
            "and fallback deployment failed:\n- " + "\n- ".join(errors))

    def _copy_linux_helpers_sftp(self, remote_root: str) -> None:
        sftp = self.client.open_sftp()
        try:
            self.run(f"mkdir -p {shlex.quote(remote_root)}", check=True, timeout=10.0)

            def put_dir(local: Path, remote: str) -> None:
                self.run(f"mkdir -p {shlex.quote(remote)}", check=True, timeout=10.0)
                for item in local.iterdir():
                    if item.name == "__pycache__":
                        continue
                    rpath = f"{remote}/{item.name}"
                    if item.is_dir():
                        put_dir(item, rpath)
                    elif item.is_file():
                        sftp.put(str(item), rpath)
                        mode = item.stat().st_mode & 0o777
                        if mode:
                            sftp.chmod(rpath, mode)

            put_dir(LOCAL_LINUX_DIR, remote_root)
        finally:
            sftp.close()

    def _copy_linux_helpers_encoded(self, remote_root: str) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for path in LOCAL_LINUX_DIR.rglob("*"):
                if "__pycache__" in path.parts:
                    continue
                tf.add(path, arcname=path.relative_to(LOCAL_LINUX_DIR))
        encoded = base64.b64encode(buf.getvalue()).decode("ascii")
        script = textwrap.dedent(f"""
            import base64, io, os, tarfile
            root = {remote_root!r}
            os.makedirs(root, exist_ok=True)
            data = base64.b64decode({encoded!r})
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tf:
                tf.extractall(root)
        """)
        self.run(f"python3 -c {shlex.quote(script)}", check=True, timeout=30.0)

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
            device_mode() {{ ps -C usbipd -o args= 2>/dev/null | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'; }}
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
        out = self.run(
            f"bash -c {shlex.quote(script)}", check=False,
            label=f"preflight vudc {self.udc}")
        if "PREFLIGHT-OK" not in out:
            raise RuntimeError(
                "usbip-vudc preflight failed on the Linux server "
                f"(udc={self.udc!r}):\n{out.strip()}")

    def ensure_dummy_ready(self) -> None:
        """Server-side preflight for dummy_hcd-backed configfs gadgets."""
        if "vudc" in self.udc:
            return
        script = textwrap.dedent(f"""
            set -u
            udc={shlex.quote(self.udc)}

            if [ ! -d /sys/kernel/config/usb_gadget ]; then
              mountpoint -q /sys/kernel/config 2>/dev/null \\
                || mount -t configfs none /sys/kernel/config 2>/dev/null || true
              modprobe libcomposite 2>/dev/null || true
            fi
            if [ ! -d /sys/kernel/config/usb_gadget ]; then
              echo "PREFLIGHT-FAIL libcomposite not loaded: /sys/kernel/config/usb_gadget is absent." >&2
              exit 21
            fi

            if [ ! -e "/sys/class/udc/$udc" ]; then
              modprobe dummy_hcd 2>/dev/null || true
            fi
            if [ ! -e "/sys/class/udc/$udc" ]; then
              echo "PREFLIGHT-FAIL UDC $udc not present under /sys/class/udc." >&2
              echo "  fix on the [linux] server (as root): modprobe dummy_hcd" >&2
              exit 22
            fi

            modprobe usbip_host 2>/dev/null || modprobe usbip-host 2>/dev/null || true
            if ! lsmod | grep -q '^usbip_host[[:space:]]'; then
              echo "PREFLIGHT-FAIL usbip_host module is not loaded" >&2
              echo "  fix on the [linux] server (as root): modprobe usbip_host" >&2
              exit 24
            fi

            device_mode() {{ ps -C usbipd -o args= 2>/dev/null | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'; }}
            if pgrep -x usbipd >/dev/null && device_mode; then
              pkill -x usbipd 2>/dev/null || true; sleep 0.5
            fi
            if ! pgrep -x usbipd >/dev/null; then
              usbipd -D 2>/dev/null || true; sleep 0.5
            fi
            if ! pgrep -x usbipd >/dev/null || device_mode; then
              echo "PREFLIGHT-FAIL usbipd is not running in host mode" >&2
              echo "  fix on the [linux] server: usbipd -D" >&2
              exit 23
            fi

            echo PREFLIGHT-OK
        """)
        out = self.run(
            f"bash -c {shlex.quote(script)}", check=False,
            label=f"preflight dummy_hcd {self.udc}")
        if "PREFLIGHT-OK" not in out:
            raise RuntimeError(
                "dummy_hcd preflight failed on the Linux server "
                f"(udc={self.udc!r}):\n{out.strip()}")

    def ensure_gadget_backend_ready(self) -> None:
        if "vudc" in self.udc:
            self.ensure_vudc_ready()
        else:
            self.ensure_dummy_ready()

    def _export_gadget(
        self, *, label: str, vid: str | None = None, pid: str | None = None,
    ) -> str:
        env = f"UDC_NAME={shlex.quote(self.udc)}"
        if vid:
            env += f" VID={shlex.quote(vid)}"
        if pid:
            env += f" PID={shlex.quote(pid)}"
        out = self.run(
            f"{env} "
            f"bash -c 'source {shlex.quote(self.test_dir)}/gadget_lib.sh; "
            f"usbip_export {shlex.quote(self.configured_busid)}'",
            label=label)
        busids = [
            line.strip() for line in out.splitlines()
            if re.fullmatch(r"(?:[0-9]+-[0-9]+(?:\.[0-9]+)*|[-A-Za-z0-9_.]*vudc[-A-Za-z0-9_.]*)",
                            line.strip())
        ]
        busid = busids[-1] if busids else ""
        if not busid:
            raise RuntimeError(f"could not resolve exported USB/IP busid:\n{out}")
        self.busid = busid
        return busid

    def build_gadget(self, name: str, vid: str | None = None, pid: str | None = None,
                     extra_env: dict[str, str] | None = None) -> None:
        self.ensure_gadget_backend_ready()
        env = f"UDC_NAME={shlex.quote(self.udc)}"
        if vid:
            env += f" VID={shlex.quote(vid)}"
        if pid:
            env += f" PID={shlex.quote(pid)}"
        for k, v in (extra_env or {}).items():
            env += f" {k}={shlex.quote(v)}"
        self.run(
            f"{env} bash {shlex.quote(self.test_dir)}/gadgets/{name}.sh",
            label=f"build gadget {name} VID={vid or 'default'} PID={pid or 'default'}")
        self._export_gadget(
            label=f"export gadget busid={self.configured_busid}",
            vid=vid, pid=pid)

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

    def hid_transport_snapshot(self) -> str:
        """Bounded Linux-side HID/USB-IP diagnostics for efficacy xfails.

        This is intentionally read-only and short: it captures the UDC state,
        bound HID function metadata, HID character nodes, USB/IP TCP socket
        state, and recent kernel messages around the moment a HID endpoint probe
        classifies as disabled.
        """
        script = textwrap.dedent(f"""
            set +e
            echo "## udc"
            echo "configured_udc={self.udc}"
            test -r /sys/class/udc/{shlex.quote(self.udc)}/state && \
              cat /sys/class/udc/{shlex.quote(self.udc)}/state
            echo "## gadgets"
            for g in /sys/kernel/config/usb_gadget/*; do
              test -d "$g" || continue
              echo "gadget=$(basename "$g") udc=$(cat "$g/UDC" 2>/dev/null)"
              find "$g/functions" -maxdepth 2 -type f \
                \\( -name dev -o -name protocol -o -name subclass -o -name report_length \\) \
                -print -exec cat {{}} \\; 2>/dev/null
            done
            echo "## hid_nodes"
            ls -l /dev/hidg* 2>/dev/null || true
            echo "## usbip_tcp"
            ss -tnp 2>/dev/null | grep ':3240' || true
            echo "## usbip_port"
            usbip port 2>&1 || true
            echo "## recent_kernel"
            dmesg -T 2>/dev/null | grep -E 'hid|dummy_udc|usbip|usb .*5-1|config' | tail -n 80
        """)
        return self.run(
            f"bash -c {shlex.quote(script)}",
            check=False, timeout=10.0, label="HID transport snapshot")

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
        export: bool = True,
    ) -> "RawGadgetRun":
        """Launch a Tier B raw_gadget profile and return only once it is proven
        live and exported.

        This never treats a startup/export failure as success: the caller gets a
        RawGadgetRun with a verified live producer, or this raises. profile is a
        file under raw_gadget/ without .py (e.g. 'toctou').
        """
        self.ensure_gadget_backend_ready()
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
                           vid=expected_vid, product_id=expected_pid,
                           busid=self.configured_busid)
        self._await_raw_ready(run, timeout)
        if export:
            self._export_verified(expected_vid, expected_pid, timeout)
            return RawGadgetRun(
                run_id=run.run_id, profile=run.profile, pid=run.pid,
                run_dir=run.run_dir, vid=run.vid, product_id=run.product_id,
                busid=self.busid)
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

    def _verify_export_visible(
        self, vid: str, pid: str, timeout: float, *, busid: str | None = None,
    ) -> None:
        expected_busid = self.busid if busid is None else busid
        want = f"{vid.lower()}:{pid.lower()}"
        deadline = time.time() + timeout
        listing = ""
        while time.time() < deadline:
            listing = self.run("usbip list -r 127.0.0.1 2>/dev/null || true", check=False)
            if expected_busid in listing and want in listing.lower():
                return
            time.sleep(1)
        raise RuntimeError(
            f"exported device not visible with busid {expected_busid} and {want}:\n"
            f"{listing}")

    def verify_raw_export_visible(
        self, vid: str, pid: str, *, timeout: float = 5.0,
        busid: str | None = None,
    ) -> None:
        self._verify_export_visible(vid, pid, timeout, busid=busid)

    def _export_verified(self, vid: str, pid: str, timeout: float) -> None:
        self._export_gadget(
            label=f"export raw gadget busid={self.configured_busid}",
            vid=f"0x{vid}", pid=f"0x{pid}")
        self._verify_export_visible(vid, pid, timeout)

    def read_raw_transcript(self, run: "RawGadgetRun") -> list[dict]:
        raw = self.run(f"cat {shlex.quote(run.run_dir)}/transcript.jsonl 2>/dev/null || true",
                       check=False)
        return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]

    def stop_raw_gadget(self, run: "RawGadgetRun") -> str:
        log = self.run(f"cat {shlex.quote(run.run_dir)}/stdout.log "
                       f"{shlex.quote(run.run_dir)}/stderr.log 2>/dev/null || true",
                       check=False)
        if run.busid and run.busid != "auto":
            self.run(
                f"UDC_NAME={shlex.quote(self.udc)} "
                f"bash -c 'source {shlex.quote(self.test_dir)}/gadget_lib.sh; "
                f"usbip_unexport {shlex.quote(run.busid)}'",
                check=False)
        self.run(f"kill {run.pid} 2>/dev/null || true", check=False)
        return log

    def teardown(self) -> None:
        self.run(
            f"UDC_NAME={shlex.quote(self.udc)} "
            f"BUSID={shlex.quote(self.busid)} "
            f"bash {shlex.quote(self.test_dir)}/gadgets/teardown.sh",
            check=False, timeout=20.0, label="teardown gadget")


class WindowsClient:
    """Thin WinRM wrapper that runs PowerShell with helpers.ps1 dot-sourced."""

    def __init__(self, cp: configparser.ConfigParser):
        import winrm  # imported lazily

        w = cp["windows"]
        self.helpers = w["helpers"]
        self._helper_mode = "configured-file"
        self._embedded_helpers_b64 = base64.b64encode(
            gzip.compress(LOCAL_WINDOWS_HELPERS.read_bytes())).decode("ascii")
        self.usbip = w.get("usbip_exe", "usbip.exe")
        self.server = cp["server"]["address"]
        self.cleanup_timeout = w.getfloat("cleanup_timeout", fallback=60.0)
        self.cleanup_step_timeout = w.getfloat("cleanup_step_timeout", fallback=20.0)
        self.winrm_step_timeout = w.getfloat("winrm_step_timeout", fallback=30.0)
        self.cleanup_reset_policy = w.getboolean("cleanup_reset_policy", fallback=False)
        self.cleanup_detach = w.get("cleanup_detach", "skip").strip().lower()
        if self.cleanup_detach not in {"closeonly", "full", "skip"}:
            raise ValueError(
                "[windows] cleanup_detach must be closeonly, full, or skip")
        self.session = winrm.Session(
            w["host"],
            auth=(w["user"], w["password"]),
            transport=w.get("transport", "ntlm"),
        )
        self._prepare_helpers()

    def ps(self, script: str) -> "winrm.Response":
        full = self._helper_prelude() + f"$UsbipExe = {self.usbip!r}\n{script}"
        r = self.session.run_ps(full)
        if r.status_code != 0:
            raise RuntimeError(f"[win] ps failed\n{r.std_out.decode()}\n{r.std_err.decode()}")
        return r

    def _run_raw_ps(self, script: str):
        return self.session.run_ps(script)

    def _prepare_helpers(self) -> None:
        """Select a helper-loading strategy for the Windows client.

        Prefer the configured helper path. If missing or not loadable, copy the
        local helper to a per-user temp path and load from there. If that copy or
        load fails, fall back to an encoded in-memory script block.
        """
        if self._helper_bootstrap_works(self.helpers):
            self._helper_mode = "configured-file"
            return

        errors: list[str] = []
        try:
            candidate = self._copy_windows_helpers_temp()
            if candidate and self._helper_bootstrap_works(candidate):
                self.helpers = candidate
                self._helper_mode = "temp-file"
                print(f"[windows] using temp helper copy {candidate}", flush=True)
                return
            errors.append(f"temp copy produced unusable helper path: {candidate!r}")
        except Exception as exc:  # noqa: BLE001 - preserve fallback path
            errors.append(f"temp copy exception: {type(exc).__name__}: {exc}")
            print(
                f"[windows] temp helper copy failed; trying embedded helpers: "
                f"{type(exc).__name__}: {exc}",
                flush=True)

        try:
            if self._embedded_helper_bootstrap_works():
                self._helper_mode = "embedded"
                print("[windows] using encoded in-memory helpers.ps1", flush=True)
                return
            errors.append("embedded helper bootstrap returned non-zero")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"embedded helper exception: {type(exc).__name__}: {exc}")

        raise RuntimeError(
            "[windows] helpers.ps1 is missing or not loadable from the configured "
            "path, temp-file copy failed, and encoded script-block fallback failed:\n- "
            + "\n- ".join(errors))

    def _copy_windows_helpers_temp(self) -> str | None:
        init = self._run_raw_ps(
            "$p = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'usbip-filter-test-helpers.ps1')\n"
            "$b = $p + '.b64'\n"
            "Remove-Item -LiteralPath $p,$b -ErrorAction SilentlyContinue\n"
            "[IO.File]::WriteAllText($b, '', [Text.Encoding]::ASCII)\n"
            "Write-Output $p\n")
        if init.status_code != 0:
            raise RuntimeError(
                f"temp init failed: {init.status_code} "
                f"{init.std_out.decode(errors='replace')} "
                f"{init.std_err.decode(errors='replace')}")
        path = init.std_out.decode(errors="replace").strip().splitlines()[-1]
        b64_path = path + ".b64"
        chunk_size = 500
        for offset in range(0, len(self._embedded_helpers_b64), chunk_size):
            chunk = self._embedded_helpers_b64[offset:offset + chunk_size]
            append = self._run_raw_ps(
                f"[IO.File]::AppendAllText({b64_path!r}, {chunk!r}, [Text.Encoding]::ASCII)\n")
            if append.status_code != 0:
                raise RuntimeError(
                    f"temp append failed at offset {offset}: {append.status_code} "
                    f"{append.std_out.decode(errors='replace')} "
                    f"{append.std_err.decode(errors='replace')}")
        finalize = self._run_raw_ps(
            f"$data = [Convert]::FromBase64String((Get-Content -Raw -LiteralPath {b64_path!r}))\n"
            "$ms = New-Object IO.MemoryStream(,$data)\n"
            "$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)\n"
            f"$out = [IO.File]::Create({path!r})\n"
            "$gz.CopyTo($out)\n"
            "$out.Dispose(); $gz.Dispose(); $ms.Dispose()\n"
            f"Remove-Item -LiteralPath {b64_path!r} -ErrorAction SilentlyContinue\n"
            f"Write-Output {path!r}\n")
        if finalize.status_code != 0:
            raise RuntimeError(
                f"temp finalize failed: {finalize.status_code} "
                f"{finalize.std_out.decode(errors='replace')} "
                f"{finalize.std_err.decode(errors='replace')}")
        return path

    def _helper_bootstrap_works(self, path: str) -> bool:
        script = (
            f"if (!(Test-Path -LiteralPath {path!r})) {{ exit 10 }}\n"
            f"$__helpers = Get-Content -Raw -LiteralPath {path!r}\n"
            ". ([scriptblock]::Create($__helpers))\n"
            "if (!(Get-Command Invoke-NativeWithTimeout -ErrorAction SilentlyContinue)) { exit 11 }\n"
        )
        return self._run_raw_ps(script).status_code == 0

    def _embedded_helper_bootstrap_works(self) -> bool:
        return self._run_raw_ps(
            self._embedded_helper_prelude() +
            "if (!(Get-Command Invoke-NativeWithTimeout -ErrorAction SilentlyContinue)) { exit 11 }\n"
        ).status_code == 0

    def _embedded_helper_prelude(self) -> str:
        return (
            f"$__helpersBytes = [Convert]::FromBase64String('{self._embedded_helpers_b64}')\n"
            "$__helpersMs = New-Object IO.MemoryStream(,$__helpersBytes)\n"
            "$__helpersGz = New-Object IO.Compression.GZipStream($__helpersMs, [IO.Compression.CompressionMode]::Decompress)\n"
            "$__helpersReader = New-Object IO.StreamReader($__helpersGz, [Text.Encoding]::UTF8)\n"
            "$__helpers = $__helpersReader.ReadToEnd()\n"
            "$__helpersReader.Dispose(); $__helpersGz.Dispose(); $__helpersMs.Dispose()\n"
            ". ([scriptblock]::Create($__helpers))\n"
        )

    def _helper_prelude(self) -> str:
        if self._helper_mode == "embedded":
            return self._embedded_helper_prelude()
        return (
            f"$__helpers = Get-Content -Raw -LiteralPath {self.helpers!r}\n"
            ". ([scriptblock]::Create($__helpers))\n"
        )

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
            print("[policy] phase: filter --disable", flush=True)
            r = self._ps_with_timeout(
                "Set-FilterPolicy -Disable -UsbipExe $UsbipExe",
                self.winrm_step_timeout, "policy filter --disable")
        elif deny_all:
            print("[policy] phase: filter --deny-all", flush=True)
            r = self._ps_with_timeout(
                "Set-FilterPolicy -DenyAll -UsbipExe $UsbipExe",
                self.winrm_step_timeout, "policy filter --deny-all")
        else:
            expected_categories = tuple(sorted(allow or []))
            joined = ",".join(f"'{c}'" for c in expected_categories)
            print(f"[policy] phase: filter --allow {','.join(expected_categories)}",
                  flush=True)
            r = self._ps_with_timeout(
                f"Set-FilterPolicy -Allow {joined} -UsbipExe $UsbipExe",
                self.winrm_step_timeout, "policy filter --allow")

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
        print(f"[windows] phase: usbip.exe attach busid={busid}", flush=True)
        r = self._ps_with_timeout(
            f"Invoke-Attach -Server '{self.server}' -BusId '{busid}' "
            f"-UsbipExe $UsbipExe | ConvertTo-Json -Compress",
            self.winrm_step_timeout, "attach")
        raw = self._json_output(r)
        return AttachResult(ok=bool(raw["Ok"]), exit_code=int(raw["ExitCode"]),
                            output=str(raw["Output"]))

    def attach(self, busid: str) -> bool:
        return self.attach_result(busid).ok

    def usbip_port_snapshot(self) -> str:
        r = self._ps_with_timeout(
            "& $UsbipExe port 2>&1 | Out-String",
            self.winrm_step_timeout, "usbip port snapshot")
        return r.std_out.decode(errors="replace").strip()

    def pnp_present(self, vid: str, pid: str) -> bool:
        """True only for a present, started node (allow-path usability)."""
        r = self.ps(f"Test-PnpPresent -Vid '{vid}' -ProductId '{pid}'")
        return r.std_out.decode().strip().lower().startswith("true")

    def pnp_exposure(self, vid: str, pid: str) -> list[dict]:
        """Any present node, regardless of status (deny-path security oracle)."""
        r = self.ps(f"Get-PnpExposure -Vid '{vid}' -ProductId '{pid}'")
        return [json.loads(ln) for ln in r.std_out.decode().splitlines() if ln.strip()]

    def pnp_node_details(self, vid: str, pid: str) -> list[dict]:
        """Detailed PnP/driver matching state for all VID/PID nodes."""
        r = self.ps(f"Get-PnpNodeDetails -Vid '{vid}' -ProductId '{pid}'")
        return [json.loads(ln) for ln in r.std_out.decode().splitlines() if ln.strip()]

    def event_cursor(self) -> int:
        print("[windows] phase: read usbip2_ude event cursor", flush=True)
        r = self._ps_with_timeout(
            "Get-FilterEventCursor", self.winrm_step_timeout, "event cursor")
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
                "'[cleanup] helpers.ps1 native-timeout revision: task-v4'.") from exc
        if ok:
            return value
        raise value

    @staticmethod
    def _print_cleanup_output(response) -> None:
        for line in response.std_out.decode().splitlines():
            if line.startswith("[cleanup]"):
                print(line, flush=True)

    @staticmethod
    def _ps_literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _cleanup_step(self, label: str, script: str, timeout: float | None = None):
        limit = self.cleanup_step_timeout if timeout is None else timeout
        print(f"[cleanup] phase: {label} (timeout={limit:g}s)", flush=True)
        return self._ps_with_timeout(script, limit, f"cleanup {label}")

    @staticmethod
    def _normalize_json_list(value) -> list[dict]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _cleanup_list_nodes(self, label: str) -> list[dict]:
        r = self._cleanup_step(label, """
$nodes = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -match 'VID_16C0' } |
    Select-Object InstanceId, Status, Class)
[pscustomobject]@{ Nodes = @($nodes) } | ConvertTo-Json -Compress
""")
        raw = self._json_output(r)
        return self._normalize_json_list(raw.get("Nodes"))

    def cleanup(self) -> None:
        print(
            f"[cleanup] starting Windows cleanup "
            f"(timeout={self.cleanup_timeout:g}s, "
            f"step_timeout={self.cleanup_step_timeout:g}s, "
            f"detach={self.cleanup_detach})",
            flush=True)

        if self.cleanup_detach == "skip":
            print("[cleanup] skipping USB/IP detach by request", flush=True)
        else:
            detach_arg = "--all" if self.cleanup_detach == "full" else "--all=closeonly"
            detach_script = (
                f"$r = Invoke-NativeWithTimeout -FilePath $UsbipExe "
                f"-Arguments @('detach', '{detach_arg}') -TimeoutSeconds 15\n"
                "if ($r.TimedOut) { "
                "Write-Output '[cleanup] usbip.exe detach timed out after 15s' "
                "} elseif ($r.ExitCode -ne 0) { "
                "Write-Output ('[cleanup] usbip.exe detach exited ' + $r.ExitCode + ': ' + $r.Output) "
                "} else { Write-Output '[cleanup] usbip.exe detach completed' }")
            r = self._cleanup_step(f"usbip.exe detach {detach_arg}", detach_script, 25.0)
            self._print_cleanup_output(r)

        if self.cleanup_reset_policy:
            r = self._cleanup_step("filter --disable", """
Invoke-UsbipChecked -UsbipExe $UsbipExe -Arguments @('filter', '--disable') `
    -TimeoutSeconds 15 | Out-Null
Write-Output '[cleanup] filter --disable completed'
[pscustomobject]@{ Ok = $true } | ConvertTo-Json -Compress
""")
            self._print_cleanup_output(r)
            self._json_output(r)
        else:
            print("[cleanup] skipping filter reset by request", flush=True)

        nodes = self._cleanup_list_nodes("enumerate stale VID_16C0 PnP nodes")
        if not nodes:
            print("[cleanup] no stale VID_16C0 PnP nodes found", flush=True)
        for node in nodes:
            instance_id = str(node.get("InstanceId", ""))
            print(
                f"[cleanup] stale PnP node found: "
                f"{node.get('Status')} {node.get('Class')} {instance_id}",
                flush=True)
            quoted_id = self._ps_literal(instance_id)
            remove_script = f"""
$id = {quoted_id}
$removePnpDevice = Get-Command Remove-PnpDevice -ErrorAction SilentlyContinue
$pnputil = Get-Command pnputil.exe -ErrorAction SilentlyContinue
if ($null -ne $removePnpDevice) {{
    try {{
        Remove-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
        [pscustomobject]@{{ Removed=$true; Method='Remove-PnpDevice'; InstanceId=$id }} | ConvertTo-Json -Compress
        return
    }} catch {{
        Write-Output ("[cleanup] Remove-PnpDevice failed for ${{id}}: " + $_.Exception.Message)
    }}
}} else {{
    Write-Output '[cleanup] Remove-PnpDevice not available; using pnputil.exe'
}}
if ($null -eq $pnputil) {{
    [pscustomobject]@{{ Removed=$false; Method='none'; InstanceId=$id; Error='pnputil.exe not available' }} | ConvertTo-Json -Compress
    return
}}
$r = Invoke-NativeWithTimeout -FilePath $pnputil.Source `
    -Arguments @('/remove-device', $id) -TimeoutSeconds 20
if ($r.Output) {{
    $r.Output.Trim() -split "`r?`n" | Where-Object {{ $_ }} |
        ForEach-Object {{ Write-Output ("[cleanup] pnputil: " + $_) }}
}}
[pscustomobject]@{{
    Removed = ($r.ExitCode -eq 0)
    Method = 'pnputil.exe'
    InstanceId = $id
    ExitCode = $r.ExitCode
    TimedOut = $r.TimedOut
}} | ConvertTo-Json -Compress
"""
            r = self._cleanup_step(f"remove stale node {instance_id}", remove_script)
            self._print_cleanup_output(r)
            result = self._json_output(r)
            if not result.get("Removed"):
                raise RuntimeError(f"Windows cleanup could not remove stale node: {result}")

        remaining = self._cleanup_list_nodes("verify no stale VID_16C0 PnP nodes remain")
        if remaining:
            raise RuntimeError(
                f"Windows cleanup left test PnP nodes present: {remaining}")
        print("[cleanup] Windows cleanup completed", flush=True)


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
