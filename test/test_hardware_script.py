from __future__ import annotations

import os
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).with_name("linux") / "hardware_device.sh"
ACK = "I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE"


def _fixture(tmp_path: Path, *, kind: str = "keyboard") -> tuple[dict[str, str], Path]:
    root = tmp_path / "sys"
    device = root / "bus/usb/devices/1-2"
    driver_root = root / "bus/usb/drivers/testdrv"
    device.mkdir(parents=True)
    driver_root.mkdir(parents=True)
    for name, value in {"idVendor": "1234\n", "idProduct": "0001\n",
                        "serial": "LAB-01\n", "bDeviceClass": "00\n"}.items():
        (device / name).write_text(value)
    interface = root / "bus/usb/devices/1-2:1.0"
    interface.mkdir(parents=True)
    (interface / "driver").symlink_to(driver_root)
    (driver_root / "unbind").write_text("")
    (driver_root / "bind").write_text("")
    (root / "module/usbip_host").mkdir(parents=True)

    state = tmp_path / "state"
    commands = tmp_path / "commands"
    commands.mkdir()
    export_marker = tmp_path / "exported"
    usbip = commands / "usbip"
    usbip.write_text(
        "#!/usr/bin/env bash\n"
        "case \"$1 ${2:-}\" in\n"
        "  'bind --list') test -f \"$EXPORT_MARKER\" && echo '1-2 test device' ;;\n"
        "  'bind -b') test \"${USBIP_FAIL_BIND:-0}\" = 1 && exit 1; touch \"$EXPORT_MARKER\" ;;\n"
        "  'unbind -b') rm -f \"$EXPORT_MARKER\" ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n"
    )
    usbip.chmod(0o755)
    modprobe = commands / "modprobe"
    modprobe.write_text("#!/usr/bin/env bash\nexit \"${MODPROBE_STATUS:-0}\"\n")
    modprobe.chmod(0o755)
    usbipd = commands / "usbipd"
    usbipd.write_text("#!/usr/bin/env bash\nexit 0\n")
    usbipd.chmod(0o755)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text("")
    routes = tmp_path / "routes"
    routes.write_text("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n")
    env = {
        **os.environ,
        "HARDWARE_SYSFS_ROOT": str(root),
        "HARDWARE_STATE_ROOT": str(state),
        "HARDWARE_LOCK_ROOT": str(tmp_path / "lock"),
        "HARDWARE_USBIP_BIN": str(usbip),
        "HARDWARE_MODPROBE_BIN": str(modprobe),
        "HARDWARE_USBIPD_BIN": str(usbipd),
        "HARDWARE_MOUNTINFO_FILE": str(mountinfo),
        "HARDWARE_ROUTES_FILE": str(routes),
        "EXPORT_MARKER": str(export_marker),
        "KIND_UNDER_TEST": kind,
    }
    return env, device


def _run(env: dict[str, str], *args: str, ack: bool = False) -> subprocess.CompletedProcess[str]:
    command = [str(SCRIPT), *args, "--busid", "1-2", "--vid", "1234", "--pid", "0001",
               "--serial", "LAB-01", "--kind", env["KIND_UNDER_TEST"]]
    if ack:
        command += ["--ack", ACK]
    return subprocess.run(command, env=env, text=True, capture_output=True, check=False)


def test_preflight_rejects_identity_mismatch(tmp_path):
    env, device = _fixture(tmp_path)
    (device / "idProduct").write_text("0002\n")
    result = _run(env, "preflight")
    assert result.returncode != 0
    assert "PID mismatch" in result.stderr


def test_preflight_rejects_hub(tmp_path):
    env, device = _fixture(tmp_path)
    (device / "bDeviceClass").write_text("09\n")
    result = _run(env, "preflight")
    assert result.returncode != 0
    assert "hub" in result.stderr


def test_preflight_rejects_mounted_storage(tmp_path):
    env, device = _fixture(tmp_path, kind="storage")
    block = device.parent / "1-2:1.0/block/sda"
    block.mkdir(parents=True)
    Path(env["HARDWARE_MOUNTINFO_FILE"]).write_text("35 25 8:0 / / rw - /dev/sda ext4 rw\n")
    result = _run(env, "preflight")
    assert result.returncode != 0
    assert "mounted" in result.stderr


def test_preflight_rejects_network_route(tmp_path):
    env, device = _fixture(tmp_path, kind="network")
    net = device.parent / "1-2:1.0/net/usb0"
    net.mkdir(parents=True)
    Path(env["HARDWARE_ROUTES_FILE"]).write_text("usb0 00000000 00000000 0001 0 0 0 00000000 0 0 0\n")
    result = _run(env, "preflight")
    assert result.returncode != 0
    assert "active route" in result.stderr


def test_export_failure_does_not_claim_export(tmp_path):
    env, _ = _fixture(tmp_path)
    env["USBIP_FAIL_BIND"] = "1"
    result = _run(env, "export", ack=True)
    assert result.returncode != 0
    assert not (Path(env["HARDWARE_STATE_ROOT"]) / "1-2.state").exists() or "exported=true" not in (Path(env["HARDWARE_STATE_ROOT"]) / "1-2.state").read_text()


def test_restore_is_idempotent_and_rebinds_recorded_driver(tmp_path):
    env, _ = _fixture(tmp_path)
    exported = _run(env, "export", ack=True)
    assert exported.returncode == 0, exported.stderr
    restored = _run(env, "restore", ack=True)
    assert restored.returncode == 0, restored.stderr
    restored_again = _run(env, "restore", ack=True)
    assert restored_again.returncode == 0, restored_again.stderr
    assert "restore ok" in restored.stdout
    assert "exported=false" in (Path(env["HARDWARE_STATE_ROOT"]) / "1-2.state").read_text()
