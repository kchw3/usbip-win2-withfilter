from __future__ import annotations

import configparser
import shlex

import pytest

from conftest import hardware_hook_command, hardware_script_command
from hardware import load_hardware_profiles
from test_hardware_profiles import BASE


def test_hardware_script_command_is_explicit_and_shell_quoted():
    cp = configparser.ConfigParser()
    cp.read_string(BASE)
    profile = load_hardware_profiles(cp)["storage"]

    command = hardware_script_command("/opt/lab test/linux", "export", profile)

    assert command.startswith("bash '/opt/lab test/linux/hardware_device.sh' export ")
    assert "--busid 1-3" in command
    assert "--vid 1234" in command
    assert "--pid 0002" in command
    assert "--serial LAB-STORAGE-01" in command
    assert "I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE" in command


def test_hardware_script_command_rejects_unknown_action():
    cp = configparser.ConfigParser()
    cp.read_string(BASE)
    profile = load_hardware_profiles(cp)["keyboard"]

    with pytest.raises(ValueError, match="unsupported hardware lifecycle action"):
        hardware_script_command("/opt/test/linux", "attach", profile)


def test_hardware_hook_command_exposes_only_fixed_run_variables():
    token = "tok'1"
    command = hardware_hook_command(
        "/opt/lab hardware/trigger.sh", run_id="run 1", token=token,
        busid="1-5", vid="1209", pid="0001",
    )

    assert command.startswith("env -i USBIP_TEST_RUN_ID='run 1'")
    assert f"USBIP_TEST_TOKEN={shlex.quote(token)}" in command
    assert "USBIP_TEST_BUSID=1-5" in command
    assert "USBIP_TEST_VID=1209" in command
    assert "USBIP_TEST_PID=0001" in command
    assert command.endswith("bash '/opt/lab hardware/trigger.sh'")
    assert "PATH=" not in command
