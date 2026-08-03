from __future__ import annotations

import configparser

import pytest

from conftest import hardware_script_command
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
