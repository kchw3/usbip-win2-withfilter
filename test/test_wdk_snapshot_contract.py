"""Static gate for the WDK descriptor snapshot validation step.

The real `/WX` build requires Visual Studio/WDK. This test keeps the
snapshot-specific source contract and the build script pinned on ordinary CI.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_descriptor_snapshot_registered_before_udecx_create():
    device_cpp = (ROOT / "drivers" / "ude" / "device.cpp").read_text()
    assert "UdecxUsbDeviceInitAddDescriptor(" in device_cpp
    assert "UdecxUsbDeviceInitAddDescriptorWithIndex(" in device_cpp

    add = device_cpp.index("add_snapshot_descriptors(init.ptr, ext.descriptors)")
    create = device_cpp.index("UdecxUsbDeviceCreate(&init.ptr")
    assert add < create


def test_snapshot_published_only_after_all_configurations_validate():
    filter_cpp = (ROOT / "drivers" / "ude" / "device_filter.cpp").read_text()
    loop = filter_cpp.index("for (UINT8 i = 0; i < snapshot.configuration_count; ++i)")
    publish = filter_cpp.index("snapshot.ready = true")
    assert loop < publish


def test_wdk_validation_script_builds_with_warnings_as_errors():
    script = (ROOT / "tools" / "validate_wdk_snapshot.ps1").read_text()
    assert "/p:TreatWarningsAsErrors=true" in script
    assert "/p:WarningsAsErrors=true" in script
    assert "/warnaserror" in script
    assert "drivers\\package\\package.vcxproj" in script
