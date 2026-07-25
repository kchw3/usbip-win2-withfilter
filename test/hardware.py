"""Hardware profile configuration for opt-in USB/IP efficacy tests."""

from __future__ import annotations

import configparser
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


ACK_TEXT = "I_UNDERSTAND_THIS_UNBINDS_A_PHYSICAL_USB_DEVICE"

SUPPORTED_KINDS = {
    "keyboard",
    "storage",
    "network",
    "programmable_hid",
    "composite",
}
KIND_ALIASES = {
    "hid": "keyboard",
    "mass_storage": "storage",
    "nic": "network",
}
SUPPORTED_CATEGORIES = {"hid", "mass_storage", "network", "vendor"}
CATEGORY_ALIASES = {
    "storage": "mass_storage",
    "ms": "mass_storage",
}
SUPPORTED_ORACLES = {
    "keyboard_ready",
    "hid_marker",
    "storage_marker",
    "network_peer",
}
DEFAULT_ORACLES = {
    "keyboard": ("keyboard_ready",),
    "storage": ("storage_marker",),
    "network": ("network_peer",),
    "programmable_hid": ("hid_marker",),
}
ORACLE_CATEGORIES = {
    "keyboard_ready": "hid",
    "hid_marker": "hid",
    "storage_marker": "mass_storage",
    "network_peer": "network",
}
BUSID_RE = re.compile(r"^[0-9]+-[0-9]+(?:\.[0-9]+)*$")
HOOK_ENV = (
    "USBIP_TEST_RUN_ID",
    "USBIP_TEST_TOKEN",
    "USBIP_TEST_BUSID",
    "USBIP_TEST_VID",
    "USBIP_TEST_PID",
)


class HardwareConfigError(ValueError):
    """Raised when the opt-in physical hardware configuration is unsafe."""


@dataclass(frozen=True)
class HardwareProfile:
    name: str
    kind: str
    busid: str
    vid: str
    pid: str
    serial: str | None
    allow_categories: tuple[str, ...]
    oracles: tuple[str, ...]
    artifact_dir: Path
    capture_traffic: bool
    deny_watch_seconds: float
    windows_ipv4: str | None = None
    prefix_length: int | None = None
    peer_ipv4: str | None = None
    peer_tcp_port: int | None = None
    prepare_hook: str | None = None
    trigger_hook: str | None = None

    @property
    def hook_env(self) -> tuple[str, ...]:
        return HOOK_ENV


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _normalize_hex4(value: str, field: str, section: str) -> str:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9a-f]{1,4}", raw):
        raise HardwareConfigError(f"{section}: {field} must be 1-4 hex digits")
    return raw.zfill(4).upper()


def _normalize_kind(value: str, section: str) -> str:
    kind = KIND_ALIASES.get(value.strip().lower(), value.strip().lower())
    if kind not in SUPPORTED_KINDS:
        supported = ", ".join(sorted(SUPPORTED_KINDS | set(KIND_ALIASES)))
        raise HardwareConfigError(f"{section}: unsupported kind {value!r}; use {supported}")
    return kind


def _normalize_categories(value: str, section: str) -> tuple[str, ...]:
    categories = []
    for token in _split_csv(value):
        normalized = CATEGORY_ALIASES.get(token.lower(), token.lower())
        if normalized not in SUPPORTED_CATEGORIES:
            supported = ", ".join(sorted(SUPPORTED_CATEGORIES | set(CATEGORY_ALIASES)))
            raise HardwareConfigError(
                f"{section}: unsupported allow_categories token {token!r}; use {supported}")
        categories.append(normalized)
    unique = tuple(sorted(set(categories)))
    if not unique:
        raise HardwareConfigError(f"{section}: allow_categories must not be empty")
    return unique


def _normalize_oracles(value: str | None, kind: str, section: str) -> tuple[str, ...]:
    if value is None:
        if kind == "composite":
            raise HardwareConfigError(f"{section}: composite profiles must list oracles")
        return DEFAULT_ORACLES[kind]
    oracles = []
    for token in _split_csv(value):
        normalized = token.lower()
        if normalized not in SUPPORTED_ORACLES:
            supported = ", ".join(sorted(SUPPORTED_ORACLES))
            raise HardwareConfigError(
                f"{section}: unsupported oracle {token!r}; use {supported}")
        oracles.append(normalized)
    unique = tuple(sorted(set(oracles)))
    if not unique:
        raise HardwareConfigError(f"{section}: oracles must not be empty")
    return unique


def _validate_busid(value: str, section: str) -> str:
    busid = value.strip()
    if not busid or busid.lower() == "auto" or "*" in busid or "?" in busid:
        raise HardwareConfigError(
            f"{section}: busid must identify one physical device; wildcards/auto are unsafe")
    if not BUSID_RE.fullmatch(busid):
        raise HardwareConfigError(
            f"{section}: busid {busid!r} must look like a physical sysfs busid (for example 1-4)")
    return busid


def _validate_serial(value: str | None, section: str) -> str | None:
    if value is None:
        return None
    serial = value.strip()
    if not serial or serial in {"*", "?", "auto"}:
        raise HardwareConfigError(
            f"{section}: serial must be omitted or be an exact non-wildcard value")
    return serial


def _require(section_data: configparser.SectionProxy, key: str, section: str) -> str:
    if not section_data.get(key, "").strip():
        raise HardwareConfigError(f"{section}: missing required {key}")
    return section_data[key]


def _parse_float(value: str, field: str, section: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise HardwareConfigError(f"{section}: {field} must be a number") from exc
    if parsed <= 0 or parsed > 300:
        raise HardwareConfigError(f"{section}: {field} must be between 0 and 300 seconds")
    return parsed


def _parse_port(value: str, field: str, section: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HardwareConfigError(f"{section}: {field} must be an integer") from exc
    if parsed < 1 or parsed > 65535:
        raise HardwareConfigError(f"{section}: {field} must be between 1 and 65535")
    return parsed


def _parse_prefix(value: str, section: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise HardwareConfigError(f"{section}: prefix_length must be an integer") from exc
    if parsed < 1 or parsed > 32:
        raise HardwareConfigError(f"{section}: prefix_length must be between 1 and 32")
    return parsed


def _validate_ipv4(value: str, field: str, section: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError as exc:
        raise HardwareConfigError(f"{section}: {field} must be an IPv4 address") from exc


def _profile_names(root: configparser.SectionProxy) -> tuple[str, ...]:
    names = _split_csv(root.get("profiles", ""))
    if not names:
        raise HardwareConfigError("[hardware]: profiles must list at least one profile")
    if len(set(names)) != len(names):
        raise HardwareConfigError("[hardware]: profiles must be unique")
    return names


def load_hardware_profiles(
    cp: configparser.ConfigParser,
    *,
    selected: tuple[str, ...] = (),
    artifact_dir: str | None = None,
    capture_traffic: bool = False,
) -> dict[str, HardwareProfile]:
    if "hardware" not in cp:
        raise HardwareConfigError("missing [hardware] configuration")

    root = cp["hardware"]
    configured_names = _profile_names(root)
    selected_set = set(selected)
    unknown = selected_set - set(configured_names)
    if unknown:
        raise HardwareConfigError(
            "unknown --hardware-profile selection(s): " + ", ".join(sorted(unknown)))
    names = tuple(name for name in configured_names if not selected_set or name in selected_set)
    root_artifact_dir = Path(artifact_dir or root.get("artifact_dir", "artifacts/hardware"))
    root_capture = root.getboolean("capture_traffic", fallback=False)
    effective_capture = root_capture or bool(capture_traffic)
    root_deny_watch = _parse_float(
        root.get("deny_watch_seconds", "15"), "deny_watch_seconds", "[hardware]")

    profiles: dict[str, HardwareProfile] = {}
    seen_busids: dict[str, str] = {}
    for name in names:
        section = f"hardware:{name}"
        if section not in cp:
            raise HardwareConfigError(f"missing [{section}] for profile {name!r}")
        data = cp[section]
        kind = _normalize_kind(_require(data, "kind", section), section)
        busid = _validate_busid(_require(data, "busid", section), section)
        if busid in seen_busids:
            raise HardwareConfigError(
                f"{section}: busid {busid!r} is already used by profile {seen_busids[busid]!r}")
        seen_busids[busid] = name

        if data.get("confirm_physical_unbind", "").strip() != ACK_TEXT:
            raise HardwareConfigError(
                f"{section}: confirm_physical_unbind must equal {ACK_TEXT}")

        vid = _normalize_hex4(_require(data, "vid", section), "vid", section)
        pid = _normalize_hex4(_require(data, "pid", section), "pid", section)
        serial = _validate_serial(data.get("serial"), section)
        categories = _normalize_categories(_require(data, "allow_categories", section), section)
        oracles = _normalize_oracles(data.get("oracles"), kind, section)
        missing_categories = sorted(
            ORACLE_CATEGORIES[oracle] for oracle in oracles
            if ORACLE_CATEGORIES[oracle] not in categories)
        if missing_categories:
            raise HardwareConfigError(
                f"{section}: allow_categories missing oracle-required token(s): "
                + ", ".join(sorted(set(missing_categories))))

        profile_artifact_dir = Path(data.get("artifact_dir", str(root_artifact_dir)))
        deny_watch = _parse_float(
            data.get("deny_watch_seconds", str(root_deny_watch)),
            "deny_watch_seconds", section)

        windows_ipv4 = prefix_length = peer_ipv4 = peer_tcp_port = None
        if "network_peer" in oracles:
            windows_ipv4 = _validate_ipv4(
                _require(data, "windows_ipv4", section), "windows_ipv4", section)
            peer_ipv4 = _validate_ipv4(
                _require(data, "peer_ipv4", section), "peer_ipv4", section)
            prefix_length = _parse_prefix(_require(data, "prefix_length", section), section)
            peer_tcp_port = _parse_port(
                _require(data, "peer_tcp_port", section), "peer_tcp_port", section)

        prepare_hook = data.get("prepare_hook", fallback=None)
        trigger_hook = data.get("trigger_hook", fallback=None)
        if "hid_marker" in oracles and not trigger_hook:
            raise HardwareConfigError(f"{section}: hid_marker requires trigger_hook")

        profiles[name] = HardwareProfile(
            name=name,
            kind=kind,
            busid=busid,
            vid=vid,
            pid=pid,
            serial=serial,
            allow_categories=categories,
            oracles=oracles,
            artifact_dir=profile_artifact_dir,
            capture_traffic=effective_capture,
            deny_watch_seconds=deny_watch,
            windows_ipv4=windows_ipv4,
            prefix_length=prefix_length,
            peer_ipv4=peer_ipv4,
            peer_tcp_port=peer_tcp_port,
            prepare_hook=prepare_hook,
            trigger_hook=trigger_hook,
        )
    return profiles
