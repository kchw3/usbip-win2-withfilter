#!/usr/bin/env python3
"""Interactive Linux preflight wrapper for test/test_connectivity.py.

This script keeps prompts and verbose Linux module setup outside pytest capture,
then runs the normal connectivity test once the lab prerequisites are ready.
"""

from __future__ import annotations

import argparse
import configparser
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("config.ini")
DEFAULT_PYTEST_ARGS = [str(Path(__file__).with_name("test_connectivity.py")), "-v"]


def _load_config() -> configparser.ConfigParser:
    if not CONFIG_PATH.exists():
        raise SystemExit(f"{CONFIG_PATH} not found; copy test/config.example.ini to test/config.ini first")
    cp = configparser.ConfigParser()
    cp.read(CONFIG_PATH)
    for section, keys in {
        "linux": ("host", "user", "test_dir"),
        "server": ("address",),
    }.items():
        if not cp.has_section(section):
            raise SystemExit(f"config.ini is missing [{section}]")
        for key in keys:
            if not cp.has_option(section, key) or not cp[section][key]:
                raise SystemExit(f"config.ini [{section}] is missing a value for {key!r}")
    return cp


def _connect(cp: configparser.ConfigParser):
    import paramiko

    s = cp["linux"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {"username": s["user"]}
    if s.get("password"):
        kwargs["password"] = s["password"]
    if s.get("key_filename"):
        kwargs["key_filename"] = os.path.expanduser(s["key_filename"])
    print(f"[linux] connecting to {s['user']}@{s['host']} ...")
    client.connect(s["host"], timeout=10, **kwargs)
    print("[linux] SSH connected")
    return client


def _ssh_run(client, cmd: str, *, timeout: int = 30) -> tuple[int, str, str]:
    _in, out, err = client.exec_command(cmd, timeout=timeout)
    rc = out.channel.recv_exit_status()
    return rc, out.read().decode(), err.read().decode()


def _linux_uses_vudc(cp: configparser.ConfigParser) -> bool:
    return "vudc" in cp["linux"].get("udc_name", "usbip-vudc.0")


def _diagnose_script(cp: configparser.ConfigParser) -> str:
    udc = cp["linux"].get("udc_name", "usbip-vudc.0")
    need_device_mode = "1" if _linux_uses_vudc(cp) else "0"
    return textwrap.dedent(f"""
        set -u
        udc={shlex.quote(udc)}
        need_device_mode={need_device_mode}
        issue() {{ printf 'ISSUE|%s\n' "$*"; }}
        ok() {{ printf 'OK|%s\n' "$*"; }}

        if [ -d /sys/kernel/config/usb_gadget ]; then
          ok "libcomposite: /sys/kernel/config/usb_gadget exists"
        else
          issue "libcomposite: /sys/kernel/config/usb_gadget is absent"
        fi

        if [ -e "/sys/class/udc/$udc" ]; then
          ok "udc: /sys/class/udc/$udc exists"
        else
          issue "udc: /sys/class/udc/$udc is absent"
        fi

        if [ -e /dev/raw-gadget ]; then
          ok "raw_gadget: /dev/raw-gadget exists"
        else
          issue "raw_gadget: /dev/raw-gadget is absent"
        fi

        if ls /sys/class/udc/dummy* >/dev/null 2>&1 || [ -e /sys/bus/platform/devices/dummy_hcd.0 ]; then
          ok "dummy_hcd: dummy UDC detected"
        else
          issue "dummy_hcd: no dummy UDC detected"
        fi

        device_mode() {{
          pgrep -af usbipd | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'
        }}
        if [ "$need_device_mode" = 1 ]; then
          if device_mode; then
            ok "usbipd: device-mode daemon found"
          else
            issue "usbipd: no device-mode daemon found"
          fi
        else
          ok "usbipd: device-mode check not required for udc=$udc"
        fi
    """)


def _fix_script(cp: configparser.ConfigParser) -> str:
    need_device_mode = "1" if _linux_uses_vudc(cp) else "0"
    return textwrap.dedent(f"""
        set -u
        need_device_mode={need_device_mode}
        failed=0

        log() {{ printf '[fix] %s\n' "$*"; }}
        as_root() {{
          if [ "$(id -u)" -eq 0 ]; then
            "$@"
          else
            sudo -n "$@"
          fi
        }}
        module_loaded() {{ lsmod | awk '{{print $1}}' | grep -qx "$1"; }}

        ensure_configfs() {{
          if mountpoint -q /sys/kernel/config 2>/dev/null; then
            log "configfs: already mounted"
          else
            log "configfs: not mounted; mounting..."
            if as_root mount -t configfs none /sys/kernel/config; then
              log "configfs: mount success"
            else
              log "configfs: mount FAILED"
              failed=1
            fi
          fi
        }}

        load_module() {{
          module=$1
          required=$2
          if module_loaded "$module"; then
            log "$module: already loaded"
            return 0
          fi
          log "$module: not loaded; loading..."
          if as_root modprobe "$module"; then
            if module_loaded "$module"; then
              log "$module: load success"
            else
              log "$module: modprobe returned success but lsmod does not show it"
            fi
            return 0
          fi
          if [ "$required" = 1 ]; then
            log "$module: load FAILED"
            failed=1
          else
            log "$module: load failed or unavailable (optional for this config)"
          fi
          return 0
        }}

        load_vudc() {{
          required=$1
          if module_loaded usbip_vudc || [ -e /sys/class/udc/usbip-vudc.0 ]; then
            log "usbip-vudc: already loaded/present"
            return 0
          fi
          log "usbip-vudc: not found; loading usbip_vudc..."
          if as_root modprobe usbip_vudc; then
            log "usbip-vudc: load success via usbip_vudc"
            return 0
          fi
          log "usbip-vudc: usbip_vudc failed; trying usbip-vudc..."
          if as_root modprobe usbip-vudc; then
            log "usbip-vudc: load success via usbip-vudc"
            return 0
          fi
          if [ "$required" = 1 ]; then
            log "usbip-vudc: load FAILED"
            failed=1
          else
            log "usbip-vudc: load failed or unavailable (optional for this config)"
          fi
        }}

        ensure_device_mode_usbipd() {{
          device_mode() {{ pgrep -af usbipd | grep -qE -- '(^|[[:space:]])(-e|--device)([[:space:]]|$)'; }}
          if device_mode; then
            log "usbipd: already running in device mode"
            return 0
          fi
          if pgrep -x usbipd >/dev/null; then
            log "usbipd: running, but not in device mode; stopping..."
            if as_root pkill -x usbipd; then
              log "usbipd: stopped existing daemon"
            else
              log "usbipd: failed to stop existing daemon"
              failed=1
            fi
            sleep 0.5
          else
            log "usbipd: not running"
          fi
          log "usbipd: starting device mode with 'usbipd --device -D'..."
          if as_root usbipd --device -D; then
            sleep 0.5
            if device_mode; then
              log "usbipd: device-mode start success"
            else
              log "usbipd: command returned success but device-mode daemon was not found"
              failed=1
            fi
          else
            log "usbipd: device-mode start FAILED"
            failed=1
          fi
        }}

        ensure_configfs
        load_module libcomposite 1
        load_vudc "$need_device_mode"
        load_module raw_gadget 1
        load_module dummy_hcd 0
        if [ "$need_device_mode" = 1 ]; then
          ensure_device_mode_usbipd
        else
          log "usbipd: device mode not required for this UDC"
        fi

        if [ "$failed" = 0 ]; then
          log "Linux USB/IP preflight fix completed"
        else
          log "Linux USB/IP preflight fix completed with failures"
        fi
        exit "$failed"
    """)


def _run_diagnosis(client, cp: configparser.ConfigParser) -> list[str]:
    rc, out, err = _ssh_run(client, f"bash -c {shlex.quote(_diagnose_script(cp))}")
    if rc != 0:
        raise RuntimeError(f"diagnosis failed with rc={rc}\nstdout:\n{out}\nstderr:\n{err}")
    issues: list[str] = []
    for line in out.splitlines():
        if line.startswith("OK|"):
            print(f"[check] OK: {line[3:]}")
        elif line.startswith("ISSUE|"):
            issue = line[6:]
            issues.append(issue)
            print(f"[check] ISSUE: {issue}")
        elif line.strip():
            print(f"[check] {line}")
    return issues


def _confirm(issues: list[str], *, assume_yes: bool, no_fix: bool) -> bool:
    if not issues:
        return False
    if no_fix:
        print("[linux] --no-fix set; leaving issues for pytest to report")
        return False
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise SystemExit("Linux preflight has issues but stdin is not interactive; re-run with --yes to apply fixes")
    print("\nLinux USB/IP prerequisites need attention:")
    for issue in issues:
        print(f"  - {issue}")
    answer = input("\nApply the verbose Linux-side fix over SSH now? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _run_fix(client, cp: configparser.ConfigParser) -> None:
    print("[linux] applying preflight fix ...")
    rc, out, err = _ssh_run(client, f"bash -c {shlex.quote(_fix_script(cp))}", timeout=60)
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)
    if rc != 0:
        raise SystemExit(f"Linux preflight fix failed with rc={rc}")


def _pytest_cmd(args: list[str]) -> list[str]:
    return [sys.executable, "-m", "pytest", *(args or DEFAULT_PYTEST_ARGS)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight Linux USB/IP modules, then run connectivity tests")
    parser.add_argument("--yes", action="store_true", help="apply Linux preflight fixes without prompting")
    parser.add_argument("--no-fix", action="store_true", help="diagnose only; do not apply Linux fixes")
    parser.add_argument("--skip-pytest", action="store_true", help="run only the Linux preflight/fix")
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER,
                        help="optional pytest args after --; defaults to test/test_connectivity.py -v")
    ns = parser.parse_args(argv)
    pytest_args = ns.pytest_args[1:] if ns.pytest_args[:1] == ["--"] else ns.pytest_args

    cp = _load_config()
    client = _connect(cp)
    try:
        issues = _run_diagnosis(client, cp)
        if _confirm(issues, assume_yes=ns.yes, no_fix=ns.no_fix):
            _run_fix(client, cp)
            print("[linux] re-checking after fix ...")
            issues = _run_diagnosis(client, cp)
            if issues:
                print("[linux] remaining issues after fix:")
                for issue in issues:
                    print(f"  - {issue}")
        if ns.skip_pytest:
            return 1 if issues else 0
    finally:
        client.close()

    cmd = _pytest_cmd(pytest_args)
    print(f"[pytest] running: {shlex.join(cmd)}")
    env = os.environ.copy()
    env.setdefault("USBIP_TEST_AUTO_FIX", "0")
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
