#!/usr/bin/env python3
"""Offline checks for the SOC Home Lab repository (no Wazuh server required)."""
from __future__ import annotations

import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
RULES = {
    "soc_lab_fim_rules.xml": ("100100", "10"),
    "soc_lab_sudo_rules.xml": ("100101", "8"),
    "100102-soc-lab-exec.xml": ("100102", "5"),
    "100103-soc-lab-cron.xml": ("100103", "8"),
    "100104-soc-lab-correlation.xml": ("100104", "10"),
    "100105-soc-lab-identity.xml": ("100105", "8"),
    "100106-soc-lab-sudoers.xml": ("100106", "9"),
}
AUDIT_FILES = {
    "50-soc-lab-exec.rules": ({"/usr/bin/id"}, "soc_lab_exec_test", "x"),
    "60-soc-lab-cron.rules": (
        {"/etc/crontab", "/etc/cron.d", "/etc/cron.daily"},
        "soc_lab_cron_change", "wa"
    ),
    "70-soc-lab-identity.rules": (
        {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"},
        "soc_lab_identity_change", "wa"
    ),
    "80-soc-lab-sudoers.rules": (
        {"/etc/sudoers", "/etc/sudoers.d"},
        "soc_lab_sudoers_change", "wa"
    ),
}
LINK = re.compile(r"!?(?:\[[^\]]*\])\(([^)]+)\)")
PNG_HEADER = b"\x89PNG\r\n\x1a\n"


def check_xml(errors: list[str]) -> int:
    seen = set()
    for filename, (expected_id, expected_level) in RULES.items():
        path = ROOT / "detection-rules" / filename
        if not path.is_file():
            errors.append(f"Missing rule file: {path.relative_to(ROOT)}")
            continue
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            errors.append(f"Invalid XML in {filename}: {exc}")
            continue
        rules = root.findall("rule")
        if root.tag != "group" or len(rules) != 1:
            errors.append(f"{filename}: expected one rule inside a group")
            continue
        rule = rules[0]
        rid, level = rule.get("id"), rule.get("level")
        if (rid, level) != (expected_id, expected_level):
            errors.append(f"{filename}: expected id={expected_id}, level={expected_level}; got {rid}/{level}")
        if rid in seen:
            errors.append(f"Duplicate rule ID {rid}")
        seen.add(rid)
        if not (rule.findtext("if_sid") or rule.findtext("if_matched_sid")):
            errors.append(f"{filename}: no parent rule reference")
        if not rule.findtext("description"):
            errors.append(f"{filename}: missing description")
    return len(seen)


def check_audit_rules(errors: list[str]) -> int:
    total = 0
    for filename, (paths, expected_key, expected_perms) in AUDIT_FILES.items():
        path = ROOT / "detection-rules" / filename
        if not path.is_file():
            errors.append(f"Missing auditd configuration: {filename}")
            continue
        lines = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        found = set()
        for line in lines:
            match = re.fullmatch(r"-w (\S+) -p (x|wa) -k (\S+)", line)
            if not match:
                errors.append(f"{filename}: unexpected audit watch: {line}")
                continue
            target, perms, key = match.groups()
            if target in found or key != expected_key or perms != expected_perms:
                errors.append(f"{filename}: duplicate path or wrong audit key: {line}")
            found.add(target)
        if found != paths:
            errors.append(f"{filename}: path mismatch: missing={paths - found}, extra={found - paths}")
        total += len(lines)
    return total


def check_links(errors: list[str]) -> int:
    count = 0
    for file in ROOT.rglob("*.md"):
        if ".git" in file.parts:
            continue
        body = file.read_text(encoding="utf-8-sig")
        for match in LINK.finditer(body):
            url = match.group(1).strip().split(' "', 1)[0].strip("<>")
            if url.startswith("#") or urlsplit(url).scheme or url.startswith("//"):
                continue
            target = (file.parent / unquote(url.split("#", 1)[0].split("?", 1)[0])).resolve()
            count += 1
            try:
                target.relative_to(ROOT)
            except ValueError:
                errors.append(f"{file.relative_to(ROOT)}: link escapes repository: {url}")
                continue
            if not target.exists():
                errors.append(f"{file.relative_to(ROOT)}: missing link target {url}")
    return count


def check_pngs(errors: list[str]) -> int:
    count = 0
    for path in (ROOT / "evidence").glob("*.png"):
        count += 1
        data = path.read_bytes()
        if not data.startswith(PNG_HEADER):
            errors.append(f"{path.name}: invalid PNG signature")
            continue
        pos, got_ihdr, got_iend = 8, False, False
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            end = pos + 12 + length
            if end > len(data):
                errors.append(f"{path.name}: truncated PNG chunk")
                break
            kind = data[pos + 4:pos + 8]
            payload = data[pos + 8:pos + 8 + length]
            crc = struct.unpack(">I", data[end - 4:end])[0]
            if zlib.crc32(kind + payload) & 0xFFFFFFFF != crc:
                errors.append(f"{path.name}: invalid PNG chunk CRC")
                break
            if kind == b"IHDR":
                got_ihdr = True
                if length != 13 or not all(struct.unpack(">II", payload[:8])):
                    errors.append(f"{path.name}: invalid PNG dimensions")
            if kind == b"IEND":
                got_iend = True
                break
            pos = end
        if not (got_ihdr and got_iend):
            errors.append(f"{path.name}: incomplete PNG")
    if count < 14:
        errors.append(f"Expected at least 14 archived evidence PNGs, found {count}")
    return count


def main() -> int:
    errors: list[str] = []
    nrules = check_xml(errors)
    nwatches = check_audit_rules(errors)
    nlinks = check_links(errors)
    npngs = check_pngs(errors)
    print(f"Checked {nrules} rule IDs, {nwatches} archived account/sudoers watches, "
          f"{nlinks} relative links and {npngs} PNG images.")
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("Repository structural checks passed.")
    print("Note: live Wazuh rule semantics, network access and endpoint status are NOT tested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
