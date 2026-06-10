"""Heuristic device type detection (phone vs PC, etc.)."""

from __future__ import annotations

import re
from typing import Literal

DeviceKind = Literal["phone", "tablet", "pc", "iot", "router", "unknown"]

_KIND_LABELS: dict[DeviceKind, str] = {
    "phone": "HP",
    "tablet": "Tablet",
    "pc": "PC",
    "iot": "IoT",
    "router": "Router",
    "unknown": "?",
}

_PHONE_HOSTNAME = re.compile(
    r"(iphone|android|galaxy|pixel|redmi|xiaomi|poco|oppo|vivo|realme|"
    r"oneplus|huawei|honor|nokia|motorola|infinix|tecno|phone|mobile|"
    r"sm-[agnpst]\d|rmx\d|cph\d|m\d{4}[a-z]\d)",
    re.I,
)
_TABLET_HOSTNAME = re.compile(r"(ipad|tablet|sm-t\d|tab[\s_-]|lenovo.*tab)", re.I)
_PC_HOSTNAME = re.compile(
    r"(macbook|imac|macmini|mac[\s_-]?pro|mac[\s_-]?studio|desktop|laptop|"
    r"pc[\s_-]|win[\s_-]|windows|thinkpad|surface|nuc|workstation|"
    r"optiplex|latitude|precision|zenbook|vivobook|rog[\s_-])",
    re.I,
)
_IOT_HOSTNAME = re.compile(
    r"(esp[\d_-]|nest|chromecast|roku|alexa|echo|smart[\s_-]|bulb|camera|"
    r"printer|hp[\s_-]?[\da-f]{4}|shelly|tuya|meross|homepod|tv[\s_-]|"
    r"lg[\s_-]?tv|samsung[\s_-]?tv)",
    re.I,
)
_ROUTER_HOSTNAME = re.compile(
    r"(router|gateway|access[\s_-]?point|\bap[\s_-]|wifi|mikrotik|unifi|"
    r"openwrt|tplink|tp[\s_-]?link|asus[\s_-]?rt|netgear|fritz)",
    re.I,
)

_PHONE_VENDORS = (
    "samsung",
    "xiaomi",
    "huawei",
    "oppo",
    "vivo",
    "realme",
    "oneplus",
    "motorola",
    "nokia",
    "honor",
    "google",
    "htc",
    "sony mobile",
    "lg electronics",
    "infinix",
    "tecno",
    "itel",
)

_PC_VENDORS = (
    "dell",
    "hewlett packard",
    "hp inc",
    "lenovo",
    "asustek",
    "micro-star",
    "msi",
    "gigabyte",
    "intel corporate",
    "azurewave",
    "realtek",
    "apple",  # handled separately — Apple bisa HP atau Mac
)

_IOT_VENDORS = (
    "espressif",
    "tuya",
    "shelly",
    "ring",
    "nest",
    "amazon",
    "raspberry pi",
    "philips",
    "sonos",
)

_ROUTER_VENDORS = (
    "cisco",
    "mikrotik",
    "ubiquiti",
    "tp-link",
    "netgear",
    "asus",
    "d-link",
    "linksys",
    "huawei technologies",  # bisa router atau phone — hostname wins
    "zte",
    "fiberhome",
)


def kind_label(kind: DeviceKind) -> str:
    return _KIND_LABELS.get(kind, "?")


def _match_vendor(vendor: str, needles: tuple[str, ...]) -> bool:
    vendor_l = vendor.lower()
    vendor_compact = re.sub(r"[^a-z0-9]", "", vendor_l)
    return any(
        needle in vendor_l or needle.replace(" ", "") in vendor_compact
        for needle in needles
    )


def _classify_apple(hostname: str) -> DeviceKind:
    host = hostname.lower()
    if "iphone" in host:
        return "phone"
    if "ipad" in host:
        return "tablet"
    if any(token in host for token in ("macbook", "imac", "macmini", "mac-", "mac.")):
        return "pc"
    if "appletv" in host or "apple-tv" in host:
        return "iot"
    if "homepod" in host:
        return "iot"
    if "watch" in host:
        return "phone"
    return "unknown"


def classify_device(
    *,
    hostname: str = "",
    vendor: str = "",
    is_gateway: bool = False,
) -> DeviceKind:
    if is_gateway:
        return "router"

    host = hostname.strip()
    host_l = host.lower()
    vendor_l = vendor.strip()

    if host:
        if _ROUTER_HOSTNAME.search(host_l):
            return "router"
        if _TABLET_HOSTNAME.search(host_l):
            return "tablet"
        if _PHONE_HOSTNAME.search(host_l):
            return "phone"
        if _PC_HOSTNAME.search(host_l):
            return "pc"
        if _IOT_HOSTNAME.search(host_l):
            return "iot"

    if vendor_l and "apple" in vendor_l.lower():
        if host:
            return _classify_apple(host_l)
        return "unknown"

    if vendor_l:
        if _match_vendor(vendor_l, _ROUTER_VENDORS):
            return "router"
        if _match_vendor(vendor_l, _IOT_VENDORS):
            return "iot"
        if _match_vendor(vendor_l, _PHONE_VENDORS):
            return "phone"
        if _match_vendor(vendor_l, _PC_VENDORS):
            return "pc"

    return "unknown"
