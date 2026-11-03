from __future__ import annotations

import ipaddress
import re


def fail():
    raise ValueError("配置内容不符合要求，请检查填写项")


def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        fail()


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        fail()


def boolean(value):
    if type(value) is not bool:
        fail()


def email(value, notification=False):
    if not isinstance(value, str) or len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value):
        fail()
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or (notification and value.startswith("-")):
        fail()
    hostname(domain, ip_allowed=False)


def hostname(value, ip_allowed=True):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        fail()
    if ip_allowed:
        try:
            ipaddress.ip_address(value)
            return
        except ValueError:
            pass
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in value.split(".")):
        fail()


def monitor(value):
    exact_keys(value, {"revision", "enabled", "missed_runs", "grace_minutes", "expiry_hours"})
    if not isinstance(value["revision"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["revision"]):
        fail()
    boolean(value["enabled"])
    integer(value["missed_runs"], 1, 6)
    integer(value["grace_minutes"], 5, 120)
    integer(value["expiry_hours"], 1, 168)
    return value


def settings(value):
    exact_keys(value, {"revision", "certificate_id", "email", "renew_before_days", "probes", "schedule", "notifications"}, {"secret_id", "secret_key"})
    if not isinstance(value["revision"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["revision"]):
        fail()
    if not isinstance(value["certificate_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value["certificate_id"]):
        fail()
    email(value["email"])
    integer(value["renew_before_days"], 1, 30)
    probes = value["probes"]
    if not isinstance(probes, list) or not 1 <= len(probes) <= 8:
        fail()
    for probe in probes:
        exact_keys(probe, {"host", "port", "server_name"})
        hostname(probe["host"])
        hostname(probe["server_name"], ip_allowed=False)
        integer(probe["port"], 1, 65535)
    schedule = value["schedule"]
    exact_keys(schedule, {"enabled", "mode", "interval_hours", "hour", "minute"})
    boolean(schedule["enabled"])
    if schedule["mode"] not in ("hourly", "daily", "adaptive"):
        fail()
    integer(schedule["interval_hours"], 1, 12)
    if schedule["interval_hours"] not in (1, 2, 3, 4, 6, 8, 12):
        fail()
    if schedule["mode"] == "adaptive" and schedule["interval_hours"] != 1:
        fail()
    integer(schedule["hour"], 0, 23)
    integer(schedule["minute"], 0, 59)
    notifications = value["notifications"]
    exact_keys(notifications, {"success_enabled", "success_email", "failure_enabled", "failure_email"})
    for prefix in ("success", "failure"):
        boolean(notifications[prefix + "_enabled"])
        address = notifications[prefix + "_email"]
        if notifications[prefix + "_enabled"] or address != "":
            email(address, notification=True)
    for key in ("secret_id", "secret_key"):
        item = value.get(key, "")
        if not isinstance(item, str) or len(item) > 256 or (item and not re.fullmatch(r"[A-Za-z0-9_+/=-]+", item)):
            fail()
    if bool(value.get("secret_id")) != bool(value.get("secret_key")):
        fail()
    return value
