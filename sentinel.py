
"""
Smartbox Sentinel PoC
A single-file desktop dashboard for hackathon demos.

Runs with: python sentinel.py
Builds on Windows with: pyinstaller --onefile --windowed --name SmartboxSentinel sentinel.py

No third-party runtime dependencies required. Optional real connectors use stdlib urllib.
"""

import base64
import ctypes
import ctypes.wintypes
import datetime as dt
import json
import math
import os
import queue
import random
import threading
import time
import traceback
import urllib.parse
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "Smartbox Security Dasher 3000"
CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SmartboxSentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"

BG = "#0A0C10"
PANEL = "#141922"
PANEL_2 = "#1B2430"
TEXT = "#F7F8FA"
MUTED = "#9BA6B6"
BLUE = "#7CC7FF"
GREEN = "#63E6BE"
AMBER = "#FFD166"
RED = "#FF6B81"
PURPLE = "#C7A7FF"
GLASS = "#10151D"
HAIRLINE = "#242D3A"


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def clamp(n, lo, hi):
    return max(lo, min(hi, n))


def safe_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


def compact_json_sample(obj, limit=2):
    """Return a small serialisable sample from a list/dict for debug export."""
    if isinstance(obj, list):
        return obj[:limit]
    if isinstance(obj, dict):
        return obj
    return obj


class SecretBox:
    """Tiny DPAPI wrapper on Windows. Falls back to base64 elsewhere for demo portability."""

    @staticmethod
    def protect(value: str) -> str:
        if not value:
            return ""
        if os.name != "nt":
            return "b64:" + base64.b64encode(value.encode()).decode()
        try:
            return "dpapi:" + SecretBox._dpapi(value.encode(), protect=True)
        except Exception:
            return "b64:" + base64.b64encode(value.encode()).decode()

    @staticmethod
    def unprotect(value: str) -> str:
        if not value:
            return ""
        if value.startswith("b64:"):
            return base64.b64decode(value[4:].encode()).decode()
        if value.startswith("dpapi:") and os.name == "nt":
            try:
                return SecretBox._dpapi(base64.b64decode(value[6:].encode()), protect=False).decode()
            except Exception:
                return ""
        return value

    @staticmethod
    def _dpapi(data, protect=True):
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def blob_from_bytes(b):
            buf = ctypes.create_string_buffer(b)
            return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

        in_blob, keepalive = blob_from_bytes(data)
        out_blob = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        if protect:
            ok = crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
        else:
            ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))

        if not ok:
            raise ctypes.WinError()
        try:
            out = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return base64.b64encode(out).decode() if protect else out
        finally:
            kernel32.LocalFree(out_blob.pbData)


class Config:
    defaults = {
        "demo_mode": False,
        "poll_seconds": 8,
        "microsoft": {"tenant_id": "", "client_id": "", "client_secret": "", "defender_api_url": "https://api.securitycenter.microsoft.com", "enabled": False},
        "unifi": {"base_url": "https://api.ui.com", "api_key": "", "site_id": "", "alerts_path": "", "site_health_path": "", "site_name_map": "", "enabled": False},
        "datto": {"api_url": "", "access_token": "", "enabled": False},
        "rocketcyber": {"base_url": "https://api-us.rocketcyber.com", "api_key": "", "enabled": False},
    }

    @classmethod
    def load(cls):
        if not CONFIG_FILE.exists():
            return json.loads(json.dumps(cls.defaults))
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        merged = json.loads(json.dumps(cls.defaults))
        cls._merge(merged, data)
        for section in ("microsoft", "unifi", "datto", "rocketcyber"):
            for key in ("client_secret", "api_key", "access_token"):
                if key in merged.get(section, {}):
                    merged[section][key] = SecretBox.unprotect(merged[section].get(key, ""))
        return merged

    @staticmethod
    def _merge(a, b):
        for k, v in b.items():
            if isinstance(v, dict) and isinstance(a.get(k), dict):
                Config._merge(a[k], v)
            else:
                a[k] = v

    @classmethod
    def save(cls, data):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        copy = json.loads(json.dumps(data))
        for section in ("microsoft", "unifi", "datto", "rocketcyber"):
            for key in ("client_secret", "api_key", "access_token"):
                if key in copy.get(section, {}):
                    copy[section][key] = SecretBox.protect(copy[section].get(key, ""))
        CONFIG_FILE.write_text(json.dumps(copy, indent=2), encoding="utf-8")


class Http:
    @staticmethod
    def request(method, url, headers=None, body=None, timeout=12):
        headers = headers or {}
        data = None
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(body, (bytes, bytearray)):
            data = body
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            raw = res.read().decode("utf-8", errors="replace")
            if not raw:
                return {}
            return json.loads(raw)


class MicrosoftGraphConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tokens = {}
        self.token_expiry = {}
        self.status = "idle"

    def enabled(self):
        c = self.cfg["microsoft"]
        return c.get("enabled") and c.get("tenant_id") and c.get("client_id") and c.get("client_secret")

    def get_token(self, scope="https://graph.microsoft.com/.default"):
        if self.tokens.get(scope) and time.time() < self.token_expiry.get(scope, 0) - 120:
            return self.tokens[scope]
        c = self.cfg["microsoft"]
        url = f"https://login.microsoftonline.com/{c['tenant_id']}/oauth2/v2.0/token"
        body = {
            "client_id": c["client_id"],
            "client_secret": c["client_secret"],
            "grant_type": "client_credentials",
            "scope": scope,
        }
        data = Http.request("POST", url, body=body)
        self.tokens[scope] = data["access_token"]
        self.token_expiry[scope] = time.time() + int(data.get("expires_in", 3600))
        return self.tokens[scope]

    def graph_get_all(self, url, headers, max_pages=100):
        """Read all pages from Microsoft Graph using @odata.nextLink."""
        items = []
        next_url = url
        pages = 0
        while next_url and pages < max_pages:
            data = Http.request("GET", next_url, headers=headers)
            batch = data.get("value", [])
            if isinstance(batch, list):
                items.extend(batch)
            next_url = data.get("@odata.nextLink")
            pages += 1
        return items

    def defender_get_all(self, url, headers, max_pages=20):
        """Read Microsoft Defender for Endpoint API pages using @odata.nextLink."""
        items = []
        next_url = url
        pages = 0
        while next_url and pages < max_pages:
            data = Http.request("GET", next_url, headers=headers)
            batch = data.get("value", [])
            if isinstance(batch, list):
                items.extend(batch)
            next_url = data.get("@odata.nextLink")
            pages += 1
        return items

    def classify_os(self, device):
        raw = str(device.get("operatingSystem") or device.get("osVersion") or "").lower()
        if "windows" in raw:
            return "windows"
        if "mac" in raw or "darwin" in raw:
            return "macos"
        if "ipad" in raw or "iphone" in raw or raw == "ios" or "ios" in raw:
            return "ios"
        if "android" in raw:
            return "android"
        return "other"


    def is_alert_active(self, alert):
        raw = " ".join([
            str(alert.get("status") or ""),
            str(alert.get("classification") or ""),
            str(alert.get("determination") or ""),
            str(alert.get("assignedTo") or ""),
        ]).lower()
        resolved_words = ("resolved", "dismissed", "closed", "remediated", "benignpositive", "falsepositive", "suppressed")
        return not any(word in raw for word in resolved_words)


    def fetch(self):
        if not self.enabled():
            return None

        graph_token = self.get_token("https://graph.microsoft.com/.default")
        graph_headers = {"Authorization": f"Bearer {graph_token}", "Accept": "application/json"}

        # Full paged Intune inventory and Graph security alerts.
        devices_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=100"
        graph_alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100"

        # Dedicated Defender for Endpoint API. This normally needs Defender API permissions on the app:
        # Alert.Read.All and optionally Machine.Read.All for deeper enrichment later.
        defender_base = self.cfg["microsoft"].get("defender_api_url", "https://api.securitycenter.microsoft.com").rstrip("/")
        defender_alerts_url = f"{defender_base}/api/alerts?$top=100"

        devices = []
        graph_alerts = []
        defender_alerts = []
        events = []

        device_error = None
        graph_alert_error = None
        defender_alert_error = None

        try:
            devices = self.graph_get_all(devices_url, headers=graph_headers, max_pages=100)
        except Exception as e:
            device_error = str(e)
            events.append({
                "severity": "medium",
                "title": "Microsoft Intune device query failed",
                "detail": device_error[:180],
                "source": "Microsoft Graph",
            })

        try:
            graph_alerts = self.graph_get_all(graph_alerts_url, headers=graph_headers, max_pages=20)
        except Exception as e:
            graph_alert_error = str(e)
            events.append({
                "severity": "medium",
                "title": "Microsoft Graph security alerts query failed",
                "detail": graph_alert_error[:180],
                "source": "Graph Security",
            })

        try:
            defender_token = self.get_token("https://api.securitycenter.microsoft.com/.default")
            defender_headers = {"Authorization": f"Bearer {defender_token}", "Accept": "application/json"}
            defender_alerts = self.defender_get_all(defender_alerts_url, headers=defender_headers, max_pages=20)
        except Exception as e:
            defender_alert_error = str(e)
            hint = defender_alert_error[:180]
            if "403" in defender_alert_error or "Forbidden" in defender_alert_error:
                hint = "403 Forbidden: add WindowsDefenderATP application permission Alert.Read.All, grant admin consent, and verify the Defender API URL/region."
            events.append({
                "severity": "medium",
                "title": "Microsoft Defender alert query failed",
                "detail": hint,
                "source": "Defender for Endpoint",
            })

        if device_error and graph_alert_error and defender_alert_error:
            raise RuntimeError(
                f"Microsoft failed. Intune: {device_error[:100]} | Graph alerts: {graph_alert_error[:100]} | Defender: {defender_alert_error[:100]}"
            )

        os_counts = {"windows": 0, "ios": 0, "macos": 0, "android": 0, "other": 0}
        for device in devices:
            os_counts[self.classify_os(device)] += 1

        noncompliant = [
            d for d in devices
            if str(d.get("complianceState", "")).lower() not in ("compliant", "unknown", "")
        ]

        graph_active = [a for a in graph_alerts if self.is_alert_active(a)]
        defender_active = [a for a in defender_alerts if self.is_alert_active(a)]
        graph_resolved = max(0, len(graph_alerts) - len(graph_active))
        defender_resolved = max(0, len(defender_alerts) - len(defender_active))

        graph_high = [
            a for a in graph_active
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]
        defender_high = [
            a for a in defender_active
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]

        # Defender signal feed first, then Graph security, then inventory.
        for a in defender_active[:25]:
            sev = str(a.get("severity", "medium")).lower()
            status = a.get("status") or a.get("classification") or "unknown"
            device = a.get("computerDnsName") or a.get("machineId") or "unknown device"
            events.append({
                "severity": "critical" if sev in ("high", "critical") else "medium" if sev == "medium" else "info",
                "title": a.get("title", "Microsoft Defender alert"),
                "detail": f"{device} | {status} | {a.get('category', 'Defender')}",
                "source": "Defender for Endpoint",
            })

        for a in graph_active[:10]:
            events.append({
                "severity": "critical" if str(a.get("severity", "")).lower() in ("high", "critical") else "medium",
                "title": a.get("title", "Microsoft security alert"),
                "detail": f"{a.get('serviceSource', 'Graph')} | {a.get('status', 'unknown')}",
                "source": "Graph Security",
            })

        events.insert(0, {
            "severity": "info",
            "title": "Full Intune inventory loaded",
            "detail": f"{len(devices)} devices: Windows {os_counts['windows']}, iOS/iPadOS {os_counts['ios']}, macOS {os_counts['macos']}, Android {os_counts['android']}, Other {os_counts['other']}",
            "source": "Microsoft Graph",
        })

        if defender_alerts:
            events.insert(1, {
                "severity": "critical" if defender_high else "medium",
                "title": "Microsoft Defender alerts live",
                "detail": f"{len(defender_active)} active Defender alert(s), {defender_resolved} resolved/closed returned, {len(defender_high)} high/critical active.",
                "source": "Defender for Endpoint",
            })

        total_alerts_returned = len(graph_alerts) + len(defender_alerts)
        total_active_alerts = len(graph_active) + len(defender_active)
        total_resolved_alerts = graph_resolved + defender_resolved
        total_critical = len(graph_high) + len(defender_high)

        return {
            "source": "Microsoft + Defender",
            "live": True,
            "devices": len(devices),
            "windows": os_counts["windows"],
            "ios": os_counts["ios"],
            "macos": os_counts["macos"],
            "android": os_counts["android"],
            "other_os": os_counts["other"],
            "noncompliant": len(noncompliant),
            "alerts": total_active_alerts,
            "active_alerts": total_active_alerts,
            "returned_alerts": total_alerts_returned,
            "resolved_alerts": total_resolved_alerts,
            "defender_alerts": len(defender_active),
            "defender_critical": len(defender_high),
            "defender_returned_alerts": len(defender_alerts),
            "defender_resolved_alerts": defender_resolved,
            "graph_alerts": len(graph_active),
            "graph_returned_alerts": len(graph_alerts),
            "graph_resolved_alerts": graph_resolved,
            "critical": total_critical,
            "events": events,
        }


class UniFiConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["unifi"]
        return c.get("enabled") and c.get("base_url") and c.get("api_key")

    def _get_nested(self, obj, paths, default=""):
        for path in paths:
            cur = obj
            ok = True
            for part in path.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok and cur not in (None, ""):
                return cur
        return default

    def _parse_site_name_map(self, raw):
        """Parse manual site name mapping lines: id=name, id:name, id,name, or #1=name."""
        mapping = {}
        ordered = {}
        if not raw:
            return {"mapping": mapping, "ordered": ordered}
        for line in str(raw).replace(";", "\n").splitlines():
            line = line.strip()
            if not line:
                continue
            sep = "=" if "=" in line else ":" if ":" in line else "," if "," in line else None
            if not sep:
                continue
            key, value = line.split(sep, 1)
            key = key.strip().lower()
            value = value.strip()
            if key and value:
                mapping[key] = value
                if key.startswith("#"):
                    try:
                        ordered[int(key[1:])] = value
                    except Exception:
                        pass
        return {"mapping": mapping, "ordered": ordered}

    def _extract_items(self, data):
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        val = data.get("data")
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            for key in ("items", "results", "sites", "devices", "alerts", "events", "alarms"):
                nested = val.get(key)
                if isinstance(nested, list):
                    return nested
            return [val]
        for key in ("value", "events", "alerts", "alarms", "items", "results", "sites", "devices"):
            val = data.get(key)
            if isinstance(val, list):
                return val
        return []

    def _get_paged(self, base_url, headers, path, page_size=500, max_pages=50):
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            if not path.startswith("/"):
                path = "/" + path
            url = base_url + path

        items = []
        trace_ids = []
        next_token = None
        pages = 0

        while pages < max_pages:
            sep = "&" if "?" in url else "?"
            paged_url = f"{url}{sep}pageSize={page_size}"
            if next_token:
                paged_url += "&nextToken=" + urllib.parse.quote(str(next_token), safe="")

            data = Http.request("GET", paged_url, headers=headers)
            if isinstance(data, dict) and data.get("traceId"):
                trace_ids.append(str(data.get("traceId")))

            items.extend(self._extract_items(data))
            next_token = data.get("nextToken") if isinstance(data, dict) else None
            pages += 1
            if not next_token:
                break

        return items, trace_ids

    def debug_snapshot(self):
        """Return raw sample payloads from UniFi Site Manager API for field mapping."""
        if not self.enabled():
            raise RuntimeError("UniFi connector is not enabled or missing Base URL/API key.")

        c = self.cfg["unifi"]
        base = c["base_url"].rstrip("/")
        headers = {"X-API-KEY": c["api_key"], "Accept": "application/json"}

        snapshot = {
            "base_url": base,
            "note": "Redact IDs/secrets before sharing outside Smartbox. API key is not included.",
            "endpoints": {},
        }

        for name, path in [
            ("sites", "/v1/sites"),
            ("devices", "/v1/devices"),
            ("hosts", "/v1/hosts"),
        ]:
            try:
                items, traces = self._get_paged(base, headers, path, page_size=10, max_pages=1)
                snapshot["endpoints"][name] = {
                    "path": path,
                    "count_sampled": len(items),
                    "trace_ids": traces,
                    "sample": compact_json_sample(items, limit=3),
                }
            except Exception as e:
                snapshot["endpoints"][name] = {
                    "path": path,
                    "error": str(e),
                }

        configured_alert_path = self._configured_path(base, c.get("alerts_path", ""))
        if configured_alert_path:
            try:
                items, traces = self._get_paged(base, headers, configured_alert_path, page_size=10, max_pages=1)
                snapshot["endpoints"]["custom_alerts"] = {
                    "path": configured_alert_path,
                    "count_sampled": len(items),
                    "trace_ids": traces,
                    "sample": compact_json_sample(items, limit=3),
                }
            except Exception as e:
                snapshot["endpoints"]["custom_alerts"] = {
                    "path": configured_alert_path,
                    "error": str(e),
                }

        return snapshot

    def _severity_from_alert(self, alert):
        raw = str(
            alert.get("severity")
            or alert.get("level")
            or alert.get("priority")
            or alert.get("type")
            or alert.get("category")
            or alert.get("status")
            or alert.get("state")
            or ""
        ).lower()
        if any(x in raw for x in ("critical", "error", "wan", "offline", "down", "fail", "disconnected")):
            return "critical"
        if any(x in raw for x in ("warn", "medium", "blocked", "threat", "rogue", "degraded")):
            return "medium"
        return "info"

    def is_unifi_alert_active(self, alert):
        raw = " ".join([
            str(alert.get("status") or ""),
            str(alert.get("state") or ""),
            str(alert.get("archived") or ""),
            str(alert.get("resolved") or ""),
            str(alert.get("cleared") or ""),
        ]).lower()
        if "true" in raw and ("resolved" in raw or "archived" in raw or "cleared" in raw):
            return False
        return not any(word in raw for word in ("resolved", "closed", "archived", "cleared"))

    def _alert_title(self, alert):
        return (
            alert.get("title")
            or alert.get("message")
            or alert.get("name")
            or alert.get("event")
            or alert.get("type")
            or alert.get("category")
            or "UniFi alert/event"
        )

    def _alert_detail(self, alert):
        parts = []
        for key in ("siteName", "siteId", "site_id", "deviceName", "hostName", "hostname", "clientName", "mac", "ip", "timestamp", "datetime", "time"):
            if alert.get(key):
                parts.append(str(alert.get(key)))
        return " | ".join(parts[:4]) or "UniFi item returned by Site Manager API"

    def _site_id(self, site):
        return str(self._get_nested(site, [
            "siteId", "id", "_id", "site_id", "site.id", "site.siteId", "meta.id", "metadata.id",
            "uuid", "uid", "key"
        ], ""))

    def _site_host_id(self, site):
        return str(self._get_nested(site, ["hostId", "host.id", "consoleId", "console.id"], ""))

    def _site_name(self, site):
        name = str(self._get_nested(site, [
            "meta.desc", "description", "displayName", "siteName", "name", "desc", "nickname", "label",
            "meta.name", "metadata.name", "site.name", "site.displayName",
            "attributes.name", "properties.name", "settings.name", "profile.name",
            "ui.name", "console.name", "host.name"
        ], ""))

        # UniFi often returns meta.name/default for every site. Prefer a real descriptor if present.
        if name.lower() == "default":
            desc = str(self._get_nested(site, ["meta.desc", "description", "desc"], ""))
            if desc and desc.lower() != "default":
                return desc

        return name or self._site_id(site) or "UniFi site"

    def _site_aliases(self, site):
        vals = set()
        for path in [
            "siteId", "id", "_id", "site_id", "site.id", "site.siteId", "meta.id", "metadata.id", "uuid", "uid", "key",
            "hostId", "host.id", "consoleId", "console.id",
            "name", "displayName", "siteName", "description", "desc", "meta.name", "meta.desc", "metadata.name", "site.name"
        ]:
            val = self._get_nested(site, [path], "")
            if val not in (None, ""):
                vals.add(str(val).lower())
        return vals

    def _host_name(self, host):
        return str(self._get_nested(host, [
            "name", "hostname", "hostName", "displayName",
            "reportedState.name", "reportedState.hostname", "reportedState.hardware.name",
            "reportedState.hardware.shortname"
        ], ""))

    def _host_aliases(self, host):
        vals = set()
        for path in [
            "id", "hostId", "host.id", "reportedState.controller_uuid",
            "reportedState.mac", "mac", "reportedState.hardware.mac",
            "name", "hostname", "reportedState.name", "reportedState.hostname"
        ]:
            val = self._get_nested(host, [path], "")
            if val not in (None, ""):
                vals.add(str(val).lower())
        return vals

    def _device_group_host_id(self, group):
        return str(self._get_nested(group, ["hostId", "id", "host.id"], ""))

    def _device_status(self, device):
        raw = str(self._get_nested(device, [
            "status", "state", "connectionState", "health", "availability",
            "state.status", "overview.status", "connection.status"
        ], "")).lower()
        if any(x in raw for x in ("offline", "down", "disconnected", "failed", "critical")):
            return "offline"
        if any(x in raw for x in ("adopting", "pending", "updating", "warning", "degraded")):
            return "degraded"
        if any(x in raw for x in ("online", "connected", "active", "healthy", "ok")):
            return "online"
        return "unknown"

    def _site_status_from_counts(self, total, offline, degraded):
        """Classify a UniFi site without exaggerating partial device failures.

        CRITICAL means the whole site appears offline.
        DEGRADED means the site is reachable but has offline/degraded devices.
        HEALTHY means all mapped devices look online.
        """
        total = int(total or 0)
        offline = int(offline or 0)
        degraded = int(degraded or 0)

        if total <= 0:
            return "VISIBLE"
        if offline >= total:
            return "CRITICAL"
        if offline > 0 or degraded > 0:
            return "DEGRADED"
        return "HEALTHY"

    def _configured_path(self, base, path):
        if not path:
            return ""
        path = path.strip()
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return base + path

    def fetch(self):
        if not self.enabled():
            return None

        c = self.cfg["unifi"]
        base = c["base_url"].rstrip("/")
        headers = {"X-API-KEY": c["api_key"], "Accept": "application/json"}

        events = []
        site_errors = []
        alert_errors = []

        sites = []
        site_trace_ids = []
        try:
            sites, site_trace_ids = self._get_paged(base, headers, "/v1/sites", page_size=500, max_pages=20)
        except Exception as e:
            site_errors.append(str(e)[:180])
            events.append({
                "severity": "critical",
                "title": "UniFi sites query failed",
                "detail": str(e)[:180],
                "source": "UniFi",
            })

        device_groups = []
        try:
            device_groups, _ = self._get_paged(base, headers, "/v1/devices", page_size=500, max_pages=50)
        except Exception as e:
            events.append({
                "severity": "medium",
                "title": "UniFi devices query failed",
                "detail": str(e)[:180],
                "source": "UniFi",
            })

        hosts = []
        try:
            hosts, _ = self._get_paged(base, headers, "/v1/hosts", page_size=500, max_pages=20)
        except Exception:
            hosts = []

        site_count = len(sites)
        host_group_count = len(device_groups)
        host_count = len(hosts)

        manual_site_names_config = self._parse_site_name_map(c.get("site_name_map", ""))
        manual_site_names = manual_site_names_config.get("mapping", {})
        manual_site_ordered_names = manual_site_names_config.get("ordered", {})

        host_name_by_alias = {}
        for host in hosts:
            if not isinstance(host, dict):
                continue
            hname = self._host_name(host)
            if not hname:
                continue
            for alias in self._host_aliases(host):
                host_name_by_alias[alias] = hname

        site_index = {}
        host_to_site_key = {}

        for i, site in enumerate(sites):
            if not isinstance(site, dict):
                continue

            sid = self._site_id(site) or f"site-{i+1}"
            host_id = self._site_host_id(site)
            aliases = self._site_aliases(site)
            name = self._site_name(site)

            # Prefer host/console name when UniFi exposes only "default" for site.
            if host_id and host_id.lower() in host_name_by_alias and name.lower() in ("default", sid.lower(), ""):
                name = host_name_by_alias[host_id.lower()]

            # Manual fallback supports exact IDs/names and positional #1/#2 mapping.
            if (i + 1) in manual_site_ordered_names:
                name = manual_site_ordered_names[i + 1]
            else:
                for alias in aliases:
                    if alias.lower() in manual_site_names:
                        name = manual_site_names[alias.lower()]
                        break
                if sid.lower() in manual_site_names:
                    name = manual_site_names[sid.lower()]
                if host_id and host_id.lower() in manual_site_names:
                    name = manual_site_names[host_id.lower()]

            counts = self._get_nested(site, ["statistics.counts"], {})
            api_total = int(counts.get("totalDevice", 0)) if isinstance(counts, dict) else 0
            api_offline = int(counts.get("offlineDevice", 0)) if isinstance(counts, dict) else 0
            api_pending = int(counts.get("pendingUpdateDevice", 0)) if isinstance(counts, dict) else 0
            critical_notifications = int(counts.get("criticalNotification", 0)) if isinstance(counts, dict) else 0

            site_index[sid] = {
                "name": name,
                "id": sid,
                "host_id": host_id,
                "total": 0,
                "online": 0,
                "offline": 0,
                "degraded": 0,
                "unknown": 0,
                "api_total": api_total,
                "api_offline": api_offline,
                "api_pending": api_pending,
                "critical_notifications": critical_notifications,
                "raw": site,
            }

            if host_id:
                host_to_site_key[host_id.lower()] = sid
            for alias in aliases:
                host_to_site_key.setdefault(alias.lower(), sid)

        # /v1/devices returns host groups, each with hostId, hostName and nested devices[].
        nested_device_total = 0
        unmatched_groups = 0
        for group in device_groups:
            if not isinstance(group, dict):
                continue
            host_id = self._device_group_host_id(group)
            group_host_name = str(group.get("hostName") or group.get("hostname") or "")
            nested_devices = group.get("devices") if isinstance(group.get("devices"), list) else []
            nested_device_total += len(nested_devices)

            key = host_to_site_key.get(host_id.lower()) if host_id else None
            if not key:
                # Fall back to host name matching.
                key = host_to_site_key.get(group_host_name.lower()) if group_host_name else None

            if not key:
                unmatched_groups += 1
                key = f"unmatched-{host_id or group_host_name or unmatched_groups}"
                site_index[key] = {
                    "name": group_host_name or "Unassigned / site mapping unavailable",
                    "id": key,
                    "host_id": host_id,
                    "total": 0,
                    "online": 0,
                    "offline": 0,
                    "degraded": 0,
                    "unknown": 0,
                    "api_total": 0,
                    "api_offline": 0,
                    "api_pending": 0,
                    "critical_notifications": 0,
                    "raw": {},
                }

            if group_host_name and site_index[key]["name"].lower() in ("default", site_index[key]["id"].lower(), ""):
                site_index[key]["name"] = group_host_name

            for device in nested_devices:
                if not isinstance(device, dict):
                    continue
                status = self._device_status(device)
                site_index[key]["total"] += 1
                site_index[key][status] = site_index[key].get(status, 0) + 1

        # If nested devices are not returned for a site, use /v1/sites statistics.counts as fallback.
        for key, row in site_index.items():
            if row["total"] == 0 and row["api_total"] > 0:
                row["total"] = row["api_total"]
                row["offline"] = row["api_offline"]
                row["degraded"] = row["api_pending"]
                row["online"] = max(0, row["api_total"] - row["api_offline"] - row["api_pending"])
                row["unknown"] = 0

        site_health = []
        for sid, data in list(site_index.items())[:100]:
            status = self._site_status_from_counts(data["total"], data["offline"], data["degraded"])
            detail = f"devices {data['total']}, online {data['online']}, offline {data['offline']}, degraded {data['degraded']}, unknown {data['unknown']}"
            if data["critical_notifications"]:
                detail += f", critical notifications {data['critical_notifications']}"
            if data["total"] == 0:
                detail = "site visible; no device counts returned"
            site_health.append({
                "name": data["name"],
                "id": data["id"],
                "status": status,
                "detail": detail,
                "total": data["total"],
                "online": data["online"],
                "offline": data["offline"],
                "degraded": data["degraded"],
                "unknown": data["unknown"],
            })

        # Count all UniFi devices from nested devices; fall back to site statistics if the nested API is empty.
        device_count = nested_device_total or sum(int(s.get("total", 0)) for s in site_health)

        healthy_sites = sum(1 for s in site_health if s["status"] == "HEALTHY")
        degraded_sites = sum(1 for s in site_health if s["status"] == "DEGRADED")
        critical_sites = sum(1 for s in site_health if s["status"] == "CRITICAL")
        visible_sites = sum(1 for s in site_health if s["status"] == "VISIBLE")

        alerts = []
        configured_alert_path = self._configured_path(base, c.get("alerts_path", ""))
        if configured_alert_path:
            try:
                alerts, _ = self._get_paged(base, headers, configured_alert_path, page_size=500, max_pages=20)
            except Exception as e:
                alert_errors.append(str(e)[:140])

        active_unifi_alerts = [a for a in alerts if isinstance(a, dict) and self.is_unifi_alert_active(a)]
        resolved_unifi_alerts = max(0, len(alerts) - len(active_unifi_alerts))
        critical_alerts = sum(1 for a in active_unifi_alerts if self._severity_from_alert(a) == "critical")
        # UniFi health is displayed locally in the network panel.
        # It must not drive the global security priority state, which is Microsoft/Intune/Defender focused.
        critical_total = critical_alerts

        if sites:
            trace_bit = f" trace {site_trace_ids[0]}" if site_trace_ids else ""
            events.append({
                "severity": "info",
                "title": "UniFi Site Manager API live",
                "detail": f"Polled /v1/sites, /v1/devices, /v1/hosts. Joined sites to device groups by hostId. {site_count} site(s), {device_count} nested device(s), {host_group_count} device group(s), {host_count} host(s).{trace_bit}",
                "source": "UniFi",
            })

        if unmatched_groups:
            events.append({
                "severity": "medium",
                "title": "UniFi device group mapping incomplete",
                "detail": f"{unmatched_groups} /v1/devices host group(s) could not be joined by hostId.",
                "source": "UniFi",
            })

        if site_health:
            events.append({
                "severity": "info",
                "title": "UniFi site health calculated",
                "detail": f"{len(site_health)} site row(s): healthy {healthy_sites}, degraded {degraded_sites}, critical {critical_sites}, visible {visible_sites}.",
                "source": "UniFi",
            })

        if active_unifi_alerts:
            events.insert(0, {
                "severity": "critical" if critical_alerts else "medium",
                "title": "UniFi alerts live",
                "detail": f"{len(active_unifi_alerts)} active UniFi alert/event item(s), {resolved_unifi_alerts} resolved/closed returned.",
                "source": "UniFi",
            })
            for alert in active_unifi_alerts[:25]:
                events.append({
                    "severity": self._severity_from_alert(alert),
                    "title": self._alert_title(alert),
                    "detail": self._alert_detail(alert),
                    "source": "UniFi",
                })
        elif configured_alert_path and alert_errors:
            events.append({
                "severity": "medium",
                "title": "Configured UniFi alerts path failed",
                "detail": f"Alerts path was configured but did not return alert items: {alert_errors[0]}",
                "source": "UniFi",
            })
        elif configured_alert_path:
            events.append({
                "severity": "info",
                "title": "Configured UniFi alerts path returned no active items",
                "detail": "The custom alerts path responded but no active UniFi alert/event items were found.",
                "source": "UniFi",
            })
        else:
            events.append({
                "severity": "info",
                "title": "UniFi alerts not configured",
                "detail": "Site Manager /v1/sites and /v1/devices are live. Add a custom Alerts path only if your UniFi API exposes one.",
                "source": "UniFi",
            })

        if site_errors and not sites:
            raise RuntimeError(f"UniFi /v1/sites failed: {site_errors[0]}")

        return {
            "source": "UniFi",
            "live": True,
            "unifi_connected": 1,
            "unifi_sites": site_count,
            "unifi_status": "LIVE",
            "unifi_devices": device_count,
            "unifi_alerts": len(active_unifi_alerts),
            "unifi_returned_alerts": len(alerts),
            "unifi_resolved_alerts": resolved_unifi_alerts,
            "unifi_site_health": site_health,
            "unifi_healthy_sites": healthy_sites,
            "unifi_degraded_sites": degraded_sites,
            "unifi_critical_sites": critical_sites,
            "unifi_visible_sites": visible_sites,
            "alerts": len(active_unifi_alerts),
            "active_alerts": len(active_unifi_alerts),
            "returned_alerts": len(alerts),
            "resolved_alerts": resolved_unifi_alerts,
            "critical": critical_total,
            "sites": site_count,
            "devices": 0,
            "wan_health": 0,
            "events": events,
        }


class DattoConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["datto"]
        return c.get("enabled") and c.get("api_url") and c.get("access_token")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["datto"]
        base = c["api_url"].rstrip("/")
        headers = {"Authorization": f"Bearer {c['access_token']}", "Accept": "application/json"}
        account = Http.request("GET", base + "/api/v2/account", headers=headers)
        # Alert/device paths differ by platform version; use Swagger for final mapping.
        return {
            "source": "Datto RMM",
            "live": True,
            "devices": int(account.get("deviceCount", 0) or account.get("devices", 0) or 0),
            "alerts": int(account.get("openAlertCount", 0) or 0),
            "events": [{
                "severity": "info",
                "title": "Datto RMM account API reachable",
                "detail": account.get("name", "Account endpoint returned JSON"),
                "source": "Datto RMM",
            }],
        }


class RocketCyberConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["rocketcyber"]
        return c.get("enabled") and c.get("base_url") and c.get("api_key")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["rocketcyber"]
        base = c["base_url"].rstrip("/")
        headers = {"Authorization": f"Bearer {c['api_key']}", "Accept": "application/json"}
        # Common customer API base probe. Keep demo resilient because tenant paths vary.
        data = Http.request("GET", base + "/v3", headers=headers)
        return {
            "source": "RocketCyber",
            "live": True,
            "alerts": 0,
            "critical": 0,
            "events": [{
                "severity": "info",
                "title": "RocketCyber API reachable",
                "detail": "Customer API responded",
                "source": "RocketCyber",
            }],
        }


class TelemetryEngine(threading.Thread):
    def __init__(self, cfg, outq):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.outq = outq
        self.stop_flag = threading.Event()
        self.connectors = [
            MicrosoftGraphConnector(cfg),
            UniFiConnector(cfg),
            DattoConnector(cfg),
            RocketCyberConnector(cfg),
        ]
        self.tick = 0

    def run(self):
        while not self.stop_flag.is_set():
            try:
                payload = self.collect()
                self.outq.put(payload)
            except Exception as e:
                self.outq.put({"error": str(e), "trace": traceback.format_exc()})
            self.stop_flag.wait(max(3, int(self.cfg.get("poll_seconds", 8))))

    def collect(self):
        self.tick += 1
        results = []
        errors = []
        for c in self.connectors:
            try:
                r = c.fetch()
                if r:
                    results.append(r)
            except Exception as e:
                errors.append({"source": c.__class__.__name__.replace("Connector", ""), "error": str(e)})

        return self.correlate(results, errors)

    def simulate(self):
        wave = (math.sin(self.tick / 3) + 1) / 2
        devices = 186 + random.randint(-4, 7)
        noncompliant = int(8 + wave * 9 + random.randint(-2, 2))
        alerts = int(11 + wave * 12 + random.randint(-3, 5))
        critical = 1 if wave > 0.65 else 0
        events = [
            {"severity": "critical" if critical else "medium", "title": "EDR signal + stale Intune sync correlation", "detail": "DESKTOP-7Q2 has high-risk alert and missed compliance sync", "source": "Correlation"},
            {"severity": "medium", "title": "VLAN anomaly on wireless estate", "detail": "Guest segment saw 31% traffic jump in 10 min window", "source": "UniFi synthetic"},
            {"severity": "info", "title": "Patch posture improved", "detail": "Windows compliant estate rose by 2.1%", "source": "Intune synthetic"},
            {"severity": "medium", "title": "RMM agent silence", "detail": "3 endpoints have not checked into Datto RMM recently", "source": "Datto synthetic"},
        ]
        return {
            "source": "Sentinel simulator",
            "live": False,
            "devices": devices,
            "noncompliant": noncompliant,
            "alerts": alerts,
            "critical": critical,
            "wan_health": int(96 - wave * 5),
            "events": events,
        }


    def priority_from_counts(self, metrics):
        """Return the main security priority from Defender only.

        Intune compliance, Graph Security and UniFi remain visible, but they do not
        drive the headline HIGH/CRITICAL state.
        """
        defender = int(metrics.get("defender_alerts", 0) or 0)
        defender_critical = int(metrics.get("defender_critical", 0) or 0)

        if defender_critical > 0:
            return "CRITICAL", 4, f"{defender_critical} high/critical active Defender alert(s)"
        if defender >= 10:
            return "HIGH", 3, f"{defender} active Defender alert(s)"
        if defender > 0:
            return "ACTION", 2, f"{defender} active Defender alert(s)"
        return "CLEAR", 0, "no active Defender alerts"


    def event_to_alert_row(self, event):
        source = str(event.get("source", "Unknown"))
        severity = str(event.get("severity", "info")).upper()
        title = str(event.get("title", ""))
        detail = str(event.get("detail", ""))
        status = "ACTIVE"
        lowered = (title + " " + detail).lower()
        if any(word in lowered for word in ("resolved", "closed", "dismissed", "remediated", "cleared", "archived")):
            status = "RESOLVED/CLOSED"
        if "site health calculated" in lowered and "unifi" in source.lower():
            status = "NETWORK"
        elif (
            "inventory loaded" in lowered
            or "api live" in lowered
            or "not configured" in lowered
            or "returned no active items" in lowered
        ):
            status = "INFO"
        return {
            "source": source,
            "severity": severity,
            "title": title,
            "status": status,
            "detail": detail,
        }


    def correlate(self, results, errors):
        if not results:
            return {
                "timestamp": now_iso(),
                "metrics": {
                    "devices": 0,
                    "noncompliant": 0,
                    "compliant_devices": 0,
                    "compliance_percent": 0,
                    "alerts": 0,
                    "active_alerts": 0,
                    "returned_alerts": 0,
                    "resolved_alerts": 0,
                    "defender_alerts": 0,
                    "defender_critical": 0,
                    "defender_returned_alerts": 0,
                    "defender_resolved_alerts": 0,
                    "graph_alerts": 0,
                    "graph_returned_alerts": 0,
                    "graph_resolved_alerts": 0,
                    "critical": 0,
                    "wan_health": 0,
                    "unifi_connected": 0,
                    "unifi_sites": 0,
                    "unifi_devices": 0,
                    "unifi_alerts": 0,
                    "unifi_returned_alerts": 0,
                    "unifi_resolved_alerts": 0,
                    "unifi_healthy_sites": 0,
                    "unifi_degraded_sites": 0,
                    "unifi_critical_sites": 0,
                    "unifi_visible_sites": 0,
                    "unifi_site_health": [],
                    "windows": 0,
                    "ios": 0,
                    "macos": 0,
                    "android": 0,
                    "other_os": 0,
                    "risk": 0,
                    "priority_state": "CLEAR",
                    "priority_level": 0,
                },
                "events": [
                    {
                        "severity": "info",
                        "title": "No configured connector is returning data",
                        "detail": "Open Setup connectors, enable the connector you want, enter credentials, and save.",
                        "source": "Connector health",
                    }
                ] + [
                    {
                        "severity": "medium",
                        "title": f"{e['source']} connector degraded",
                        "detail": e["error"][:160],
                        "source": "Connector health",
                    } for e in errors[:4]
                ],
                "alert_rows": [],
                "sources": {"live": [], "simulated": [], "errors": errors},
            }

        devices = sum(int(r.get("devices", 0)) for r in results)
        noncompliant = sum(int(r.get("noncompliant", 0)) for r in results)
        compliant_devices = max(0, devices - noncompliant)
        compliance_percent = int((compliant_devices / max(devices, 1)) * 100) if devices else 0
        alerts = sum(int(r.get("alerts", 0)) for r in results)
        active_alerts = sum(int(r.get("active_alerts", r.get("alerts", 0))) for r in results)
        returned_alerts = sum(int(r.get("returned_alerts", r.get("alerts", 0))) for r in results)
        resolved_alerts = sum(int(r.get("resolved_alerts", 0)) for r in results)
        defender_alerts = sum(int(r.get("defender_alerts", 0)) for r in results)
        defender_critical = sum(int(r.get("defender_critical", 0)) for r in results)
        defender_returned_alerts = sum(int(r.get("defender_returned_alerts", r.get("defender_alerts", 0))) for r in results)
        defender_resolved_alerts = sum(int(r.get("defender_resolved_alerts", 0)) for r in results)
        graph_alerts = sum(int(r.get("graph_alerts", 0)) for r in results)
        graph_returned_alerts = sum(int(r.get("graph_returned_alerts", r.get("graph_alerts", 0))) for r in results)
        graph_resolved_alerts = sum(int(r.get("graph_resolved_alerts", 0)) for r in results)
        # Global security criticality should come from Defender only.
        # Graph Security, Intune compliance and UniFi network health are visible context,
        # but they do not drive the headline Critical/High state.
        microsoft_critical = defender_critical
        critical = defender_critical
        unifi_connected = sum(int(r.get("unifi_connected", 0)) for r in results)
        unifi_sites = sum(int(r.get("unifi_sites", 0)) for r in results)
        unifi_devices = sum(int(r.get("unifi_devices", 0)) for r in results)
        unifi_alerts = sum(int(r.get("unifi_alerts", 0)) for r in results)
        unifi_returned_alerts = sum(int(r.get("unifi_returned_alerts", r.get("unifi_alerts", 0))) for r in results)
        unifi_resolved_alerts = sum(int(r.get("unifi_resolved_alerts", 0)) for r in results)
        unifi_healthy_sites = sum(int(r.get("unifi_healthy_sites", 0)) for r in results)
        unifi_degraded_sites = sum(int(r.get("unifi_degraded_sites", 0)) for r in results)
        unifi_critical_sites = sum(int(r.get("unifi_critical_sites", 0)) for r in results)
        unifi_visible_sites = sum(int(r.get("unifi_visible_sites", 0)) for r in results)
        unifi_site_health = []
        for r in results:
            unifi_site_health.extend(r.get("unifi_site_health", []) or [])
        windows = sum(int(r.get("windows", 0)) for r in results)
        ios = sum(int(r.get("ios", 0)) for r in results)
        macos = sum(int(r.get("macos", 0)) for r in results)
        android = sum(int(r.get("android", 0)) for r in results)
        other_os = sum(int(r.get("other_os", 0)) for r in results)
        wan = [int(r.get("wan_health")) for r in results if r.get("wan_health") not in (None, 0)]
        wan_health = int(sum(wan) / len(wan)) if wan else 0
        wan_penalty = (100 - wan_health) * 1.2 if wan_health else 0
        risk = 0  # Deprecated: kept internally only so older chart state does not break. Not displayed as a security result.
        priority_state, priority_level, priority_reason = self.priority_from_counts({
            "critical": critical,
            "active_alerts": active_alerts,
            "defender_alerts": defender_alerts,
            "defender_critical": defender_critical,
            "graph_alerts": graph_alerts,
            "noncompliant": noncompliant,
        })
        live_sources = [r["source"] for r in results if r.get("live")]
        sim_sources = [r["source"] for r in results if not r.get("live")]
        events = []
        for r in results:
            events.extend(r.get("events", []))
        for e in errors[:4]:
            events.append({"severity": "medium", "title": f"{e['source']} connector degraded", "detail": e["error"][:160], "source": "Connector health"})
        alert_rows = [self.event_to_alert_row(e) for e in events[:100]]
        events = events[:100]
        return {
            "timestamp": now_iso(),
            "metrics": {
                "devices": devices,
                "noncompliant": noncompliant,
                "compliant_devices": compliant_devices,
                "compliance_percent": compliance_percent,
                "alerts": active_alerts,
                "active_alerts": active_alerts,
                "returned_alerts": returned_alerts,
                "resolved_alerts": resolved_alerts,
                "defender_alerts": defender_alerts,
                "defender_critical": defender_critical,
                "defender_returned_alerts": defender_returned_alerts,
                "defender_resolved_alerts": defender_resolved_alerts,
                "graph_alerts": graph_alerts,
                "graph_returned_alerts": graph_returned_alerts,
                "graph_resolved_alerts": graph_resolved_alerts,
                "critical": critical,
                "microsoft_critical": microsoft_critical,
                "wan_health": wan_health,
                "unifi_connected": unifi_connected,
                "unifi_sites": unifi_sites,
                "unifi_devices": unifi_devices,
                "unifi_alerts": unifi_alerts,
                "unifi_returned_alerts": unifi_returned_alerts,
                "unifi_resolved_alerts": unifi_resolved_alerts,
                "unifi_healthy_sites": unifi_healthy_sites,
                "unifi_degraded_sites": unifi_degraded_sites,
                "unifi_critical_sites": unifi_critical_sites,
                "unifi_visible_sites": unifi_visible_sites,
                "unifi_site_health": unifi_site_health,
                "windows": windows,
                "ios": ios,
                "macos": macos,
                "android": android,
                "other_os": other_os,
                "risk": risk,
                "priority_state": priority_state,
                "priority_level": priority_level,
                "priority_reason": priority_reason,
            },
            "events": events,
            "alert_rows": alert_rows,
            "sources": {"live": live_sources, "simulated": sim_sources, "errors": errors},
        }


class SentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1480x860")
        self.minsize(1250, 760)
        self.configure(bg=BG)
        self.cfg = Config.load()
        self.q = queue.Queue()
        self.engine = None
        self.metric_labels = {}
        self.metric_cards = {}
        self.platform_labels = {}
        self.alert_breakdown_labels = {}
        self.unifi_labels = {}
        self.connector_widgets = {}
        self.focus_cards = {"defender": {}, "intune": {}, "unifi": {}}
        self.last_payload = None
        self.optional_metric_keys = ["wan_health"]
        self.optional_bars = []
        self.status_var = tk.StringVar(value="Starting telemetry engine...")
        self._setup_style()
        self._build()
        self.start_engine()
        self.after(250, self.drain_queue)

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Variable Display", 24, "bold"))
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI Variable Display", 24, "bold"))
        style.configure("SmallCard.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT, font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground="#0F1524", foreground=TEXT, insertcolor=TEXT, bordercolor="#24304A")
        style.configure("Dasher.TNotebook", background=BG, borderwidth=0, tabmargins=(0, 8, 0, 0))
        style.configure("Dasher.TNotebook.Tab", background="#121821", foreground=MUTED, padding=(22, 11), font=("Segoe UI Variable Text", 10, "bold"), borderwidth=0)
        style.map("Dasher.TNotebook.Tab",
                  background=[("selected", "#202A38"), ("active", "#1A2330")],
                  foreground=[("selected", TEXT), ("active", TEXT)])

    def _build(self):
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True, padx=24, pady=20)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="Smartbox Security Dasher 3000", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 30, "bold")).pack(side="left")
        tk.Label(header, text="Defender priority • Intune estate • UniFi health", bg=BG, fg=MUTED, font=("Segoe UI", 11)).pack(side="left", padx=18, pady=(14,0))
        tk.Button(header, text="Setup connectors", command=self.open_setup, bg="#1A2330", fg=TEXT, activebackground="#263347", relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold")).pack(side="right")
        tk.Button(header, text="Export UniFi debug", command=self.export_unifi_debug, bg="#151D29", fg=TEXT, activebackground="#263347", relief="flat", padx=12, pady=8, font=("Segoe UI", 9, "bold")).pack(side="right", padx=(0, 8))

        self.overview = tk.Frame(shell, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        self.overview.pack(fill="x", pady=(14, 6))
        self.state_badge = tk.Label(self.overview, text="INITIALISING", bg=PANEL, fg=BLUE, font=("Segoe UI", 10, "bold"))
        self.state_badge.pack(side="left", padx=(18, 10), pady=12)
        self.state_detail = tk.Label(self.overview, text="Waiting for first telemetry pull...", bg=PANEL, fg=TEXT, font=("Segoe UI", 10))
        self.state_detail.pack(side="left", padx=(0, 8), pady=12)
        self.live_badge = tk.Label(self.overview, text="LIVE: NONE", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold"))
        self.live_badge.pack(side="right", padx=(8, 18), pady=12)

        self.main_tabs = ttk.Notebook(shell, style="Dasher.TNotebook")
        self.main_tabs.pack(fill="both", expand=True, pady=(12, 0))

        self.tab_overview = tk.Frame(self.main_tabs, bg=BG)
        self.tab_defender = tk.Frame(self.main_tabs, bg=BG)
        self.tab_intune = tk.Frame(self.main_tabs, bg=BG)
        self.tab_unifi = tk.Frame(self.main_tabs, bg=BG)

        self.main_tabs.add(self.tab_overview, text="Overview")
        self.main_tabs.add(self.tab_defender, text="Defender")
        self.main_tabs.add(self.tab_intune, text="Intune")
        self.main_tabs.add(self.tab_unifi, text="UniFi")

        body = tk.Frame(self.tab_overview, bg=BG)
        body.pack(fill="both", expand=True, pady=(12, 0))

        self.overview_focus_bar = tk.Frame(body, bg=GLASS, highlightthickness=1, highlightbackground=HAIRLINE)
        self.overview_focus_bar.pack(fill="x", pady=(0, 12))
        tk.Label(self.overview_focus_bar, text="Operational summary", bg=GLASS, fg=MUTED, font=("Segoe UI Variable Text", 9, "bold")).pack(anchor="w", padx=14, pady=(10, 2))
        self.overview_focus_text = tk.Label(self.overview_focus_bar, text="Waiting for live connector data", bg=GLASS, fg=TEXT, font=("Segoe UI", 11, "bold"), justify="left")
        self.overview_focus_text.pack(anchor="w", padx=14, pady=(0, 10))
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side="right", fill="y", padx=(18, 0))
        right.pack_propagate(False)

        cards = tk.Frame(left, bg=BG)
        cards.pack(fill="x")
        for i in range(3):
            cards.grid_columnconfigure(i, weight=1)
        self.card(cards, 0, 0, "Defender priority", "priority_state", BLUE)
        self.card(cards, 0, 1, "Active security alerts", "alerts", RED)
        self.card(cards, 0, 2, "Intune compliance gap", "noncompliant", AMBER)
        self.card(cards, 1, 0, "Intune devices", "devices", GREEN)
        self.card(cards, 1, 1, "High/Critical Defender", "critical", PURPLE)


        self.unifi_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        for label, key, color in [
            ("Network status", "unifi_status", BLUE),
            ("UniFi sites", "unifi_sites", GREEN),
            ("UniFi devices", "unifi_devices", BLUE),
            ("UniFi alerts", "unifi_alerts", AMBER),
            ("Healthy", "unifi_healthy_sites", GREEN),
            ("Degraded sites", "unifi_degraded_sites", AMBER),
            ("Offline sites", "unifi_critical_sites", RED),
        ]:
            box = tk.Frame(self.unifi_bar, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=14, pady=8)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 16, "bold"))
            val.pack(anchor="w")
            self.unifi_labels[key] = val


        self.network_summary_bar = tk.Frame(left, bg=GLASS, highlightthickness=1, highlightbackground=HAIRLINE)
        self.network_summary_bar.pack(fill="x", pady=(8, 0))
        ns_left = tk.Frame(self.network_summary_bar, bg=GLASS)
        ns_left.pack(side="left", fill="x", expand=True, padx=12, pady=12)
        tk.Label(ns_left, text="Network site status", bg=GLASS, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.network_status_big = tk.Label(ns_left, text="--", bg=GLASS, fg=BLUE, font=("Segoe UI Variable Display", 18, "bold"))
        self.network_status_big.pack(anchor="w")
        ns_right = tk.Frame(self.network_summary_bar, bg=GLASS)
        ns_right.pack(side="right", fill="x", expand=True, padx=12, pady=12)
        tk.Label(ns_right, text="UniFi site health summary", bg=GLASS, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.network_status_detail = tk.Label(ns_right, text="Waiting for UniFi site data", bg=GLASS, fg=TEXT, font=("Segoe UI", 10, "bold"), justify="left")
        self.network_status_detail.pack(anchor="w")

        self.unifi_site_health_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        site_header = tk.Frame(self.unifi_site_health_bar, bg=PANEL)
        site_header.pack(fill="x", padx=12, pady=(8, 2))
        self.unifi_site_health_title = tk.Label(site_header, text="UniFi network sites", bg=PANEL, fg=TEXT, font=("Segoe UI", 9, "bold"))
        self.unifi_site_health_title.pack(side="left")
        self.unifi_site_health_summary = tk.Label(site_header, text="Waiting for UniFi site health...", bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold"))
        self.unifi_site_health_summary.pack(side="right")

        self.unifi_site_table_canvas = tk.Canvas(self.unifi_site_health_bar, bg=PANEL, highlightthickness=0, bd=0, height=150)
        self.unifi_site_table_scrollbar = tk.Scrollbar(self.unifi_site_health_bar, orient="vertical", command=self.unifi_site_table_canvas.yview, bg=PANEL, troughcolor=BG)
        self.unifi_site_table_canvas.configure(yscrollcommand=self.unifi_site_table_scrollbar.set)
        self.unifi_site_table_canvas.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 8))
        self.unifi_site_table_scrollbar.pack(side="right", fill="y", padx=(0, 12), pady=(0, 8))

        self.unifi_site_table = tk.Frame(self.unifi_site_table_canvas, bg=PANEL)
        self.unifi_site_table_window = self.unifi_site_table_canvas.create_window((0, 0), window=self.unifi_site_table, anchor="nw")
        self.unifi_site_table.bind("<Configure>", self._on_unifi_site_table_configure)
        self.unifi_site_table_canvas.bind("<Configure>", self._on_unifi_site_table_canvas_configure)
        self.unifi_site_table_canvas.bind("<Enter>", self._bind_unifi_site_table_mousewheel)
        self.unifi_site_table_canvas.bind("<Leave>", self._unbind_unifi_site_table_mousewheel)


        self.platform_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        self.platform_bar.pack(fill="x", pady=(8, 0))
        for label, key, color in [
            ("Windows devices", "windows", BLUE),
            ("iPhone / iPad", "ios", GREEN),
            ("Mac devices", "macos", PURPLE),
            ("Android", "android", AMBER),
            ("Other OS", "other_os", MUTED),
        ]:
            box = tk.Frame(self.platform_bar, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=14, pady=12)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="0", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 18, "bold"))
            val.pack(anchor="w")
            self.platform_labels[key] = val


        self.alert_table_panel = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        # Overview is intentionally executive: detailed alert rows live on the Defender tab.
        # self.alert_table_panel.pack(fill="both", expand=True, pady=(12, 0))

        table_header = tk.Frame(self.alert_table_panel, bg=PANEL)
        table_header.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(table_header, text="Security alert table", bg=PANEL, fg=TEXT, font=("Segoe UI Variable Display", 16, "bold")).pack(side="left")
        self.alert_table_summary = tk.Label(table_header, text="Waiting for live rows...", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold"))
        self.alert_table_summary.pack(side="right")

        self.alert_table_canvas = tk.Canvas(self.alert_table_panel, bg=PANEL, highlightthickness=0, bd=0, height=320)
        self.alert_table_scrollbar = tk.Scrollbar(self.alert_table_panel, orient="vertical", command=self.alert_table_canvas.yview, bg=PANEL, troughcolor=BG)
        self.alert_table_canvas.configure(yscrollcommand=self.alert_table_scrollbar.set)
        self.alert_table_canvas.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 10))
        self.alert_table_scrollbar.pack(side="right", fill="y", padx=(0, 12), pady=(0, 10))

        self.alert_table = tk.Frame(self.alert_table_canvas, bg=PANEL)
        self.alert_table_window = self.alert_table_canvas.create_window((0, 0), window=self.alert_table, anchor="nw")
        self.alert_table.bind("<Configure>", self._on_alert_table_configure)
        self.alert_table_canvas.bind("<Configure>", self._on_alert_table_canvas_configure)
        self.alert_table_canvas.bind("<Enter>", self._bind_alert_table_mousewheel)
        self.alert_table_canvas.bind("<Leave>", self._unbind_alert_table_mousewheel)

        self.spark = []

        tk.Label(right, text="Signal feed", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 20, "bold")).pack(anchor="w")

        self.feed_canvas = tk.Canvas(right, bg=BG, highlightthickness=0, bd=0)
        self.feed_scrollbar = tk.Scrollbar(right, orient="vertical", command=self.feed_canvas.yview, bg=PANEL, troughcolor=BG, activebackground="#263347")
        self.feed_canvas.configure(yscrollcommand=self.feed_scrollbar.set)

        self.feed_canvas.pack(side="left", fill="both", expand=True, pady=(10, 0))
        self.feed_scrollbar.pack(side="right", fill="y", pady=(10, 0))

        self.feed = tk.Frame(self.feed_canvas, bg=BG)
        self.feed_window = self.feed_canvas.create_window((0, 0), window=self.feed, anchor="nw")

        self.feed.bind("<Configure>", self._on_feed_configure)
        self.feed_canvas.bind("<Configure>", self._on_feed_canvas_configure)
        self.feed_canvas.bind("<Enter>", self._bind_feed_mousewheel)
        self.feed_canvas.bind("<Leave>", self._unbind_feed_mousewheel)

        self._build_focus_tabs()

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill="x", pady=(12, 0))
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(footer, text="Overview shows the big hitters. Detail lives in Defender, Intune and UniFi tabs. No simulated telemetry.", bg=BG, fg="#526078", font=("Segoe UI", 9)).pack(side="right")

    def focus_card(self, parent, title, color, bucket, key, width_pack=True):
        f = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1, highlightbackground=HAIRLINE)
        if width_pack:
            f.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        else:
            f.pack(fill="x", padx=6, pady=6)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 26, "bold"))
        val.pack(anchor="w", padx=16, pady=(0, 2))
        hint = tk.Label(f, text="Awaiting data", bg=PANEL, fg="#8290A7", font=("Segoe UI", 8))
        hint.pack(anchor="w", padx=16, pady=(0, 12))
        self.focus_cards[bucket][key] = {"frame": f, "value": val, "hint": hint, "base": color}
        return f

    def text_panel(self, parent, title):
        wrap = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        top = tk.Frame(wrap, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI Variable Display", 16, "bold")).pack(side="left")
        text_frame = tk.Frame(wrap, bg=PANEL)
        text_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        widget = tk.Text(
            text_frame,
            bg="#10151D",
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            padx=14,
            pady=12
        )
        scroll = tk.Scrollbar(text_frame, orient="vertical", command=widget.yview)
        widget.configure(yscrollcommand=scroll.set)
        widget.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        widget.config(state="disabled")
        return widget

    def set_text_widget(self, widget, value):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.config(state="disabled")

    def _build_focus_tabs(self):
        # Defender tab
        defender_wrap = tk.Frame(self.tab_defender, bg=BG)
        defender_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        tk.Label(defender_wrap, text="Defender security view", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 22, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tk.Label(defender_wrap, text="A calmer, focused page for Microsoft security alerts and signal quality.", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=8, pady=(0, 12))

        row = tk.Frame(defender_wrap, bg=BG)
        row.pack(fill="x")
        self.focus_card(row, "Defender priority", AMBER, "defender", "priority_state")
        self.focus_card(row, "Defender active alerts", BLUE, "defender", "defender_alerts")
        self.focus_card(row, "High / critical Defender", RED, "defender", "defender_critical")
        self.focus_card(row, "Graph security context", PURPLE, "defender", "graph_alerts")
        self.defender_text = self.text_panel(defender_wrap, "Defender and Microsoft security rows")

        # Intune tab
        intune_wrap = tk.Frame(self.tab_intune, bg=BG)
        intune_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        tk.Label(intune_wrap, text="Intune estate view", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 22, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tk.Label(intune_wrap, text="Device inventory and compliance context, separated cleanly from Defender priority.", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=8, pady=(0, 12))

        row = tk.Frame(intune_wrap, bg=BG)
        row.pack(fill="x")
        self.focus_card(row, "Intune devices", GREEN, "intune", "devices")
        self.focus_card(row, "Non-compliant devices", AMBER, "intune", "noncompliant")
        self.focus_card(row, "Compliant devices", BLUE, "intune", "compliant_devices")
        self.focus_card(row, "Compliance rate", PURPLE, "intune", "compliance_percent")

        platform = tk.Frame(intune_wrap, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        platform.pack(fill="x", padx=6, pady=6)
        tk.Label(platform, text="Platform breakdown", bg=PANEL, fg=TEXT, font=("Segoe UI Variable Display", 16, "bold")).pack(anchor="w", padx=14, pady=(10, 8))
        self.intune_platform_focus = {}
        plat_row = tk.Frame(platform, bg=PANEL)
        plat_row.pack(fill="x", padx=6, pady=(0, 10))
        for label, key, color in [
            ("Windows", "windows", BLUE),
            ("iPhone / iPad", "ios", GREEN),
            ("Mac", "macos", PURPLE),
            ("Android", "android", AMBER),
            ("Other", "other_os", MUTED),
        ]:
            box = tk.Frame(plat_row, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=8)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            val = tk.Label(box, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 18, "bold"))
            val.pack(anchor="w")
            self.intune_platform_focus[key] = val

        self.intune_text = self.text_panel(intune_wrap, "Intune inventory and compliance summary")

        # UniFi tab
        unifi_wrap = tk.Frame(self.tab_unifi, bg=BG)
        unifi_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        tk.Label(unifi_wrap, text="UniFi network view", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 22, "bold")).pack(anchor="w", padx=8, pady=(0, 4))
        tk.Label(unifi_wrap, text="All network context on its own page, without affecting Defender headline severity.", bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=8, pady=(0, 12))

        status_shell = tk.Frame(unifi_wrap, bg=BG)
        status_shell.pack(fill="x")
        left_big = tk.Frame(status_shell, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        left_big.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        tk.Label(left_big, text="Network site status", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        self.unifi_tab_status_big = tk.Label(left_big, text="--", bg=PANEL, fg=BLUE, font=("Segoe UI Variable Display", 26, "bold"))
        self.unifi_tab_status_big.pack(anchor="w", padx=16, pady=(0, 2))
        self.unifi_tab_status_hint = tk.Label(left_big, text="Awaiting data", bg=PANEL, fg="#8290A7", font=("Segoe UI", 8))
        self.unifi_tab_status_hint.pack(anchor="w", padx=16, pady=(0, 12))

        right_stats = tk.Frame(status_shell, bg=BG)
        right_stats.pack(side="left", fill="both", expand=True)
        row_a = tk.Frame(right_stats, bg=BG)
        row_a.pack(fill="x")
        self.focus_card(row_a, "UniFi sites", GREEN, "unifi", "unifi_sites")
        self.focus_card(row_a, "UniFi devices", BLUE, "unifi", "unifi_devices")
        self.focus_card(row_a, "Offline sites", RED, "unifi", "unifi_critical_sites")
        row_b = tk.Frame(right_stats, bg=BG)
        row_b.pack(fill="x")
        self.focus_card(row_b, "Healthy sites", GREEN, "unifi", "unifi_healthy_sites")
        self.focus_card(row_b, "Degraded sites", AMBER, "unifi", "unifi_degraded_sites")
        self.focus_card(row_b, "UniFi alerts", AMBER, "unifi", "unifi_alerts")

        self.unifi_text = self.text_panel(unifi_wrap, "UniFi site and connector detail")

    def card(self, parent, row, col, title, key, color):
        f = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1, highlightbackground=HAIRLINE)
        f.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI Variable Text", 9, "bold")).pack(anchor="w", padx=18, pady=(16, 2))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 30, "bold"))
        val.pack(anchor="w", padx=18, pady=(0, 2))
        hint = tk.Label(f, text="Awaiting data", bg=PANEL, fg="#8490A3", font=("Segoe UI", 8))
        hint.pack(anchor="w", padx=18, pady=(0, 12))
        self.metric_labels[key] = val
        self.metric_cards[key] = {"frame": f, "value": val, "hint": hint, "base": color}

    def metric_style(self, key, val):
        raw = str(val)
        num = safe_float(val, 0)
        if key == "priority_state":
            state = raw.upper()
            if state == "CRITICAL":
                return RED, "Defender high/critical active"
            if state == "HIGH":
                return RED, "high Defender volume"
            if state == "ACTION":
                return AMBER, "Defender investigation required"
            return GREEN, "no active Defender alerts"
        if key == "risk":
            return MUTED, "deprecated"
        if key == "alerts":
            if num >= 100:
                return RED, "active security alert volume"
            if num >= 25:
                return AMBER, "active security alert volume"
            if num > 0:
                return BLUE, "active security context"
            return GREEN, "no active security alerts"
        if key == "noncompliant":
            if num >= 100:
                return AMBER, "device compliance context"
            if num >= 25:
                return AMBER, "Intune compliance context"
            if num > 0:
                return BLUE, "device compliance context"
            return GREEN, "all Intune devices compliant"
        if key == "critical":
            if num > 0:
                return RED, "active high/critical Defender"
            return GREEN, "no high/critical Defender"
        if key == "wan_health":
            if num <= 0:
                return MUTED, "no network source"
            if num < 90:
                return RED, "unstable"
            if num < 95:
                return AMBER, "degraded"
            if num < 98:
                return BLUE, "good"
            return GREEN, "excellent"
        if key == "devices":
            if num <= 0:
                return AMBER, "no Intune inventory"
            return GREEN, "Intune inventory visible"
        return BLUE, "live"

    def overall_state(self, metrics):
        state = str(metrics.get("priority_state", "CLEAR")).upper()
        if state == "CRITICAL":
            return "CRITICAL", RED
        if state == "HIGH":
            return "HIGH", RED
        if state == "ACTION":
            return "ACTION", AMBER
        return "CLEAR", GREEN





    def _on_unifi_site_table_configure(self, event=None):
        if hasattr(self, "unifi_site_table_canvas"):
            self.unifi_site_table_canvas.configure(scrollregion=self.unifi_site_table_canvas.bbox("all"))

    def _on_unifi_site_table_canvas_configure(self, event):
        if hasattr(self, "unifi_site_table_canvas") and hasattr(self, "unifi_site_table_window"):
            self.unifi_site_table_canvas.itemconfigure(self.unifi_site_table_window, width=event.width)

    def _unifi_site_table_mousewheel(self, event):
        if hasattr(self, "unifi_site_table_canvas"):
            delta = -1 * int(event.delta / 120) if event.delta else 0
            self.unifi_site_table_canvas.yview_scroll(delta, "units")

    def _unifi_site_table_mousewheel_linux_up(self, event):
        if hasattr(self, "unifi_site_table_canvas"):
            self.unifi_site_table_canvas.yview_scroll(-3, "units")

    def _unifi_site_table_mousewheel_linux_down(self, event):
        if hasattr(self, "unifi_site_table_canvas"):
            self.unifi_site_table_canvas.yview_scroll(3, "units")

    def _bind_unifi_site_table_mousewheel(self, event=None):
        if hasattr(self, "unifi_site_table_canvas"):
            self.unifi_site_table_canvas.bind_all("<MouseWheel>", self._unifi_site_table_mousewheel)
            self.unifi_site_table_canvas.bind_all("<Button-4>", self._unifi_site_table_mousewheel_linux_up)
            self.unifi_site_table_canvas.bind_all("<Button-5>", self._unifi_site_table_mousewheel_linux_down)

    def _unbind_unifi_site_table_mousewheel(self, event=None):
        if hasattr(self, "unifi_site_table_canvas"):
            self.unifi_site_table_canvas.unbind_all("<MouseWheel>")
            self.unifi_site_table_canvas.unbind_all("<Button-4>")
            self.unifi_site_table_canvas.unbind_all("<Button-5>")

    def render_unifi_site_table(self, sites):
        if not hasattr(self, "unifi_site_table"):
            return

        for child in self.unifi_site_table.winfo_children():
            child.destroy()

        if not sites:
            self.unifi_site_health_summary.config(text="No UniFi sites returned")
            empty = tk.Frame(self.unifi_site_table, bg=PANEL)
            empty.pack(fill="x", pady=3)
            tk.Label(empty, text="No UniFi site rows returned yet.", bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=6, pady=6)
            return

        healthy = sum(1 for s in sites if str(s.get("status", "")).upper() == "HEALTHY")
        degraded = sum(1 for s in sites if str(s.get("status", "")).upper() == "DEGRADED")
        critical = sum(1 for s in sites if str(s.get("status", "")).upper() == "CRITICAL")
        visible = sum(1 for s in sites if str(s.get("status", "")).upper() == "VISIBLE")
        unassigned = sum(1 for s in sites if "unassigned" in str(s.get("name", "")).lower())
        suffix = f" • {unassigned} unassigned mapping row" if unassigned else ""
        self.unifi_site_health_summary.config(
            text=f"{len(sites)} rows • healthy {healthy} • degraded {degraded} • critical {critical} • visible {visible}{suffix}"
        )

        header = tk.Frame(self.unifi_site_table, bg="#1A2230")
        header.pack(fill="x", pady=(0, 2))
        for title, width in [
            ("Site", 36),
            ("Status", 10),
            ("Devices", 8),
            ("Online", 8),
            ("Offline", 8),
            ("Degraded", 9),
            ("Unknown", 9),
        ]:
            tk.Label(header, text=title, bg="#1A2230", fg=MUTED, font=("Segoe UI", 8, "bold"), width=width, anchor="w").pack(side="left", padx=3, pady=4)

        status_color = {"HEALTHY": GREEN, "DEGRADED": AMBER, "CRITICAL": RED, "VISIBLE": BLUE}
        for site in sites[:80]:
            status = str(site.get("status", "VISIBLE")).upper()
            color = status_color.get(status, BLUE)
            row = tk.Frame(self.unifi_site_table, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=str(site.get("name", "UniFi site"))[:48], bg=PANEL, fg=TEXT, font=("Segoe UI", 8, "bold"), width=36, anchor="w").pack(side="left", padx=3, pady=4)
            tk.Label(row, text=status, bg=PANEL, fg=color, font=("Segoe UI", 8, "bold"), width=10, anchor="w").pack(side="left", padx=3, pady=4)
            for key, width in [("total", 8), ("online", 8), ("offline", 8), ("degraded", 9), ("unknown", 9)]:
                tk.Label(row, text=str(site.get(key, 0)), bg=PANEL, fg=MUTED if key != "offline" or int(site.get(key, 0) or 0) == 0 else RED, font=("Segoe UI", 8), width=width, anchor="w").pack(side="left", padx=3, pady=4)

        self.unifi_site_table.update_idletasks()
        self.unifi_site_table_canvas.configure(scrollregion=self.unifi_site_table_canvas.bbox("all"))


    def _on_alert_table_configure(self, event=None):
        if hasattr(self, "alert_table_canvas"):
            self.alert_table_canvas.configure(scrollregion=self.alert_table_canvas.bbox("all"))

    def _on_alert_table_canvas_configure(self, event):
        if hasattr(self, "alert_table_canvas") and hasattr(self, "alert_table_window"):
            self.alert_table_canvas.itemconfigure(self.alert_table_window, width=event.width)

    def _alert_table_mousewheel(self, event):
        if hasattr(self, "alert_table_canvas"):
            delta = -1 * int(event.delta / 120) if event.delta else 0
            self.alert_table_canvas.yview_scroll(delta, "units")

    def _alert_table_mousewheel_linux_up(self, event):
        if hasattr(self, "alert_table_canvas"):
            self.alert_table_canvas.yview_scroll(-3, "units")

    def _alert_table_mousewheel_linux_down(self, event):
        if hasattr(self, "alert_table_canvas"):
            self.alert_table_canvas.yview_scroll(3, "units")

    def _bind_alert_table_mousewheel(self, event=None):
        if hasattr(self, "alert_table_canvas"):
            self.alert_table_canvas.bind_all("<MouseWheel>", self._alert_table_mousewheel)
            self.alert_table_canvas.bind_all("<Button-4>", self._alert_table_mousewheel_linux_up)
            self.alert_table_canvas.bind_all("<Button-5>", self._alert_table_mousewheel_linux_down)

    def _unbind_alert_table_mousewheel(self, event=None):
        if hasattr(self, "alert_table_canvas"):
            self.alert_table_canvas.unbind_all("<MouseWheel>")
            self.alert_table_canvas.unbind_all("<Button-4>")
            self.alert_table_canvas.unbind_all("<Button-5>")

    def render_alert_table(self, rows, metrics):
        if not hasattr(self, "alert_table"):
            return
        for child in self.alert_table.winfo_children():
            child.destroy()

        summary = f"Active security {metrics.get('active_alerts', metrics.get('alerts', 0))} • Returned {metrics.get('returned_alerts', 0)} • Resolved/closed {metrics.get('resolved_alerts', 0)}"
        self.alert_table_summary.config(text=summary)

        headers = [("Connector", 18), ("Severity", 10), ("Status", 14), ("Alert / finding", 42)]
        header_row = tk.Frame(self.alert_table, bg="#1A2230")
        header_row.pack(fill="x", pady=(0, 2))
        for title, width in headers:
            tk.Label(header_row, text=title, bg="#1A2230", fg=MUTED, font=("Segoe UI", 8, "bold"), width=width, anchor="w").pack(side="left", padx=4, pady=5)

        sev_color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": AMBER, "INFO": BLUE, "LOW": GREEN}
        active_rows = rows[:120]
        if not active_rows:
            empty = tk.Frame(self.alert_table, bg=PANEL)
            empty.pack(fill="x", pady=4)
            tk.Label(empty, text="No live alert rows returned by configured connectors.", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=8, pady=8)
        for row in active_rows:
            sev = str(row.get("severity", "INFO")).upper()
            color = sev_color.get(sev, BLUE)
            status = str(row.get("status", "ACTIVE"))
            bg = "#121827" if status != "RESOLVED/CLOSED" else "#101522"
            r = tk.Frame(self.alert_table, bg=bg, highlightthickness=1, highlightbackground=HAIRLINE)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=row.get("source", ""), bg=bg, fg=TEXT, font=("Segoe UI", 8, "bold"), width=18, anchor="w").pack(side="left", padx=4, pady=5)
            tk.Label(r, text=sev, bg=bg, fg=color, font=("Segoe UI", 8, "bold"), width=10, anchor="w").pack(side="left", padx=4, pady=5)
            status_fg = GREEN if status == "ACTIVE" else BLUE if status == "NETWORK" else MUTED
            tk.Label(r, text=status, bg=bg, fg=status_fg, font=("Segoe UI", 8, "bold"), width=14, anchor="w").pack(side="left", padx=4, pady=5)
            text_value = row.get("title", "")
            detail = row.get("detail", "")
            if detail:
                text_value = f"{text_value} | {detail}"
            tk.Label(r, text=text_value, bg=bg, fg=TEXT if status == "ACTIVE" else MUTED, font=("Segoe UI", 8), anchor="w", justify="left", wraplength=620).pack(side="left", fill="x", expand=True, padx=4, pady=5)

        self.alert_table.update_idletasks()
        self.alert_table_canvas.configure(scrollregion=self.alert_table_canvas.bbox("all"))


    def _on_feed_configure(self, event=None):
        if hasattr(self, "feed_canvas"):
            self.feed_canvas.configure(scrollregion=self.feed_canvas.bbox("all"))

    def _on_feed_canvas_configure(self, event):
        if hasattr(self, "feed_canvas") and hasattr(self, "feed_window"):
            self.feed_canvas.itemconfigure(self.feed_window, width=event.width)

    def _feed_mousewheel(self, event):
        if hasattr(self, "feed_canvas"):
            delta = -1 * int(event.delta / 120) if event.delta else 0
            self.feed_canvas.yview_scroll(delta, "units")

    def _feed_mousewheel_linux_up(self, event):
        if hasattr(self, "feed_canvas"):
            self.feed_canvas.yview_scroll(-3, "units")

    def _feed_mousewheel_linux_down(self, event):
        if hasattr(self, "feed_canvas"):
            self.feed_canvas.yview_scroll(3, "units")

    def _bind_feed_mousewheel(self, event=None):
        if hasattr(self, "feed_canvas"):
            self.feed_canvas.bind_all("<MouseWheel>", self._feed_mousewheel)
            self.feed_canvas.bind_all("<Button-4>", self._feed_mousewheel_linux_up)
            self.feed_canvas.bind_all("<Button-5>", self._feed_mousewheel_linux_down)

    def _unbind_feed_mousewheel(self, event=None):
        if hasattr(self, "feed_canvas"):
            self.feed_canvas.unbind_all("<MouseWheel>")
            self.feed_canvas.unbind_all("<Button-4>")
            self.feed_canvas.unbind_all("<Button-5>")


    def connector_enabled(self, section):
        return bool(self.cfg.get(section, {}).get("enabled", False))

    def set_widget_visible(self, widget, visible, manager="pack", **opts):
        if not widget:
            return
        if visible:
            if manager == "pack" and not widget.winfo_manager():
                widget.pack(**opts)
            elif manager == "grid" and not widget.winfo_manager():
                widget.grid(**opts)
        else:
            if widget.winfo_manager():
                widget.pack_forget() if manager == "pack" else widget.grid_forget()

    def update_configured_visibility(self, metrics, sources):
        """Hide optional connector UI unless the connector is configured and returning live data."""
        microsoft_live = any("Microsoft" in s or "Defender" in s for s in sources.get("live", []))
        network_live = any("UniFi" in s for s in sources.get("live", []))

        # UniFi gets its own small strip. WAN remains hidden until deeper UniFi health is mapped.
        if hasattr(self, "unifi_bar"):
            if network_live or int(metrics.get("unifi_connected", 0) or 0) > 0:
                if not self.unifi_bar.winfo_manager():
                    self.unifi_bar.pack(fill="x", pady=(8, 0), )
            else:
                if self.unifi_bar.winfo_manager():
                    self.unifi_bar.pack_forget()

        if hasattr(self, "unifi_site_health_bar"):
            if network_live or int(metrics.get("unifi_connected", 0) or 0) > 0:
                if not self.unifi_site_health_bar.winfo_manager():
                    pass  # Detailed UniFi site rows live on the UniFi tab.
            else:
                if self.unifi_site_health_bar.winfo_manager():
                    self.unifi_site_health_bar.pack_forget()

        # Platform and alert breakdown bars are Microsoft-specific.
        for bar in getattr(self, "optional_bars", []):
            if microsoft_live:
                if not bar.winfo_manager():
                    bar.pack(fill="x", pady=(8, 0))
            else:
                if bar.winfo_manager():
                    bar.pack_forget()


    def export_unifi_debug(self):
        try:
            conn = UniFiConnector(self.cfg)
            snapshot = conn.debug_snapshot()
            default_name = f"unifi_debug_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            path = filedialog.asksaveasfilename(
                title="Save UniFi debug JSON",
                defaultextension=".json",
                initialfile=default_name,
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not path:
                return
            Path(path).write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            messagebox.showinfo("UniFi debug exported", f"Saved UniFi debug sample to:\n{path}\n\nRedact IDs if sharing outside Smartbox.")
        except Exception as e:
            messagebox.showerror("UniFi debug export failed", str(e))


    def open_setup(self):
        win = tk.Toplevel(self)
        win.title("Dasher setup")
        win.geometry("780x690")
        win.configure(bg=BG)
        win.transient(self)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=16, pady=16)
        entries = {}

        def add_tab(name, section, fields):
            frame = tk.Frame(nb, bg=PANEL)
            nb.add(frame, text=name)
            row = 0
            enabled = tk.BooleanVar(value=bool(self.cfg[section].get("enabled", False)))
            demo = tk.Checkbutton(frame, text=f"Enable {name} connector", variable=enabled, bg=PANEL, fg=TEXT, selectcolor=PANEL, activebackground=PANEL)
            demo.grid(row=row, column=0, columnspan=2, sticky="w", padx=18, pady=14)
            entries[(section, "enabled")] = enabled
            row += 1
            for label, key, secret in fields:
                tk.Label(frame, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).grid(row=row, column=0, sticky="w", padx=18, pady=(8, 2))
                var = tk.StringVar(value=self.cfg[section].get(key, ""))
                ent = tk.Entry(frame, textvariable=var, show="*" if secret else "", bg="#0F1524", fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 10))
                ent.grid(row=row, column=1, sticky="ew", padx=18, pady=(8, 2), ipady=8)
                entries[(section, key)] = var
                row += 1
            frame.grid_columnconfigure(1, weight=1)

        general = tk.Frame(nb, bg=PANEL)
        nb.add(general, text="General")
        demo_var = tk.BooleanVar(value=bool(self.cfg.get("demo_mode", True)))
        poll_var = tk.StringVar(value=str(self.cfg.get("poll_seconds", 8)))
        tk.Checkbutton(general, text="Legacy demo mode flag disabled in this build", variable=demo_var, bg=PANEL, fg=TEXT, selectcolor=PANEL, activebackground=PANEL, state="disabled").pack(anchor="w", padx=18, pady=16)
        tk.Label(general, text="Poll interval seconds", bg=PANEL, fg=MUTED).pack(anchor="w", padx=18)
        tk.Entry(general, textvariable=poll_var, bg="#0F1524", fg=TEXT, insertbackground=TEXT, relief="flat").pack(fill="x", padx=18, pady=8, ipady=8)

        add_tab("Microsoft", "microsoft", [
            ("Tenant ID", "tenant_id", False),
            ("App/client ID", "client_id", False),
            ("Client secret", "client_secret", True),
            ("Defender API URL", "defender_api_url", False),
        ])
        add_tab("UniFi", "unifi", [
            ("Base URL", "base_url", False),
            ("API key", "api_key", True),
            ("Site ID optional", "site_id", False),
            ("Alerts path optional", "alerts_path", False),
            ("Site health path optional", "site_health_path", False),
            ("Site name map optional", "site_name_map", False),
        ])
        add_tab("Datto RMM", "datto", [
            ("API URL, e.g. https://vidal-api.centrastage.net", "api_url", False),
            ("Bearer access token", "access_token", True),
        ])
        add_tab("RocketCyber", "rocketcyber", [
            ("Base URL", "base_url", False),
            ("API key / bearer token", "api_key", True),
        ])

        def save():
            self.cfg["demo_mode"] = bool(demo_var.get())
            self.cfg["poll_seconds"] = int(safe_float(poll_var.get(), 8))
            for (section, key), var in entries.items():
                self.cfg[section][key] = bool(var.get()) if key == "enabled" else var.get().strip()
            Config.save(self.cfg)
            self.restart_engine()
            win.destroy()

        tk.Button(win, text="Save and restart telemetry", command=save, bg="#1A2330", fg=TEXT, activebackground="#263347", relief="flat", padx=14, pady=12, font=("Segoe UI", 10, "bold")).pack(pady=(0, 16))

    def start_engine(self):
        self.engine = TelemetryEngine(self.cfg, self.q)
        self.engine.start()

    def restart_engine(self):
        if self.engine:
            self.engine.stop_flag.set()
        self.q = queue.Queue()
        self.start_engine()
        self.status_var.set("Telemetry restarted with updated connector settings.")

    def drain_queue(self):
        try:
            while True:
                payload = self.q.get_nowait()
                if "error" in payload:
                    self.status_var.set("Telemetry error: " + payload["error"][:120])
                else:
                    self.render(payload)
        except queue.Empty:
            pass
        self.after(250, self.drain_queue)

    def render(self, payload):
        self.last_payload = payload
        m = payload["metrics"]
        self.update_configured_visibility(m, payload["sources"])
        for key, val in m.items():
            suffix = "%" if key == "wan_health" else ""
            if key in self.metric_labels:
                color, hint = self.metric_style(key, val)
                display = str(val).upper() if key == "priority_state" else f"{val}{suffix}"
                self.metric_labels[key].config(text=display, fg=color)
                self.metric_cards[key]["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
                self.metric_cards[key]["frame"].config(highlightbackground=color)

        for key, label in self.platform_labels.items():
            label.config(text=str(m.get(key, 0)))

        for key, label in self.alert_breakdown_labels.items():
            label.config(text=str(m.get(key, 0)))

        # Show Intune device/compliance context directly under the Compliance gap card.
        if "noncompliant" in self.metric_cards:
            devices_total = int(m.get("devices", 0) or 0)
            gap = int(m.get("noncompliant", 0) or 0)
            compliant = int(m.get("compliant_devices", max(0, devices_total - gap)) or 0)
            percent = int(m.get("compliance_percent", 0) or 0)
            if devices_total:
                self.metric_cards["noncompliant"]["hint"].config(
                    text=f"{gap} non-compliant • {compliant} compliant • {percent}% compliant",
                    fg=MUTED if gap == 0 else AMBER if gap < 100 else RED,
                )
            else:
                self.metric_cards["noncompliant"]["hint"].config(
                    text="No Intune device inventory returned",
                    fg=MUTED,
                )

        for key, label in self.unifi_labels.items():
            if key == "unifi_status":
                label.config(text="LIVE" if int(m.get("unifi_connected", 0) or 0) > 0 else "--")
            else:
                label.config(text=str(m.get(key, 0)))

        if hasattr(self, "network_status_big"):
            offline_sites = int(m.get("unifi_critical_sites", 0) or 0)
            degraded_sites = int(m.get("unifi_degraded_sites", 0) or 0)
            healthy_sites = int(m.get("unifi_healthy_sites", 0) or 0)
            total_sites = int(m.get("unifi_sites", 0) or 0)
            network_devices = int(m.get("unifi_devices", 0) or 0)
            if total_sites == 0:
                network_state, network_color = "NO DATA", MUTED
            elif offline_sites > 0:
                network_state, network_color = "ATTENTION", AMBER
            elif degraded_sites > 0:
                network_state, network_color = "DEGRADED", AMBER
            else:
                network_state, network_color = "GOOD", GREEN
            self.network_status_big.config(text=network_state, fg=network_color)
            self.network_status_detail.config(
                text=f"{healthy_sites}/{total_sites} sites healthy • {offline_sites} site offline • {degraded_sites} site degraded • {network_devices} network devices",
                fg=network_color if network_state != "GOOD" else TEXT
            )

        self.render_unifi_site_table(m.get("unifi_site_health", []) or [])

        # Final compliance-card override: keep Compliance gap as context, not priority.
        if "noncompliant" in self.metric_cards:
            devices_total = int(m.get("devices", 0) or 0)
            gap = int(m.get("noncompliant", 0) or 0)
            compliant = int(m.get("compliant_devices", max(0, devices_total - gap)) or 0)
            percent = int(m.get("compliance_percent", 0) or 0)
            if devices_total:
                self.metric_cards["noncompliant"]["hint"].config(
                    text=f"{gap} non-compliant • {compliant} compliant • {percent}% compliant",
                    fg=MUTED if gap == 0 else AMBER if gap < 100 else RED,
                )

        state_text, state_color = self.overall_state(m)

        live = ", ".join(payload["sources"]["live"]) or "no configured live connector"
        self.state_badge.config(text=state_text, fg=state_color)
        unifi_bit = f" • UniFi sites {m.get('unifi_sites', 0)} • UniFi devices {m.get('unifi_devices', 0)} • UniFi alerts {m.get('unifi_alerts', 0)} • UniFi degraded {m.get('unifi_degraded_sites', 0)} • UniFi critical {m.get('unifi_critical_sites', 0)}" if int(m.get("unifi_connected", 0) or 0) > 0 else ""
        self.state_detail.config(text=f"Defender priority: {m.get('priority_reason', 'live counts')} • Defender active {m.get('defender_alerts', 0)} • Defender critical {m.get('defender_critical', 0)} • Intune devices {m.get('devices', 0)} • Intune compliance gap {m.get('noncompliant', 0)} • Graph active context {m.get('graph_alerts', 0)}{unifi_bit}")
        self.live_badge.config(text=f"LIVE: {live.upper()}", fg=GREEN if live != "none" else MUTED)

        if hasattr(self, "overview_focus_text"):
            defender = int(m.get("defender_alerts", 0) or 0)
            defender_critical = int(m.get("defender_critical", 0) or 0)
            noncompliant = int(m.get("noncompliant", 0) or 0)
            intune_devices = int(m.get("devices", 0) or 0)
            offline_sites = int(m.get("unifi_critical_sites", 0) or 0)
            total_sites = int(m.get("unifi_sites", 0) or 0)
            self.overview_focus_text.config(
                text=f"Defender: {defender} active, {defender_critical} high/critical   •   Intune: {intune_devices} devices, {noncompliant} non-compliant   •   UniFi: {total_sites} sites, {offline_sites} offline"
            )

        self.spark.append(m.get("alerts", 0))
        self.spark = self.spark[-80:]
        self.render_alert_table(payload.get("alert_rows", []), m)
        self.render_focus_views(payload)

        for child in self.feed.winfo_children():
            child.destroy()

        sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sev_color = {"critical": RED, "high": RED, "medium": AMBER, "info": BLUE, "low": GREEN}
        sev_bg = {"critical": "#22141A", "high": "#22141A", "medium": "#211D13", "info": "#121B28", "low": "#102019"}
        events = sorted(payload["events"][:100], key=lambda e: sev_priority.get(str(e.get("severity", "info")).lower(), 9))
        for event in events:
            sev = str(event.get("severity", "info")).lower()
            color = sev_color.get(sev, BLUE)
            bg = sev_bg.get(sev, PANEL)
            f = tk.Frame(self.feed, bg=bg, highlightthickness=1, highlightbackground="#2B3545")
            f.pack(fill="x", pady=5)
            top = tk.Frame(f, bg=bg)
            top.pack(fill="x", padx=12, pady=(8, 0))
            tk.Label(top, text=sev.upper(), bg=bg, fg=color, font=("Segoe UI", 8, "bold")).pack(side="left")
            tk.Label(top, text=event.get("source", "source"), bg=bg, fg="#8D9BB5", font=("Segoe UI", 8, "bold")).pack(side="right")
            tk.Label(f, text=event.get("title", "event"), bg=bg, fg=TEXT, font=("Segoe UI", 10, "bold"), wraplength=320, justify="left").pack(anchor="w", padx=12, pady=(4,0))
            tk.Label(f, text=event.get("detail", ""), bg=bg, fg=MUTED, font=("Segoe UI", 8), wraplength=320, justify="left").pack(anchor="w", padx=12, pady=(0, 8))

        self.feed.update_idletasks()
        self.feed_canvas.configure(scrollregion=self.feed_canvas.bbox("all"))

        unifi_footer = f" | UniFi: {m.get('unifi_alerts', 0)}" if int(m.get("unifi_connected", 0) or 0) > 0 else ""
        self.status_var.set(f"Updated {dt.datetime.now().strftime('%H:%M:%S')} | state: {state_text.lower()} | live: {live} | active: {m.get('active_alerts', m.get('alerts', 0))} | returned: {m.get('returned_alerts', 0)} | resolved/closed: {m.get('resolved_alerts', 0)} | Defender critical: {m.get('defender_critical', 0)} | Intune devices: {m.get('devices', 0)} | compliance gap: {m.get('noncompliant', 0)}")

    def render_focus_views(self, payload):
        m = payload.get("metrics", {})
        rows = payload.get("alert_rows", []) or []
        events = payload.get("events", []) or []

        # Defender focused cards
        for key, card in self.focus_cards["defender"].items():
            if key == "priority_state":
                value = str(m.get("priority_state", "--")).upper()
            else:
                value = str(m.get(key, 0))
            card["value"].config(text=value)
            if key == "priority_state":
                color, hint = self.metric_style("priority_state", m.get("priority_state", "CLEAR"))
            elif key == "defender_critical":
                color = RED if int(m.get("defender_critical", 0) or 0) > 0 else GREEN
                hint = "high / critical Defender active" if int(m.get("defender_critical", 0) or 0) > 0 else "no high / critical Defender"
            elif key == "defender_alerts":
                count = int(m.get("defender_alerts", 0) or 0)
                color = RED if count >= 25 else AMBER if count > 0 else GREEN
                hint = "Defender active alerts"
            elif key == "graph_alerts":
                count = int(m.get("graph_alerts", 0) or 0)
                color = PURPLE if count > 0 else GREEN
                hint = "Graph / MDO active context"
            else:
                color, hint = BLUE, "live"
            card["value"].config(fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        ms_rows = []
        for r in rows:
            src = str(r.get("source", ""))
            if src in ("Defender for Endpoint", "Graph Security", "Microsoft Graph"):
                ms_rows.append(r)

        def_lines = []
        def_lines.append(f"Defender priority: {m.get('priority_state', 'CLEAR')}")
        def_lines.append(f"Defender active alerts: {m.get('defender_alerts', 0)} | high/critical: {m.get('defender_critical', 0)} | Graph context: {m.get('graph_alerts', 0)}")
        def_lines.append("")
        def_lines.append("Security rows")
        def_lines.append("-" * 90)
        if not ms_rows:
            def_lines.append("No Microsoft security rows returned.")
        for r in ms_rows[:250]:
            sev = str(r.get("severity", "INFO")).upper()
            status = str(r.get("status", "ACTIVE"))
            src = str(r.get("source", ""))
            title = str(r.get("title", ""))
            detail = str(r.get("detail", ""))
            line = f"[{status:<15}] {sev:<8} | {src:<22} | {title}"
            if detail:
                line += f"\n    {detail}"
            def_lines.append(line)
        if events:
            def_lines.append("")
            def_lines.append("Signal feed")
            def_lines.append("-" * 90)
            for e in events[:40]:
                src = str(e.get("source", ""))
                if src in ("Defender for Endpoint", "Graph Security", "Microsoft Graph", "Microsoft"):
                    def_lines.append(f"{str(e.get('severity','info')).upper():<8} | {src:<22} | {e.get('title','')}")
        self.set_text_widget(self.defender_text, "\n".join(def_lines))

        # Intune focused cards
        for key, card in self.focus_cards["intune"].items():
            val = m.get(key, 0)
            suffix = "%" if key == "compliance_percent" else ""
            color = card["base"]
            hint = "live"
            if key == "devices":
                color, hint = self.metric_style("devices", val)
            elif key == "noncompliant":
                color, hint = self.metric_style("noncompliant", val)
            elif key == "compliant_devices":
                color = GREEN
                hint = "compliant Intune inventory"
            elif key == "compliance_percent":
                pct = int(val or 0)
                color = GREEN if pct >= 90 else AMBER if pct >= 75 else RED
                hint = "overall Intune compliance rate"
            card["value"].config(text=f"{val}{suffix}", fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        for key, label in getattr(self, "intune_platform_focus", {}).items():
            label.config(text=str(m.get(key, 0)))

        total = int(m.get("devices", 0) or 0)
        noncompliant = int(m.get("noncompliant", 0) or 0)
        compliant = int(m.get("compliant_devices", max(0, total - noncompliant)) or 0)
        pct = int(m.get("compliance_percent", 0) or 0)
        int_lines = [
            f"Total Intune devices : {total}",
            f"Compliant devices    : {compliant}",
            f"Non-compliant devices: {noncompliant}",
            f"Compliance rate      : {pct}%",
            "",
            "Platform breakdown",
            "-" * 90,
            f"Windows      : {m.get('windows', 0)}",
            f"iPhone / iPad: {m.get('ios', 0)}",
            f"Mac          : {m.get('macos', 0)}",
            f"Android      : {m.get('android', 0)}",
            f"Other OS     : {m.get('other_os', 0)}",
            "",
            "Context",
            "-" * 90,
            f"Graph security active context: {m.get('graph_alerts', 0)}",
            "Defender headline severity is intentionally separate from Intune compliance.",
        ]
        graph_rows = [r for r in rows if str(r.get("source","")) == "Microsoft Graph"]
        if graph_rows:
            int_lines += ["", "Microsoft Graph rows", "-" * 90]
            for r in graph_rows[:50]:
                title = str(r.get("title", ""))
                detail = str(r.get("detail", ""))
                line = f"{title}"
                if detail:
                    line += f"\n    {detail}"
                int_lines.append(line)
        else:
            int_lines += ["", "No dedicated Microsoft Graph rows returned in this poll."]
        self.set_text_widget(self.intune_text, "\n".join(int_lines))

        # UniFi focused cards and summary
        for key, card in self.focus_cards["unifi"].items():
            val = m.get(key, 0)
            color = card["base"]
            if key == "unifi_critical_sites":
                color = RED if int(val or 0) > 0 else GREEN
                hint = "offline / critical sites"
            elif key == "unifi_degraded_sites":
                color = AMBER if int(val or 0) > 0 else GREEN
                hint = "degraded sites"
            elif key == "unifi_alerts":
                color = AMBER if int(val or 0) > 0 else GREEN
                hint = "UniFi alert endpoint count"
            elif key == "unifi_devices":
                color = BLUE if int(val or 0) > 0 else MUTED
                hint = "network devices discovered"
            elif key == "unifi_sites":
                color = GREEN if int(val or 0) > 0 else MUTED
                hint = "sites returned"
            else:
                hint = "live"
            card["value"].config(text=str(val), fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        offline_sites = int(m.get("unifi_critical_sites", 0) or 0)
        degraded_sites = int(m.get("unifi_degraded_sites", 0) or 0)
        healthy_sites = int(m.get("unifi_healthy_sites", 0) or 0)
        total_sites = int(m.get("unifi_sites", 0) or 0)
        network_devices = int(m.get("unifi_devices", 0) or 0)
        if total_sites == 0:
            network_state, network_color = "NO DATA", MUTED
        elif offline_sites > 0:
            network_state, network_color = "ATTENTION", AMBER
        elif degraded_sites > 0:
            network_state, network_color = "DEGRADED", AMBER
        else:
            network_state, network_color = "GOOD", GREEN
        self.unifi_tab_status_big.config(text=network_state, fg=network_color)
        self.unifi_tab_status_hint.config(
            text=f"{healthy_sites}/{total_sites} sites healthy • {offline_sites} site offline • {degraded_sites} site degraded • {network_devices} devices",
            fg=network_color if network_state != "GOOD" else "#8FD7B9"
        )
        sites = m.get("unifi_site_health", []) or []
        uni_lines = [
            f"Network site status: {network_state}",
            f"UniFi sites: {total_sites} | devices: {network_devices} | fully offline sites: {offline_sites} | degraded sites: {degraded_sites} | alerts: {m.get('unifi_alerts', 0)}",
            "",
            "Site inventory. CRITICAL = all devices offline. DEGRADED = partial device issue.",
            "-" * 110,
        ]
        if not sites:
            uni_lines.append("No UniFi site rows returned.")
        else:
            for s in sites[:200]:
                uni_lines.append(
                    f"{str(s.get('name','UniFi site')):<28} | {str(s.get('status','VISIBLE')):<8} | total {int(s.get('total',0) or 0):>3} | online {int(s.get('online',0) or 0):>3} | offline {int(s.get('offline',0) or 0):>3} | degraded {int(s.get('degraded',0) or 0):>3} | unknown {int(s.get('unknown',0) or 0):>3}"
                )
        uni_rows = [r for r in rows if str(r.get("source","")) == "UniFi"]
        if uni_rows:
            uni_lines += ["", "UniFi connector notes", "-" * 110]
            for r in uni_rows[:80]:
                title = str(r.get("title", ""))
                detail = str(r.get("detail", ""))
                line = title
                if detail:
                    line += f"\n    {detail}"
                uni_lines.append(line)
        self.set_text_widget(self.unifi_text, "\n".join(uni_lines))

    def draw_spark(self):
        if not hasattr(self, "canvas"):
            return
        self.canvas.delete("all")
        w = max(10, self.canvas.winfo_width())
        h = max(10, self.canvas.winfo_height())
        self.canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline="")
        current = self.spark[-1] if self.spark else 0
        line_color = RED if current >= 100 else AMBER if current >= 25 else BLUE if current > 0 else GREEN
        self.canvas.create_text(24, 24, anchor="w", text="Alert telemetry", fill=TEXT, font=("Segoe UI Variable Display", 18, "bold"))
        self.canvas.create_text(24, 52, anchor="w", text="Live active unresolved alert trend from Defender, Graph Security, and UniFi", fill=MUTED, font=("Segoe UI", 10))
        self.canvas.create_text(w - 24, 24, anchor="e", text=f"Current active unresolved alerts {int(current)}", fill=line_color, font=("Segoe UI", 11, "bold"))
        if len(self.spark) < 2:
            return
        left, top, right, bottom = 32, 84, w - 40, h - 30
        max_value = max(max(self.spark), 10)
        scale_top = max(10, int(((max_value + 24) // 25) * 25))
        for y in range(0, scale_top + 1, max(1, scale_top // 4)):
            yy = bottom - (y / max(scale_top, 1)) * (bottom - top)
            self.canvas.create_line(left, yy, right, yy, fill="#202B44")
            self.canvas.create_text(right + 6, yy, anchor="w", text=str(y), fill="#526078", font=("Segoe UI", 8))
        pts = []
        for i, v in enumerate(self.spark):
            x = left + (i / max(1, len(self.spark) - 1)) * (right - left)
            y = bottom - (v / max(scale_top, 1)) * (bottom - top)
            pts.extend([x, y])
        self.canvas.create_line(*pts, fill=line_color, width=3, smooth=True)
        x, y = pts[-2], pts[-1]
        self.canvas.create_oval(x-6, y-6, x+6, y+6, fill=line_color, outline="")



def main():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
