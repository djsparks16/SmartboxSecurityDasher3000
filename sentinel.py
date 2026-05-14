
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
from tkinter import ttk, messagebox

APP_NAME = "Smartbox Security Dasher 3000"
CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SmartboxSentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"

BG = "#0B0F1A"
PANEL = "#121827"
PANEL_2 = "#171F33"
TEXT = "#F5F7FB"
MUTED = "#9BA7BD"
BLUE = "#53A6FF"
GREEN = "#4DFFB5"
AMBER = "#FFD166"
RED = "#FF4D6D"
PURPLE = "#B38CFF"


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def clamp(n, lo, hi):
    return max(lo, min(hi, n))


def safe_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default


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
        "unifi": {"base_url": "https://api.ui.com", "api_key": "", "site_id": "", "alerts_path": "", "site_health_path": "", "enabled": False},
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
                "detail": f"{len(defender_active)} active Defender alert(s), {len(defender_resolved)} resolved/closed returned, {len(defender_high)} high/critical active.",
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

    def _items_from_response(self, data):
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        for key in ("data", "value", "events", "alerts", "alarms", "items", "results", "sites"):
            val = data.get(key)
            if isinstance(val, list):
                return val
        return []

    def _severity_from_alert(self, alert):
        raw = str(
            alert.get("severity")
            or alert.get("level")
            or alert.get("priority")
            or alert.get("type")
            or alert.get("category")
            or ""
        ).lower()
        if any(x in raw for x in ("critical", "error", "wan", "offline", "down", "fail")):
            return "critical"
        if any(x in raw for x in ("warn", "medium", "blocked", "threat", "rogue")):
            return "medium"
        return "info"

    def _alert_title(self, alert):
        return (
            alert.get("title")
            or alert.get("message")
            or alert.get("name")
            or alert.get("event")
            or alert.get("type")
            or "UniFi alert"
        )

    def _alert_detail(self, alert):
        parts = []
        for key in ("siteName", "site_id", "deviceName", "hostname", "clientName", "mac", "ip", "timestamp", "datetime", "time"):
            if alert.get(key):
                parts.append(str(alert.get(key)))
        return " | ".join(parts[:4]) or "UniFi event returned by API"

    def _site_id(self, site):
        return str(site.get("id") or site.get("_id") or site.get("siteId") or site.get("site_id") or site.get("name") or "")

    def _site_name(self, site):
        return str(site.get("name") or site.get("displayName") or site.get("siteName") or site.get("desc") or self._site_id(site) or "UniFi site")

    def _site_status(self, site):
        raw = str(
            site.get("status")
            or site.get("state")
            or site.get("health")
            or site.get("connectionState")
            or site.get("wanStatus")
            or site.get("availability")
            or ""
        ).lower()

        if any(x in raw for x in ("critical", "offline", "down", "failed", "disconnected", "bad")):
            return "CRITICAL"
        if any(x in raw for x in ("warning", "degraded", "poor", "limited", "attention")):
            return "DEGRADED"
        if any(x in raw for x in ("online", "active", "healthy", "good", "ok", "connected")):
            return "HEALTHY"

        # Official site listings may not include health. Treat as visible, not healthy.
        return "VISIBLE"

    def _site_detail(self, site):
        parts = []
        for key in ("status", "state", "health", "wanStatus", "connectionState", "deviceCount", "devices", "clients", "clientCount"):
            if site.get(key) not in (None, ""):
                parts.append(f"{key}: {site.get(key)}")
        return ", ".join(parts[:4]) or "site object visible; health fields not returned"

    def _alert_paths(self, base, site_id, configured_path):
        if configured_path:
            path = configured_path.strip()
            if path.startswith("http://") or path.startswith("https://"):
                return [path]
            if not path.startswith("/"):
                path = "/" + path
            return [base + path]

        if not site_id:
            return []

        safe_site = urllib.parse.quote(site_id.strip(), safe="")
        return [
            f"{base}/proxy/network/integration/v1/sites/{safe_site}/alerts",
            f"{base}/proxy/network/integration/v1/sites/{safe_site}/events",
            f"{base}/proxy/network/integration/v1/sites/{safe_site}/alarms",
        ]

    def _site_health_paths(self, base, site_id, configured_path):
        if configured_path:
            path = configured_path.strip()
            if path.startswith("http://") or path.startswith("https://"):
                return [path]
            if not path.startswith("/"):
                path = "/" + path
            return [base + path]

        paths = []
        if site_id:
            safe_site = urllib.parse.quote(site_id.strip(), safe="")
            paths.extend([
                f"{base}/proxy/network/integration/v1/sites/{safe_site}/health",
                f"{base}/proxy/network/integration/v1/sites/{safe_site}/devices",
            ])
        return paths


    def is_unifi_alert_active(self, alert):
        raw = " ".join([
            str(alert.get("status") or ""),
            str(alert.get("state") or ""),
            str(alert.get("archived") or ""),
            str(alert.get("resolved") or ""),
        ]).lower()
        if "true" in raw and ("resolved" in raw or "archived" in raw):
            return False
        return not any(word in raw for word in ("resolved", "closed", "archived", "cleared"))


    def fetch(self):
        if not self.enabled():
            return None

        c = self.cfg["unifi"]
        base = c["base_url"].rstrip("/")
        headers = {"X-API-KEY": c["api_key"], "Accept": "application/json"}

        site_path = "/proxy/network/integration/v1/sites"
        sites_response = Http.request("GET", base + site_path, headers=headers)
        sites = self._items_from_response(sites_response)
        site_count = len(sites) if isinstance(sites, list) else 0

        # Try optional health endpoint. If unavailable, use the site listing objects as the health source.
        health_items = []
        health_errors = []
        for url in self._site_health_paths(base, c.get("site_id", ""), c.get("site_health_path", "")):
            try:
                data = Http.request("GET", url, headers=headers)
                health_items = self._items_from_response(data)
                if health_items:
                    break
            except Exception as e:
                health_errors.append(str(e)[:120])

        site_health_source = health_items if health_items else sites
        site_health = []
        for site in site_health_source[:25]:
            if not isinstance(site, dict):
                continue
            site_health.append({
                "name": self._site_name(site),
                "id": self._site_id(site),
                "status": self._site_status(site),
                "detail": self._site_detail(site),
            })

        healthy_sites = sum(1 for s in site_health if s["status"] == "HEALTHY")
        degraded_sites = sum(1 for s in site_health if s["status"] == "DEGRADED")
        critical_sites = sum(1 for s in site_health if s["status"] == "CRITICAL")
        visible_sites = sum(1 for s in site_health if s["status"] == "VISIBLE")

        alerts = []
        for url in self._alert_paths(base, c.get("site_id", ""), c.get("alerts_path", "")):
            try:
                data = Http.request("GET", url, headers=headers)
                alerts = self._items_from_response(data)
                break
            except Exception:
                pass

        events = [{
            "severity": "info",
            "title": "UniFi API reachable",
            "detail": f"{site_count} site object(s) returned.",
            "source": "UniFi",
        }]

        if site_health:
            events.append({
                "severity": "critical" if critical_sites else "medium" if degraded_sites else "info",
                "title": "UniFi site health loaded",
                "detail": f"{len(site_health)} site(s): healthy {healthy_sites}, degraded {degraded_sites}, critical {critical_sites}, visible {visible_sites}.",
                "source": "UniFi",
            })

        if alerts:
            events.insert(0, {
                "severity": "critical" if any(self._severity_from_alert(a) == "critical" for a in alerts) else "medium",
                "title": "UniFi alerts live",
                "detail": f"{len(alerts)} alert/event item(s) returned.",
                "source": "UniFi",
            })
            for alert in alerts[:25]:
                events.append({
                    "severity": self._severity_from_alert(alert),
                    "title": self._alert_title(alert),
                    "detail": self._alert_detail(alert),
                    "source": "UniFi",
                })
        elif c.get("site_id") or c.get("alerts_path"):
            events.append({
                "severity": "medium",
                "title": "UniFi alert endpoint returned no items",
                "detail": "No UniFi alerts/events found, or endpoint shape did not contain a list.",
                "source": "UniFi",
            })
        else:
            events.append({
                "severity": "info",
                "title": "UniFi alerts not configured",
                "detail": "Add Site ID or Alerts path in Setup to query UniFi alerts/events.",
                "source": "UniFi",
            })

        active_unifi_alerts = [a for a in alerts if self.is_unifi_alert_active(a)]
        resolved_unifi_alerts = max(0, len(alerts) - len(active_unifi_alerts))
        critical_alerts = sum(1 for a in active_unifi_alerts if self._severity_from_alert(a) == "critical")
        critical_total = critical_alerts + critical_sites

        return {
            "source": "UniFi",
            "live": True,
            "unifi_connected": 1,
            "unifi_sites": site_count,
            "unifi_status": "LIVE",
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
        """Return a plain-language state from real counts only. No artificial score."""
        critical = int(metrics.get("critical", 0) or 0)
        defender = int(metrics.get("defender_alerts", 0) or 0)
        graph = int(metrics.get("graph_alerts", 0) or 0)
        noncompliant = int(metrics.get("noncompliant", 0) or 0)

        if critical > 0:
            return "CRITICAL", 4, "critical alerts present"
        if defender >= 10 or graph >= 25 or noncompliant >= 100:
            return "HIGH", 3, "large alert/compliance volume"
        if defender > 0 or graph > 0 or noncompliant > 0:
            return "ACTION", 2, "investigation required"
        return "CLEAR", 0, "no active findings"


    def correlate(self, results, errors):
        if not results:
            return {
                "timestamp": now_iso(),
                "metrics": {
                    "devices": 0,
                    "noncompliant": 0,
                    "alerts": 0,
                    "active_alerts": 0,
                    "returned_alerts": 0,
                    "resolved_alerts": 0,
                    "defender_alerts": 0,
                    "defender_returned_alerts": 0,
                    "defender_resolved_alerts": 0,
                    "graph_alerts": 0,
                    "graph_returned_alerts": 0,
                    "graph_resolved_alerts": 0,
                    "critical": 0,
                    "wan_health": 0,
                    "unifi_connected": 0,
                    "unifi_sites": 0,
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
                "sources": {"live": [], "simulated": [], "errors": errors},
            }

        devices = sum(int(r.get("devices", 0)) for r in results)
        noncompliant = sum(int(r.get("noncompliant", 0)) for r in results)
        alerts = sum(int(r.get("alerts", 0)) for r in results)
        active_alerts = sum(int(r.get("active_alerts", r.get("alerts", 0))) for r in results)
        returned_alerts = sum(int(r.get("returned_alerts", r.get("alerts", 0))) for r in results)
        resolved_alerts = sum(int(r.get("resolved_alerts", 0)) for r in results)
        defender_alerts = sum(int(r.get("defender_alerts", 0)) for r in results)
        defender_returned_alerts = sum(int(r.get("defender_returned_alerts", r.get("defender_alerts", 0))) for r in results)
        defender_resolved_alerts = sum(int(r.get("defender_resolved_alerts", 0)) for r in results)
        graph_alerts = sum(int(r.get("graph_alerts", 0)) for r in results)
        graph_returned_alerts = sum(int(r.get("graph_returned_alerts", r.get("graph_alerts", 0))) for r in results)
        graph_resolved_alerts = sum(int(r.get("graph_resolved_alerts", 0)) for r in results)
        critical = sum(int(r.get("critical", 0)) for r in results)
        unifi_connected = sum(int(r.get("unifi_connected", 0)) for r in results)
        unifi_sites = sum(int(r.get("unifi_sites", 0)) for r in results)
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
            "defender_alerts": defender_alerts,
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
        events = events[:12]
        return {
            "timestamp": now_iso(),
            "metrics": {
                "devices": devices,
                "noncompliant": noncompliant,
                "alerts": active_alerts,
                "active_alerts": active_alerts,
                "returned_alerts": returned_alerts,
                "resolved_alerts": resolved_alerts,
                "defender_alerts": defender_alerts,
                "defender_returned_alerts": defender_returned_alerts,
                "defender_resolved_alerts": defender_resolved_alerts,
                "graph_alerts": graph_alerts,
                "graph_returned_alerts": graph_returned_alerts,
                "graph_resolved_alerts": graph_resolved_alerts,
                "critical": critical,
                "wan_health": wan_health,
                "unifi_connected": unifi_connected,
                "unifi_sites": unifi_sites,
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
            "sources": {"live": live_sources, "simulated": sim_sources, "errors": errors},
        }


class SentinelApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1240x760")
        self.minsize(1100, 680)
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

    def _build(self):
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True, padx=22, pady=18)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="Smartbox Security Dasher 3000", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 28, "bold")).pack(side="left")
        tk.Label(header, text="real-time infrastructure, compliance and threat correlation", bg=BG, fg=MUTED, font=("Segoe UI", 11)).pack(side="left", padx=18, pady=(12,0))
        tk.Button(header, text="Setup connectors", command=self.open_setup, bg="#1C2740", fg=TEXT, activebackground="#243455", relief="flat", padx=14, pady=8, font=("Segoe UI", 10, "bold")).pack(side="right")

        self.overview = tk.Frame(shell, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        self.overview.pack(fill="x", pady=(14, 6))
        self.state_badge = tk.Label(self.overview, text="INITIALISING", bg=PANEL, fg=BLUE, font=("Segoe UI", 10, "bold"))
        self.state_badge.pack(side="left", padx=(18, 10), pady=12)
        self.state_detail = tk.Label(self.overview, text="Waiting for first telemetry pull...", bg=PANEL, fg=TEXT, font=("Segoe UI", 10))
        self.state_detail.pack(side="left", padx=(0, 8), pady=12)
        self.live_badge = tk.Label(self.overview, text="LIVE: NONE", bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold"))
        self.live_badge.pack(side="right", padx=(8, 18), pady=12)

        body = tk.Frame(shell, bg=BG)
        body.pack(fill="both", expand=True, pady=(12, 0))
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        right = tk.Frame(body, bg=BG, width=360)
        right.pack(side="right", fill="y", padx=(18, 0))
        right.pack_propagate(False)

        cards = tk.Frame(left, bg=BG)
        cards.pack(fill="x")
        for i in range(3):
            cards.grid_columnconfigure(i, weight=1)
        self.card(cards, 0, 0, "Priority state", "priority_state", BLUE)
        self.card(cards, 0, 1, "Active unresolved alerts", "alerts", RED)
        self.card(cards, 0, 2, "Compliant gap", "noncompliant", AMBER)
        self.card(cards, 1, 0, "Managed devices", "devices", GREEN)
        self.card(cards, 1, 1, "Critical", "critical", PURPLE)

        self.unifi_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        for label, key, color in [
            ("UniFi", "unifi_status", BLUE),
            ("UniFi sites", "unifi_sites", GREEN),
            ("Active UniFi alerts", "unifi_alerts", AMBER),
            ("Healthy sites", "unifi_healthy_sites", GREEN),
            ("Degraded sites", "unifi_degraded_sites", AMBER),
            ("Critical sites", "unifi_critical_sites", RED),
        ]:
            box = tk.Frame(self.unifi_bar, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=10, pady=8)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 16, "bold"))
            val.pack(anchor="w")
            self.unifi_labels[key] = val


        self.unifi_site_health_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        self.unifi_site_health_title = tk.Label(self.unifi_site_health_bar, text="UniFi site health", bg=PANEL, fg=TEXT, font=("Segoe UI", 9, "bold"))
        self.unifi_site_health_title.pack(anchor="w", padx=12, pady=(8, 2))
        self.unifi_site_health_text = tk.Label(self.unifi_site_health_bar, text="Waiting for UniFi site health...", bg=PANEL, fg=MUTED, font=("Segoe UI", 9), justify="left", wraplength=1100)
        self.unifi_site_health_text.pack(anchor="w", padx=12, pady=(0, 8))

        self.top_issues_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        self.top_issues_bar.pack(fill="x", pady=(8, 0))
        tk.Label(self.top_issues_bar, text="Top live findings", bg=PANEL, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(8, 2))
        self.top_issues_text = tk.Label(self.top_issues_bar, text="Waiting for alerts...", bg=PANEL, fg=MUTED, font=("Segoe UI", 9), justify="left", wraplength=900)
        self.top_issues_text.pack(anchor="w", padx=12, pady=(0, 8))


        self.platform_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        self.optional_bars.append(self.platform_bar)
        for label, key, color in [
            ("Windows devices", "windows", BLUE),
            ("iPhone / iPad", "ios", GREEN),
            ("Mac devices", "macos", PURPLE),
            ("Android", "android", AMBER),
            ("Other OS", "other_os", MUTED),
        ]:
            box = tk.Frame(self.platform_bar, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=10, pady=10)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="0", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 18, "bold"))
            val.pack(anchor="w")
            self.platform_labels[key] = val


        self.canvas = tk.Canvas(left, bg=PANEL, highlightthickness=0, height=165)
        self.canvas.pack(fill="both", expand=True, pady=(18, 0))
        self.spark = []

        tk.Label(right, text="Verified signal feed", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 18, "bold")).pack(anchor="w")

        self.feed_canvas = tk.Canvas(right, bg=BG, highlightthickness=0, bd=0)
        self.feed_scrollbar = tk.Scrollbar(right, orient="vertical", command=self.feed_canvas.yview, bg=PANEL, troughcolor=BG, activebackground="#243455")
        self.feed_canvas.configure(yscrollcommand=self.feed_scrollbar.set)

        self.feed_canvas.pack(side="left", fill="both", expand=True, pady=(10, 0))
        self.feed_scrollbar.pack(side="right", fill="y", pady=(10, 0))

        self.feed = tk.Frame(self.feed_canvas, bg=BG)
        self.feed_window = self.feed_canvas.create_window((0, 0), window=self.feed, anchor="nw")

        self.feed.bind("<Configure>", self._on_feed_configure)
        self.feed_canvas.bind("<Configure>", self._on_feed_canvas_configure)
        self.feed_canvas.bind("<Enter>", self._bind_feed_mousewheel)
        self.feed_canvas.bind("<Leave>", self._unbind_feed_mousewheel)

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill="x", pady=(12, 0))
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(footer, text="Only configured live connectors are displayed. No simulated telemetry.", bg=BG, fg="#526078", font=("Segoe UI", 9)).pack(side="right")

    def card(self, parent, row, col, title, key, color):
        f = tk.Frame(parent, bg=PANEL, bd=0, highlightthickness=1, highlightbackground="#22304C")
        f.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18, pady=(14, 2))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=("Segoe UI Variable Display", 28, "bold"))
        val.pack(anchor="w", padx=18, pady=(0, 2))
        hint = tk.Label(f, text="Awaiting data", bg=PANEL, fg="#7F8AA3", font=("Segoe UI", 8))
        hint.pack(anchor="w", padx=18, pady=(0, 12))
        self.metric_labels[key] = val
        self.metric_cards[key] = {"frame": f, "value": val, "hint": hint, "base": color}

    def metric_style(self, key, val):
        raw = str(val)
        num = safe_float(val, 0)
        if key == "priority_state":
            state = raw.upper()
            if state == "CRITICAL":
                return RED, "critical alerts present"
            if state == "HIGH":
                return RED, "large alert/compliance volume"
            if state == "ACTION":
                return AMBER, "investigation required"
            return GREEN, "no active findings"
        if key == "risk":
            return MUTED, "deprecated"
        if key == "alerts":
            if num >= 100:
                return RED, "high alert volume"
            if num >= 25:
                return AMBER, "elevated alert volume"
            if num > 0:
                return BLUE, "active"
            return GREEN, "clear"
        if key == "noncompliant":
            if num >= 100:
                return RED, "large compliance gap"
            if num >= 25:
                return AMBER, "compliance drift"
            if num > 0:
                return BLUE, "small compliance gap"
            return GREEN, "fully compliant"
        if key == "critical":
            if num > 0:
                return RED, "immediate attention"
            return GREEN, "none"
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
                return AMBER, "no visibility"
            return GREEN, "visible"
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
                    self.unifi_bar.pack(fill="x", pady=(8, 0), before=self.top_issues_bar)
            else:
                if self.unifi_bar.winfo_manager():
                    self.unifi_bar.pack_forget()

        if hasattr(self, "unifi_site_health_bar"):
            if network_live or int(metrics.get("unifi_connected", 0) or 0) > 0:
                if not self.unifi_site_health_bar.winfo_manager():
                    self.unifi_site_health_bar.pack(fill="x", pady=(8, 0), before=self.top_issues_bar)
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

        tk.Button(win, text="Save and restart telemetry", command=save, bg="#1C2740", fg=TEXT, activebackground="#243455", relief="flat", padx=14, pady=10, font=("Segoe UI", 10, "bold")).pack(pady=(0, 16))

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

        for key, label in self.unifi_labels.items():
            if key == "unifi_status":
                label.config(text="LIVE" if int(m.get("unifi_connected", 0) or 0) > 0 else "--")
            else:
                label.config(text=str(m.get(key, 0)))

        site_lines = []
        for site in (m.get("unifi_site_health", []) or [])[:12]:
            status = site.get("status", "VISIBLE")
            site_lines.append(f"{status}: {site.get('name', 'UniFi site')} ({site.get('detail', '')})")
        if site_lines and hasattr(self, "unifi_site_health_text"):
            self.unifi_site_health_text.config(text="  •  ".join(site_lines), fg=TEXT)
        elif hasattr(self, "unifi_site_health_text"):
            self.unifi_site_health_text.config(text="No UniFi site health fields returned yet.", fg=MUTED)

        top_events = [e for e in payload["events"] if str(e.get("severity", "")).lower() in ("critical", "high", "medium")]
        if top_events:
            summary = "  •  ".join([f"{e.get('source','')}: {e.get('title','')}" for e in top_events[:3]])
            self.top_issues_text.config(text=summary, fg=TEXT)
        else:
            self.top_issues_text.config(text="No critical or medium live findings returned.", fg=MUTED)

        state_text, state_color = self.overall_state(m)
        live = ", ".join(payload["sources"]["live"]) or "no configured live connector"
        self.state_badge.config(text=state_text, fg=state_color)
        unifi_bit = f" • UniFi sites {m.get('unifi_sites', 0)} • UniFi alerts {m.get('unifi_alerts', 0)} • UniFi degraded {m.get('unifi_degraded_sites', 0)} • UniFi critical {m.get('unifi_critical_sites', 0)}" if int(m.get("unifi_connected", 0) or 0) > 0 else ""
        self.state_detail.config(text=f"{m.get('priority_reason', 'live counts')} • Devices {m.get('devices', 0)} • Active {m.get('active_alerts', m.get('alerts', 0))} • Returned {m.get('returned_alerts', 0)} • Resolved/closed {m.get('resolved_alerts', 0)} • Critical {m.get('critical', 0)} • Non-compliant {m.get('noncompliant', 0)}{unifi_bit}")
        self.live_badge.config(text=f"LIVE: {live.upper()}", fg=GREEN if live != "none" else MUTED)

        self.spark.append(m.get("alerts", 0))
        self.spark = self.spark[-80:]
        self.draw_spark()

        for child in self.feed.winfo_children():
            child.destroy()

        sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sev_color = {"critical": RED, "high": RED, "medium": AMBER, "info": BLUE, "low": GREEN}
        sev_bg = {"critical": "#26111A", "high": "#26111A", "medium": "#241E11", "info": "#131C2D", "low": "#102019"}
        events = sorted(payload["events"][:100], key=lambda e: sev_priority.get(str(e.get("severity", "info")).lower(), 9))
        for event in events:
            sev = str(event.get("severity", "info")).lower()
            color = sev_color.get(sev, BLUE)
            bg = sev_bg.get(sev, PANEL)
            f = tk.Frame(self.feed, bg=bg, highlightthickness=1, highlightbackground=color)
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
        self.status_var.set(f"Updated {dt.datetime.now().strftime('%H:%M:%S')} | state: {state_text.lower()} | live: {live} | active: {m.get('active_alerts', m.get('alerts', 0))} | returned: {m.get('returned_alerts', 0)} | resolved/closed: {m.get('resolved_alerts', 0)} | critical: {m.get('critical', 0)} | non-compliant: {m.get('noncompliant', 0)}")

    def draw_spark(self):
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
