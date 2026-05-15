
"""
Smartbox Security by Marc PoC - v12 no-clip icon and table polish
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
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog

APP_NAME = "Smartbox Security by Marc"
CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "SmartboxSentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"
SOFTWARE_CACHE_FILE = CONFIG_DIR / "software_cache.json"
INCIDENT_CACHE_FILE = CONFIG_DIR / "incident_cache.json"

BG = "#020812"
PANEL = "#061827"
PANEL_2 = "#0B2238"
TEXT = "#F7FBFF"
MUTED = "#A9C8E4"
BLUE = "#36CFFF"
GREEN = "#7DFF57"
AMBER = "#FFC84A"
ORANGE = "#FF9B42"
RED = "#FF4F7D"
PURPLE = "#C06BFF"
GLASS = "#061827"
HAIRLINE = "#173A5A"
GLASS_2 = "#071B2B"
ROW_ALT = "#0A2236"


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


def parse_dt_safe(value):
    if not value:
        return None
    try:
        raw = str(value).replace("Z", "+00:00")
        return dt.datetime.fromisoformat(raw)
    except Exception:
        return None


def days_since(value):
    parsed = parse_dt_safe(value)
    if not parsed:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - parsed).days


def software_cache_age_minutes(state):
    try:
        updated = parse_dt_safe(state.get("updated"))
        if not updated:
            return None
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=dt.timezone.utc)
        return int((dt.datetime.now(dt.timezone.utc) - updated).total_seconds() / 60)
    except Exception:
        return None


def short_ts(value):
    if not value:
        return ""
    return str(value).replace("T", " ").replace("Z", "")[:19]


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
        "software_poll_hours": 6,
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
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                raw = res.read().decode("utf-8", errors="replace")
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            try:
                body_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            hint = body_text[:600] if body_text else str(e)
            raise RuntimeError(f"HTTP {e.code} {e.reason}: {hint}") from None


class MicrosoftGraphConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tokens = {}
        self.token_expiry = {}
        self.status = "idle"


    def recommendation_row(self, r):
        return {
            "title": r.get("recommendationName") or r.get("title") or r.get("name") or "Security recommendation",
            "severity": r.get("severity") or r.get("exposureImpact") or r.get("riskScore") or "",
            "status": r.get("status") or r.get("implementationStatus") or "",
            "category": r.get("category") or r.get("productName") or "",
            "impact": r.get("impact") or r.get("exposedMachinesCount") or r.get("exposedMachineCount") or "",
            "detail": r.get("description") or r.get("remediationType") or r.get("remediation") or "",
        }

    def vulnerability_row(self, v):
        return {
            "id": v.get("id") or v.get("cveId") or v.get("name") or "vulnerability",
            "severity": v.get("severity") or v.get("cvssV3") or v.get("cvssScore") or "",
            "cvss": v.get("cvssV3") or v.get("cvssScore") or "",
            "published": v.get("publishedOn") or v.get("publishedDate") or "",
            "updated": v.get("updatedOn") or v.get("lastModified") or "",
            "detail": v.get("description") or v.get("name") or "",
        }

    def machine_row(self, m):
        return {
            "name": m.get("computerDnsName") or m.get("machineName") or m.get("deviceName") or m.get("id") or "machine",
            "risk": m.get("riskScore") or m.get("exposureLevel") or "",
            "health": m.get("healthStatus") or m.get("onboardingStatus") or "",
            "os": m.get("osPlatform") or m.get("osProcessor") or "",
            "last_seen": m.get("lastSeen") or "",
            "ip": m.get("lastIpAddress") or "",
        }


    def enabled(self):
        c = self.cfg["microsoft"]
        return c.get("enabled") and c.get("tenant_id") and c.get("client_id") and c.get("client_secret")


    def clear_token_cache(self):
        try:
            self.tokens = {}
            self.token_expiry = {}
        except Exception:
            pass

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


    def load_incident_state(self):
        try:
            if INCIDENT_CACHE_FILE.exists():
                data = json.loads(INCIDENT_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {"updated": "", "incidents": [], "backoff_until": "", "last_error": "", "source": ""}

    def save_incident_state(self, incidents, source="Graph incidents", last_error="", backoff_until=""):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            INCIDENT_CACHE_FILE.write_text(json.dumps({
                "updated": now_iso(),
                "incidents": incidents[:1000] if isinstance(incidents, list) else [],
                "source": source,
                "last_error": last_error,
                "backoff_until": backoff_until,
            }, indent=2), encoding="utf-8")
        except Exception:
            pass

    def should_skip_incident_poll(self, state, min_age_minutes=15):
        try:
            backoff_until = parse_dt_safe(state.get("backoff_until"))
            now = dt.datetime.now(dt.timezone.utc)
            if backoff_until:
                if backoff_until.tzinfo is None:
                    backoff_until = backoff_until.replace(tzinfo=dt.timezone.utc)
                if backoff_until > now:
                    return True, f"Graph incidents backoff active until {short_ts(backoff_until.isoformat())}"
            updated = parse_dt_safe(state.get("updated"))
            if updated and state.get("incidents"):
                if updated.tzinfo is None:
                    updated = updated.replace(tzinfo=dt.timezone.utc)
                age = int((now - updated).total_seconds() / 60)
                if age < min_age_minutes:
                    return True, f"Using cached Graph incidents, refreshed {age} minute(s) ago"
        except Exception:
            pass
        return False, ""


    def fetch_graph_incidents(self, headers):
        """Fetch Microsoft 365 Defender incidents with cache/backoff protection.

        Graph security incidents can throttle hard. On 429 we keep the last good
        incident rows visible instead of turning the dashboard into an error wall.
        """
        state = self.load_incident_state()
        skip, reason = self.should_skip_incident_poll(state, min_age_minutes=15)
        if skip:
            return state.get("incidents", []) or [], state.get("source") or "cache", reason

        urls = [
            "https://graph.microsoft.com/v1.0/security/incidents",
            "https://graph.microsoft.com/beta/security/incidents",
        ]
        last_error = ""
        for url in urls:
            try:
                rows = self.graph_get_all(url, headers=headers, max_pages=3)
                self.save_incident_state(rows, source=url, last_error="", backoff_until="")
                return rows, url, ""
            except Exception as e:
                last_error = str(e)
                if "429" in last_error or "TooManyRequests" in last_error or "Too Many Requests" in last_error:
                    until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)
                    cached = state.get("incidents", []) or []
                    self.save_incident_state(cached, source=state.get("source") or "cache", last_error=last_error, backoff_until=until.isoformat())
                    return cached, state.get("source") or "cache", f"Graph incidents throttled; using cache. {last_error[:220]}"
        cached = state.get("incidents", []) or []
        if cached:
            return cached, state.get("source") or "cache", f"Graph incidents unavailable; using cache. {last_error[:220]}"
        return [], "", last_error


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

    def defender_get_optional(self, url, headers, label, max_pages=5):
        try:
            return self.defender_get_all(url, headers=headers, max_pages=max_pages), ""
        except Exception as e:
            return [], str(e)

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
        resolved_words = ("resolved", "dismissed", "closed", "remediated", "suppressed")
        return not any(word in raw for word in resolved_words)



    def device_row(self, device):
        last_sync = device.get("lastSyncDateTime") or ""
        return {
            "name": device.get("deviceName") or device.get("azureADDeviceId") or device.get("id") or "unknown device",
            "user": device.get("userPrincipalName") or device.get("emailAddress") or "",
            "os": device.get("operatingSystem") or "",
            "model": device.get("model") or "",
            "manufacturer": device.get("manufacturer") or "",
            "compliance": device.get("complianceState") or "",
            "last_sync": last_sync,
            "last_sync_days": days_since(last_sync),
            "encrypted": device.get("isEncrypted"),
            "jailbroken": device.get("jailBroken"),
            "management_agent": device.get("managementAgent") or "",
            "ownership": device.get("managedDeviceOwnerType") or device.get("ownerType") or "",
        }

    def alert_time(self, alert):
        for key in ("createdDateTime", "lastUpdateDateTime", "lastUpdatedDateTime", "firstActivityDateTime", "lastActivityDateTime", "eventDateTime", "createdTime", "lastUpdateTime"):
            if alert.get(key):
                return alert.get(key)
        return ""


    def is_incident_active(self, incident):
        raw = " ".join([
            str(incident.get("status") or ""),
            str(incident.get("classification") or ""),
            str(incident.get("determination") or ""),
        ]).lower()
        closed_words = ("resolved", "redirected", "closed", "suppressed")
        return not any(word in raw for word in closed_words)

    def incident_time(self, incident):
        for key in ("lastUpdateDateTime", "createdDateTime", "lastModifiedDateTime", "lastActivityDateTime"):
            if incident.get(key):
                return incident.get(key)
        return ""

    def app_key(self, app):
        return "|".join([
            str(app.get("displayName") or app.get("name") or "").strip().lower(),
            str(app.get("version") or "").strip().lower(),
            str(app.get("publisher") or "").strip().lower(),
        ])

    def normalise_app(self, app):
        return {
            "displayName": app.get("displayName") or app.get("name") or "Unknown app",
            "version": app.get("version") or "",
            "publisher": app.get("publisher") or "",
            "deviceCount": app.get("deviceCount") or 0,
            "sizeInByte": app.get("sizeInByte") or 0,
        }

    def load_software_state(self):
        try:
            if SOFTWARE_CACHE_FILE.exists():
                data = json.loads(SOFTWARE_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {"updated": "", "keys": [], "apps": [], "backoff_until": "", "last_error": ""}

    def save_software_state(self, keys, apps, source="unknown", last_error="", backoff_until=""):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            SOFTWARE_CACHE_FILE.write_text(json.dumps({
                "updated": now_iso(),
                "keys": sorted(keys),
                "apps": apps[:20000],
                "source": source,
                "last_error": last_error,
                "backoff_until": backoff_until,
            }, indent=2), encoding="utf-8")
        except Exception:
            pass

    def should_skip_software_poll(self, state, min_age_minutes=None):
        # detectedApps can be expensive and rate-limited. Keep it on a slow lane.
        if min_age_minutes is None:
            try:
                min_age_minutes = max(60, int(float(self.cfg.get("software_poll_hours", 6)) * 60))
            except Exception:
                min_age_minutes = 360
        backoff_until = parse_dt_safe(state.get("backoff_until"))
        now = dt.datetime.now(dt.timezone.utc)
        if backoff_until:
            if backoff_until.tzinfo is None:
                backoff_until = backoff_until.replace(tzinfo=dt.timezone.utc)
            if backoff_until > now:
                return True, f"Graph detectedApps backoff active until {short_ts(backoff_until.isoformat())}"
        age = software_cache_age_minutes(state)
        if age is not None and age < min_age_minutes and state.get("apps"):
            return True, f"Using cached detectedApps inventory, refreshed {age} minute(s) ago"
        return False, ""

    def backoff_from_error(self, err, minutes=30):
        # urllib hides Retry-After in this version, so use a safe local backoff.
        if "429" in str(err) or "Too Many Requests" in str(err):
            until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)
            return until.isoformat()
        return ""


    def fetch(self):
        if not self.enabled():
            return None

        graph_token = self.get_token("https://graph.microsoft.com/.default")
        graph_headers = {"Authorization": f"Bearer {graph_token}", "Accept": "application/json"}

        # Full paged Intune inventory and Graph security alerts.
        devices_url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=100"
        graph_alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100"
        graph_incidents_url = "https://graph.microsoft.com/v1.0/security/incidents"
        detected_apps_url = "https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?$top=100"
        detected_apps_beta_url = "https://graph.microsoft.com/beta/deviceManagement/detectedApps?$top=100"

        # Dedicated Defender for Endpoint API. This normally needs Defender API permissions on the app:
        # Alert.Read.All and optionally Machine.Read.All for deeper enrichment later.
        defender_base = self.cfg["microsoft"].get("defender_api_url", "https://api.securitycenter.microsoft.com").rstrip("/")
        defender_alerts_url = f"{defender_base}/api/alerts?$top=200"
        defender_machines_url = f"{defender_base}/api/machines?$top=100"
        defender_recommendations_url = f"{defender_base}/api/recommendations?$top=100"
        defender_vulnerabilities_url = f"{defender_base}/api/vulnerabilities?$top=100"

        devices = []
        graph_alerts = []
        graph_incidents = []
        defender_alerts = []
        defender_machines = []
        defender_recommendations = []
        defender_vulnerabilities = []
        detected_apps = []
        events = []

        device_error = None
        graph_alert_error = None
        graph_incident_error = None
        defender_alert_error = None
        defender_machine_error = None
        defender_recommendation_error = None
        defender_vulnerability_error = None
        detected_apps_error = None

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
            graph_incidents, graph_incidents_used_url, graph_incident_error = self.fetch_graph_incidents(graph_headers)
            if graph_incident_error:
                events.append({
                    "severity": "info" if graph_incidents else "medium",
                    "title": "Microsoft Graph security incidents cache/backoff" if graph_incidents else "Microsoft Graph security incidents query failed",
                    "detail": graph_incident_error[:300],
                    "source": "Graph Incidents",
                })
            elif graph_incidents:
                events.append({
                    "severity": "info",
                    "title": "Microsoft Graph security incidents query live",
                    "detail": f"{len(graph_incidents)} incident row(s) returned from {graph_incidents_used_url.replace('https://graph.microsoft.com/', '')}",
                    "source": "Graph Incidents",
                })
        except Exception as e:
            graph_incident_error = str(e)
            events.append({
                "severity": "medium",
                "title": "Microsoft Graph security incidents query failed",
                "detail": graph_incident_error[:300],
                "source": "Graph Incidents",
            })

        detected_apps_source = "v1.0"
        software_state = self.load_software_state()
        skip_software_poll, software_skip_reason = self.should_skip_software_poll(software_state)
        if skip_software_poll:
            detected_apps = software_state.get("apps", []) or []
            detected_apps_source = software_state.get("source") or "cache"
            detected_apps_error = software_state.get("last_error") or software_skip_reason
            events.append({
                "severity": "info",
                "title": "Detected apps inventory using cache",
                "detail": software_skip_reason,
                "source": "Microsoft Graph",
            })
        else:
            try:
                detected_apps = self.graph_get_all(detected_apps_url, headers=graph_headers, max_pages=120)
                if not detected_apps:
                    try:
                        beta_apps = self.graph_get_all(detected_apps_beta_url, headers=graph_headers, max_pages=120)
                        if beta_apps:
                            detected_apps = beta_apps
                            detected_apps_source = "beta"
                    except Exception:
                        pass
            except Exception as e:
                detected_apps_error = str(e)
                backoff_until = self.backoff_from_error(detected_apps_error, minutes=30)
                try:
                    if not backoff_until:
                        detected_apps = self.graph_get_all(detected_apps_beta_url, headers=graph_headers, max_pages=120)
                        detected_apps_source = "beta"
                    else:
                        detected_apps = software_state.get("apps", []) or []
                        detected_apps_source = software_state.get("source") or "cache"
                except Exception as beta_e:
                    detected_apps_error = f"{detected_apps_error[:120]} | beta: {str(beta_e)[:120]}"
                if backoff_until or detected_apps_error:
                    self.save_software_state(set(software_state.get("keys", [])), software_state.get("apps", []) or [], source=detected_apps_source, last_error=detected_apps_error, backoff_until=backoff_until)
                    events.append({
                        "severity": "medium" if "429" in detected_apps_error else "info",
                        "title": "Detected apps inventory unavailable",
                        "detail": ("Graph rate limited detectedApps; using cache/backoff. " if "429" in detected_apps_error else "") + detected_apps_error[:180],
                        "source": "Microsoft Graph",
                    })

        try:
            defender_token = self.get_token("https://api.securitycenter.microsoft.com/.default")
            defender_headers = {"Authorization": f"Bearer {defender_token}", "Accept": "application/json"}
            defender_alerts = self.defender_get_all(defender_alerts_url, headers=defender_headers, max_pages=20)
            defender_machines, defender_machine_error = self.defender_get_optional(defender_machines_url, defender_headers, "machines", max_pages=5)
            defender_recommendations, defender_recommendation_error = self.defender_get_optional(defender_recommendations_url, defender_headers, "recommendations", max_pages=5)
            defender_vulnerabilities, defender_vulnerability_error = self.defender_get_optional(defender_vulnerabilities_url, defender_headers, "vulnerabilities", max_pages=5)
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

        if device_error and graph_alert_error and graph_incident_error and defender_alert_error:
            raise RuntimeError(
                f"Microsoft failed. Intune: {device_error[:100]} | Graph alerts: {graph_alert_error[:100]} | Graph incidents: {graph_incident_error[:100]} | Defender: {defender_alert_error[:100]}"
            )

        os_counts = {"windows": 0, "ios": 0, "macos": 0, "android": 0, "other": 0}
        for device in devices:
            os_counts[self.classify_os(device)] += 1

        noncompliant = [
            d for d in devices
            if str(d.get("complianceState", "")).lower() not in ("compliant", "unknown", "")
        ]
        stale_30 = [
            d for d in devices
            if (days_since(d.get("lastSyncDateTime")) is not None and days_since(d.get("lastSyncDateTime")) >= 30)
        ]
        unencrypted = [
            d for d in devices
            if d.get("isEncrypted") is False
        ]
        jailbroken = [
            d for d in devices
            if str(d.get("jailBroken") or "").strip().lower() not in ("", "false", "no", "0", "unknown")
        ]
        no_user = [
            d for d in devices
            if not (d.get("userPrincipalName") or d.get("emailAddress"))
        ]

        normalised_apps = [self.normalise_app(a) for a in detected_apps]
        app_keys = {self.app_key(a) for a in normalised_apps if self.app_key(a)}
        previous_app_keys = set(software_state.get("keys", [])) if isinstance(software_state, dict) else set()
        newly_seen_keys = app_keys - previous_app_keys if previous_app_keys else set()
        new_software = [
            a for a in normalised_apps
            if self.app_key(a) in newly_seen_keys
        ][:100]
        if detected_apps and not detected_apps_error:
            self.save_software_state(app_keys, normalised_apps, source=detected_apps_source, last_error="", backoff_until="")

        graph_active = [a for a in graph_alerts if self.is_alert_active(a)]
        incident_active = [i for i in graph_incidents if self.is_incident_active(i)]
        defender_active = [a for a in defender_alerts if self.is_alert_active(a)]
        graph_resolved = max(0, len(graph_alerts) - len(graph_active))
        incident_resolved = max(0, len(graph_incidents) - len(incident_active))
        defender_resolved = max(0, len(defender_alerts) - len(defender_active))

        graph_high = [
            a for a in graph_active
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]
        incident_high = [
            i for i in incident_active
            if str(i.get("severity", "")).lower() in ("high", "critical")
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
            alert_ts = self.alert_time(a)
            events.append({
                "severity": "critical" if sev in ("high", "critical") else "medium" if sev == "medium" else "info",
                "title": a.get("title", "Microsoft Defender alert"),
                "detail": f"{short_ts(alert_ts)} | {device} | {status} | {a.get('category', 'Defender')}",
                "timestamp": alert_ts,
                "source": "Defender for Endpoint",
            })

        for i in incident_active[:25]:
            incident_ts = self.incident_time(i)
            sev = str(i.get("severity", "informational")).lower()
            alert_count = i.get("alertCount") or i.get("alertsCount") or ""
            impact = i.get("impactedAssets") or ""
            detail_bits = [
                short_ts(incident_ts),
                f"status {i.get('status', 'unknown')}",
                f"state {i.get('determination', i.get('classification', 'unknown'))}",
            ]
            if alert_count != "":
                detail_bits.append(f"{alert_count} alert(s)")
            if impact:
                detail_bits.append(str(impact)[:80])
            events.append({
                "severity": "critical" if sev in ("high", "critical") else "medium" if sev == "medium" else "info",
                "title": i.get("displayName") or i.get("incidentName") or "Microsoft 365 Defender incident",
                "detail": " | ".join(detail_bits),
                "timestamp": incident_ts,
                "source": "Microsoft 365 Defender",
            })

        for a in graph_active[:10]:
            alert_ts = self.alert_time(a)
            events.append({
                "severity": "critical" if str(a.get("severity", "")).lower() in ("high", "critical") else "medium",
                "title": a.get("title", "Microsoft security alert"),
                "detail": f"{short_ts(alert_ts)} | {a.get('serviceSource', 'Graph')} | {a.get('status', 'unknown')}",
                "timestamp": alert_ts,
                "source": "Graph Security",
            })

        events.insert(0, {
            "severity": "info",
            "title": "Full Intune inventory loaded",
            "detail": f"{len(devices)} devices: Windows {os_counts['windows']}, iOS/iPadOS {os_counts['ios']}, macOS {os_counts['macos']}, Android {os_counts['android']}, Other {os_counts['other']}",
            "source": "Microsoft Graph",
        })
        events.insert(1, {
            "severity": "info" if len(stale_30) == 0 and len(unencrypted) == 0 else "medium",
            "title": "Intune device posture summary",
            "detail": f"{len(noncompliant)} non-compliant, {len(stale_30)} not contacted 30+ days, {len(unencrypted)} unencrypted, {len(jailbroken)} jailbroken/rooted flags.",
            "source": "Microsoft Graph",
        })
        if detected_apps:
            events.insert(2, {
                "severity": "info" if not new_software else "medium",
                "title": "Detected software inventory loaded",
                "detail": f"{len(detected_apps)} detected apps from Graph {detected_apps_source}. {len(new_software)} newly observed since local baseline.",
                "source": "Microsoft Graph",
            })

        if graph_incidents:
            events.insert(1, {
                "severity": "critical" if incident_high else "medium" if incident_active else "info",
                "title": "Microsoft 365 Defender incidents live",
                "detail": f"{len(incident_active)} active incident(s), {incident_resolved} resolved/closed returned, {len(incident_high)} high/critical active.",
                "source": "Graph Incidents",
            })
        elif not graph_incident_error:
            events.insert(1, {
                "severity": "info",
                "title": "Microsoft 365 Defender incidents query returned zero rows",
                "detail": "Graph security/incidents responded successfully but returned no incidents for the current query window.",
                "source": "Graph Incidents",
            })

        if defender_alerts:
            events.insert(1, {
                "severity": "critical" if defender_high else "medium",
                "title": "Microsoft Defender alerts live",
                "detail": f"{len(defender_active)} active Defender alert(s), {defender_resolved} resolved/closed returned, {len(defender_high)} high/critical active.",
                "source": "Defender for Endpoint",
            })

        total_alerts_returned = len(graph_alerts) + len(graph_incidents) + len(defender_alerts)
        total_active_alerts = len(graph_active) + len(incident_active) + len(defender_active)
        total_resolved_alerts = graph_resolved + incident_resolved + defender_resolved
        total_critical = len(graph_high) + len(incident_high) + len(defender_high)

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
            "stale_30_count": len(stale_30),
            "unencrypted_count": len(unencrypted),
            "jailbroken_count": len(jailbroken),
            "no_user_count": len(no_user),
            "noncompliant_devices": [self.device_row(d) for d in noncompliant[:200]],
            "stale_devices": [self.device_row(d) for d in stale_30[:200]],
            "unencrypted_devices": [self.device_row(d) for d in unencrypted[:200]],
            "jailbroken_devices": [self.device_row(d) for d in jailbroken[:100]],
            "detected_app_count": len(detected_apps),
            "detected_apps_source": detected_apps_source if detected_apps else ("unavailable" if detected_apps_error else "empty"),
            "detected_apps_error": detected_apps_error or "",
            "new_software_count": len(new_software),
            "new_software": new_software,
            "detected_apps": normalised_apps[:20000],
            "alerts": total_active_alerts,
            "active_alerts": total_active_alerts,
            "returned_alerts": total_alerts_returned,
            "resolved_alerts": total_resolved_alerts,
            "defender_alerts": len(defender_active),
            "defender_critical": len(defender_high),
            "defender_returned_alerts": len(defender_alerts),
            "defender_resolved_alerts": defender_resolved,
            "defender_machines": len(defender_machines),
            "defender_machine_rows": [self.machine_row(m) for m in defender_machines[:500]],
            "defender_machine_error": defender_machine_error or "",
            "defender_recommendations": len(defender_recommendations),
            "defender_recommendation_rows": [self.recommendation_row(r) for r in defender_recommendations[:500]],
            "defender_recommendation_error": defender_recommendation_error or "",
            "defender_vulnerabilities": len(defender_vulnerabilities),
            "defender_vulnerability_rows": [self.vulnerability_row(v) for v in defender_vulnerabilities[:500]],
            "defender_vulnerability_error": defender_vulnerability_error or "",
            "graph_alerts": len(graph_active),
            "graph_returned_alerts": len(graph_alerts),
            "graph_resolved_alerts": graph_resolved,
            "graph_incidents": len(incident_active),
            "graph_returned_incidents": len(graph_incidents),
            "graph_resolved_incidents": incident_resolved,
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

        clients = []
        traffic_items = []
        client_endpoint_note = "client endpoint not exposed by this Site Manager API"
        traffic_endpoint_note = "traffic endpoint not exposed by this Site Manager API"
        for path in ("/v1/clients", "/v1/client-devices"):
            try:
                clients, _ = self._get_paged(base, headers, path, page_size=500, max_pages=20)
                client_endpoint_note = f"{path} returned {len(clients)} item(s)"
                break
            except Exception:
                clients = []
        for path in ("/v1/traffic", "/v1/traffic-stats", "/v1/insights/traffic"):
            try:
                traffic_items, _ = self._get_paged(base, headers, path, page_size=500, max_pages=10)
                traffic_endpoint_note = f"{path} returned {len(traffic_items)} item(s)"
                break
            except Exception:
                traffic_items = []

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

        events.append({
            "severity": "info",
            "title": "UniFi client and traffic probe",
            "detail": f"{client_endpoint_note}; {traffic_endpoint_note}.",
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
            "unifi_clients": len(clients),
            "unifi_traffic_items": len(traffic_items),
            "unifi_client_note": client_endpoint_note,
            "unifi_traffic_note": traffic_endpoint_note,
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
            return "ACTION", 2, f"{defender} active Defender alert(s), medium included"
        return "CLEAR", 0, "no active Defender alerts"



    def recommendation_row(self, r):
        return {
            "title": r.get("recommendationName") or r.get("title") or r.get("name") or "Security recommendation",
            "severity": r.get("severity") or r.get("exposureImpact") or r.get("riskScore") or "",
            "status": r.get("status") or r.get("implementationStatus") or "",
            "category": r.get("category") or r.get("productName") or "",
            "impact": r.get("impact") or r.get("exposedMachinesCount") or r.get("exposedMachineCount") or "",
            "detail": r.get("description") or r.get("remediationType") or r.get("remediation") or "",
        }

    def vulnerability_row(self, v):
        return {
            "id": v.get("id") or v.get("cveId") or v.get("name") or "vulnerability",
            "severity": v.get("severity") or v.get("cvssV3") or v.get("cvssScore") or "",
            "cvss": v.get("cvssV3") or v.get("cvssScore") or "",
            "published": v.get("publishedOn") or v.get("publishedDate") or "",
            "updated": v.get("updatedOn") or v.get("lastModified") or "",
            "detail": v.get("description") or v.get("name") or "",
        }

    def machine_row(self, m):
        return {
            "name": m.get("computerDnsName") or m.get("machineName") or m.get("deviceName") or m.get("id") or "machine",
            "risk": m.get("riskScore") or m.get("exposureLevel") or "",
            "health": m.get("healthStatus") or m.get("onboardingStatus") or "",
            "os": m.get("osPlatform") or m.get("osProcessor") or "",
            "last_seen": m.get("lastSeen") or "",
            "ip": m.get("lastIpAddress") or "",
        }


    def _is_defender_related_row(self, source, title="", detail=""):
        raw = " ".join([str(source or ""), str(title or ""), str(detail or "")]).lower()
        needles = (
            "defender",
            "microsoft 365",
            "graph incidents",
            "security incidents",
            "mdo",
            "office 365",
            "email messages",
            "malicious url",
            "phish",
            "credential phish",
        )
        return any(n in raw for n in needles)


    def event_to_alert_row(self, event):
        source = str(event.get("source", "Unknown"))
        severity = str(event.get("severity", "info")).upper()
        title = str(event.get("title", ""))
        detail = str(event.get("detail", ""))
        status = "ACTIVE"
        lowered = (title + " " + detail).lower()
        if any(word in lowered for word in ("resolved", "closed", "dismissed", "cleared", "archived")):
            status = "RESOLVED/CLOSED"
        elif "remediated" in lowered:
            status = "REMEDIATED"
        elif "pending approval" in lowered or "pending action" in lowered:
            status = "PENDING"
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
            "type": "Incident" if "incident" in source.lower() else "Alert",
            "severity": severity,
            "title": title,
            "status": status,
            "detail": detail,
            "timestamp": event.get("timestamp", ""),
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
                    "stale_30_count": 0,
                    "unencrypted_count": 0,
                    "jailbroken_count": 0,
                    "no_user_count": 0,
                    "noncompliant_devices": [],
                    "stale_devices": [],
                    "unencrypted_devices": [],
                    "jailbroken_devices": [],
                    "detected_app_count": 0,
                    "detected_apps_source": "",
                    "detected_apps_error": "",
                    "software_issue_state": "ok",
                    "new_software_count": 0,
                    "new_software": [],
                    "detected_apps": [],
                    "alerts": 0,
                    "active_alerts": 0,
                    "returned_alerts": 0,
                    "resolved_alerts": 0,
                    "defender_alerts": 0,
                    "defender_critical": 0,
                    "defender_returned_alerts": 0,
                    "defender_resolved_alerts": 0,
                    "defender_machines": 0,
                    "defender_machine_rows": [],
                    "defender_machine_error": "",
                    "defender_recommendations": 0,
                    "defender_recommendation_rows": [],
                    "defender_recommendation_error": "",
                    "defender_vulnerabilities": 0,
                    "defender_vulnerability_rows": [],
                    "defender_vulnerability_error": "",
                    "graph_alerts": 0,
                    "graph_returned_alerts": 0,
                    "graph_resolved_alerts": 0,
                    "graph_incidents": 0,
                    "graph_returned_incidents": 0,
                    "graph_resolved_incidents": 0,
                    "critical": 0,
                    "wan_health": 0,
                    "unifi_connected": 0,
                    "unifi_sites": 0,
                    "unifi_devices": 0,
                    "unifi_clients": 0,
                    "unifi_traffic_items": 0,
                    "unifi_client_note": "",
                    "unifi_traffic_note": "",
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
        stale_30_count = sum(int(r.get("stale_30_count", 0)) for r in results)
        unencrypted_count = sum(int(r.get("unencrypted_count", 0)) for r in results)
        jailbroken_count = sum(int(r.get("jailbroken_count", 0)) for r in results)
        no_user_count = sum(int(r.get("no_user_count", 0)) for r in results)
        noncompliant_devices = []
        stale_devices = []
        unencrypted_devices = []
        jailbroken_devices = []
        detected_apps = []
        new_software = []
        for r in results:
            noncompliant_devices.extend(r.get("noncompliant_devices", []) or [])
            stale_devices.extend(r.get("stale_devices", []) or [])
            unencrypted_devices.extend(r.get("unencrypted_devices", []) or [])
            jailbroken_devices.extend(r.get("jailbroken_devices", []) or [])
            detected_apps.extend(r.get("detected_apps", []) or [])
            new_software.extend(r.get("new_software", []) or [])
        detected_app_count = sum(int(r.get("detected_app_count", 0)) for r in results)
        detected_apps_source = "; ".join([str(r.get("detected_apps_source", "")) for r in results if r.get("detected_apps_source")])
        detected_apps_error = "; ".join([str(r.get("detected_apps_error", "")) for r in results if r.get("detected_apps_error")])
        new_software_count = sum(int(r.get("new_software_count", 0)) for r in results)
        alerts = sum(int(r.get("alerts", 0)) for r in results)
        active_alerts = sum(int(r.get("active_alerts", r.get("alerts", 0))) for r in results)
        returned_alerts = sum(int(r.get("returned_alerts", r.get("alerts", 0))) for r in results)
        resolved_alerts = sum(int(r.get("resolved_alerts", 0)) for r in results)
        defender_alerts = sum(int(r.get("defender_alerts", 0)) for r in results)
        defender_critical = sum(int(r.get("defender_critical", 0)) for r in results)
        defender_returned_alerts = sum(int(r.get("defender_returned_alerts", r.get("defender_alerts", 0))) for r in results)
        defender_resolved_alerts = sum(int(r.get("defender_resolved_alerts", 0)) for r in results)
        defender_machines = sum(int(r.get("defender_machines", 0)) for r in results)
        defender_machine_rows = []
        defender_machine_error = "; ".join([str(r.get("defender_machine_error", "")) for r in results if r.get("defender_machine_error")])
        defender_recommendations = sum(int(r.get("defender_recommendations", 0)) for r in results)
        defender_recommendation_rows = []
        defender_recommendation_error = "; ".join([str(r.get("defender_recommendation_error", "")) for r in results if r.get("defender_recommendation_error")])
        defender_vulnerabilities = sum(int(r.get("defender_vulnerabilities", 0)) for r in results)
        defender_vulnerability_rows = []
        defender_vulnerability_error = "; ".join([str(r.get("defender_vulnerability_error", "")) for r in results if r.get("defender_vulnerability_error")])
        for r in results:
            defender_machine_rows.extend(r.get("defender_machine_rows", []) or [])
            defender_recommendation_rows.extend(r.get("defender_recommendation_rows", []) or [])
            defender_vulnerability_rows.extend(r.get("defender_vulnerability_rows", []) or [])

        graph_alerts = sum(int(r.get("graph_alerts", 0)) for r in results)
        graph_returned_alerts = sum(int(r.get("graph_returned_alerts", r.get("graph_alerts", 0))) for r in results)
        graph_resolved_alerts = sum(int(r.get("graph_resolved_alerts", 0)) for r in results)
        graph_incidents = sum(int(r.get("graph_incidents", 0)) for r in results)
        graph_returned_incidents = sum(int(r.get("graph_returned_incidents", r.get("graph_incidents", 0))) for r in results)
        graph_resolved_incidents = sum(int(r.get("graph_resolved_incidents", 0)) for r in results)
        # Global security criticality should come from Defender only.
        # Graph Security, Intune compliance and UniFi network health are visible context,
        # but they do not drive the headline Critical/High state.
        microsoft_critical = defender_critical
        critical = defender_critical
        unifi_connected = sum(int(r.get("unifi_connected", 0)) for r in results)
        unifi_sites = sum(int(r.get("unifi_sites", 0)) for r in results)
        unifi_devices = sum(int(r.get("unifi_devices", 0)) for r in results)
        unifi_clients = sum(int(r.get("unifi_clients", 0)) for r in results)
        unifi_traffic_items = sum(int(r.get("unifi_traffic_items", 0)) for r in results)
        unifi_client_note = "; ".join([str(r.get("unifi_client_note", "")) for r in results if r.get("unifi_client_note")])
        unifi_traffic_note = "; ".join([str(r.get("unifi_traffic_note", "")) for r in results if r.get("unifi_traffic_note")])
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
                "stale_30_count": stale_30_count,
                "unencrypted_count": unencrypted_count,
                "jailbroken_count": jailbroken_count,
                "no_user_count": no_user_count,
                "noncompliant_devices": noncompliant_devices[:500],
                "stale_devices": stale_devices[:500],
                "unencrypted_devices": unencrypted_devices[:500],
                "jailbroken_devices": jailbroken_devices[:200],
                "detected_app_count": detected_app_count,
                "detected_apps_source": detected_apps_source,
                "detected_apps_error": detected_apps_error,
                "software_issue_state": "429/backoff" if "429" in detected_apps_error else ("check" if detected_apps_error else "ok"),
                "new_software_count": new_software_count,
                "new_software": new_software[:300],
                "detected_apps": detected_apps[:20000],
                "alerts": active_alerts,
                "active_alerts": active_alerts,
                "returned_alerts": returned_alerts,
                "resolved_alerts": resolved_alerts,
                "defender_alerts": defender_alerts,
                "defender_critical": defender_critical,
                "defender_returned_alerts": defender_returned_alerts,
                "defender_resolved_alerts": defender_resolved_alerts,
                "defender_machines": defender_machines,
                "defender_machine_rows": defender_machine_rows[:500],
                "defender_machine_error": defender_machine_error,
                "defender_recommendations": defender_recommendations,
                "defender_recommendation_rows": defender_recommendation_rows[:500],
                "defender_recommendation_error": defender_recommendation_error,
                "defender_vulnerabilities": defender_vulnerabilities,
                "defender_vulnerability_rows": defender_vulnerability_rows[:500],
                "defender_vulnerability_error": defender_vulnerability_error,
                "graph_alerts": graph_alerts,
                "graph_returned_alerts": graph_returned_alerts,
                "graph_resolved_alerts": graph_resolved_alerts,
                "graph_incidents": graph_incidents,
                "graph_returned_incidents": graph_returned_incidents,
                "graph_resolved_incidents": graph_resolved_incidents,
                "critical": critical,
                "microsoft_critical": microsoft_critical,
                "wan_health": wan_health,
                "unifi_connected": unifi_connected,
                "unifi_sites": unifi_sites,
                "unifi_devices": unifi_devices,
                "unifi_clients": unifi_clients,
                "unifi_traffic_items": unifi_traffic_items,
                "unifi_client_note": unifi_client_note,
                "unifi_traffic_note": unifi_traffic_note,
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
        self.geometry("1760x1020")
        self.minsize(1360, 860)
        self.configure(bg=BG)
        self._init_fonts()
        self.cfg = Config.load()
        self.q = queue.Queue()
        self.engine = None
        self.metric_labels = {}
        self.metric_cards = {}
        self.platform_labels = {}
        self.alert_breakdown_labels = {}
        self.unifi_labels = {}
        self.connector_widgets = {}
        self.nav_rows = []
        self.current_main_frame = None
        self.focus_cards = {"defender": {}, "intune": {}, "unifi": {}, "software": {}}
        self.last_payload = None
        self.trend_history = {"defender": [], "compliance": [], "network": []}
        self.trend_canvases = {}
        self.trend_labels = {}
        self.security_signals_canvas = None
        self.table_sort_state = {}
        self.optional_metric_keys = ["wan_health"]
        self.optional_bars = []
        self.status_var = tk.StringVar(value="Starting telemetry engine...")
        self._setup_style()
        self._build()
        self.after(350, self.pulse_overview_status)
        self.start_engine()
        self.after(250, self.drain_queue)

    def _init_fonts(self):
        try:
            fams = set(tkfont.families())
        except Exception:
            fams = set()
        self.font_display = "SF Pro Display" if "SF Pro Display" in fams else ("Segoe UI Variable Display" if "Segoe UI Variable Display" in fams else "Segoe UI")
        self.font_text = "SF Pro Text" if "SF Pro Text" in fams else ("Segoe UI Variable Text" if "Segoe UI Variable Text" in fams else "Segoe UI")
        self.font_ui = self.font_text if self.font_text else "Segoe UI"

    def _rounded_points(self, x1, y1, x2, y2, r=18):
        r = max(4, min(r, int((x2 - x1) / 2), int((y2 - y1) / 2)))
        return [
            x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
            x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
            x1, y2, x1, y2-r, x1, y1+r, x1, y1
        ]

    def rounded_panel(self, parent, fill=None, border=None, radius=18, padding=1):
        parent_bg = parent.cget("bg") if hasattr(parent, 'cget') else BG
        shell = tk.Frame(parent, bg=parent_bg, bd=0, highlightthickness=0)
        canvas = tk.Canvas(shell, bg=parent_bg, highlightthickness=0, bd=0, relief="flat")
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=fill or PANEL, bd=0, highlightthickness=0)
        win = canvas.create_window((padding, padding), window=inner, anchor="nw")

        def redraw(event=None):
            w = max(canvas.winfo_width(), 40)
            h = max(canvas.winfo_height(), 40)
            canvas.delete("panel")
            pts = self._rounded_points(padding, padding, w-padding, h-padding, radius)
            canvas.create_polygon(pts, smooth=True, splinesteps=24, fill=fill or PANEL, outline=border or HAIRLINE, width=1.4, tags="panel")
            canvas.coords(win, padding+1, padding+1)
            canvas.itemconfigure(win, width=max(16, w-(padding+1)*2), height=max(16, h-(padding+1)*2))
            canvas.tag_lower("panel")

        canvas.bind("<Configure>", redraw)
        shell.canvas = canvas
        shell.inner = inner
        return shell, inner


    def glow_icon(self, parent, icon, color, size=18, bg=None, glow_layers=6, halo=True):
        """Dependency-free neon icon made from layered Tk glyphs."""
        try:
            bg = bg or parent.cget("bg")
        except Exception:
            bg = BG

        pad = max(22, int(size * 1.15))
        wrap = tk.Frame(parent, bg=bg, width=size + pad, height=size + pad)
        wrap.pack_propagate(False)

        if halo:
            try:
                halo_canvas = tk.Canvas(wrap, width=size + pad, height=size + pad, bg=bg, highlightthickness=0, bd=0)
                halo_canvas.place(relx=0.5, rely=0.5, anchor="center")
                cx = (size + pad) // 2
                cy = (size + pad) // 2
                for radius, outline, width in (
                    (int(size * 1.08), "#061827", 1),
                    (int(size * 0.86), "#113E5E", 1),
                    (int(size * 0.66), color, 1),
                ):
                    halo_canvas.create_oval(cx-radius//2, cy-radius//2, cx+radius//2, cy+radius//2, outline=outline, width=width)
            except Exception:
                pass

        glow_palette = ["#04111E", "#08273D", "#0E4E73", "#1599C2", color, color]
        for idx in range(max(1, glow_layers)):
            layer_color = glow_palette[min(idx, len(glow_palette) - 1)]
            lbl = tk.Label(
                wrap,
                text=icon,
                bg=bg,
                fg=layer_color,
                font=(self.font_ui, size + (glow_layers - idx) * 2, "bold"),
                bd=0,
                highlightthickness=0,
            )
            lbl.place(relx=0.5, rely=0.5, anchor="center")

        core = tk.Label(
            wrap,
            text=icon,
            bg=bg,
            fg=color,
            font=(self.font_ui, size, "bold"),
            bd=0,
            highlightthickness=0,
        )
        core.place(relx=0.5, rely=0.5, anchor="center")
        wrap.icon_label = core
        return wrap

    def glow_title(self, parent, icon, text, color, bg=None, font_size=20):
        try:
            bg = bg or parent.cget("bg")
        except Exception:
            bg = BG
        row = tk.Frame(parent, bg=bg)
        self.glow_icon(row, icon, color, size=font_size, bg=bg).pack(side="left", padx=(0, 10))
        tk.Label(row, text=text, bg=bg, fg=TEXT, font=(self.font_display, font_size, "bold")).pack(side="left")
        return row

    def neon_button(self, parent, label, icon, command, color=BLUE, width=150, active=False):
        shell = tk.Frame(parent, bg=BG, width=width, height=36)
        shell.pack_propagate(False)
        canvas = tk.Canvas(shell, bg=BG, width=width, height=36, highlightthickness=0, bd=0)
        canvas.pack(fill="both", expand=True)

        fill = "#0E2A44" if active else "#061827"
        border = color if active else "#183A55"
        pts = self._rounded_points(2, 3, width - 2, 33, 12)
        canvas.create_polygon(pts, smooth=True, splinesteps=18, fill=fill, outline=border, width=1.8)
        canvas.create_line(14, 3, width - 18, 3, fill=color if active else "#183A55", width=1)

        row = tk.Frame(canvas, bg=fill)
        self.glow_icon(row, icon, color, size=14, bg=fill, halo=False).pack(side="left", padx=(8, 5))
        tk.Label(row, text=label, bg=fill, fg="#F7FBFF" if active else "#9BE8FF", font=(self.font_ui, 9, "bold")).pack(side="left")
        canvas.create_window(width // 2, 18, window=row, width=width - 14, height=28)

        def invoke(event=None):
            try:
                command()
            except Exception as e:
                try:
                    self.status_var.set(f"Navigation error: {e}")
                except Exception:
                    pass

        def bind_tree(widget):
            try:
                widget.configure(cursor="hand2")
            except Exception:
                pass
            try:
                widget.bind("<Button-1>", invoke, add="+")
            except Exception:
                pass
            try:
                for child in widget.winfo_children():
                    bind_tree(child)
            except Exception:
                pass

        bind_tree(shell)
        return shell

    def neon_sidebar_item(self, parent, label, icon, command, color=BLUE, active=False):
        row_bg = "#061827"
        active_bg = "#0B3554"
        row = tk.Frame(parent, bg=active_bg if active else row_bg, height=36, highlightthickness=1 if active else 0, highlightbackground=color)
        row.pack(fill="x", padx=10, pady=2)
        row.pack_propagate(False)

        icon_w = self.glow_icon(row, icon, color, size=12, bg=row.cget("bg"), halo=False)
        icon_w.pack(side="left", padx=(8, 6))
        label_w = tk.Label(row, text=label, bg=row.cget("bg"), fg="#FFFFFF" if active else "#9EDFFF", font=(self.font_ui, 9, "bold"), anchor="w")
        label_w.pack(side="left", fill="x", expand=True)

        if not hasattr(self, "nav_rows"):
            self.nav_rows = []
        self.nav_rows.append({"row": row, "label": label_w, "color": color})

        def invoke(event=None):
            try:
                for nav in getattr(self, "nav_rows", []):
                    r = nav.get("row")
                    l = nav.get("label")
                    try:
                        r.configure(bg=row_bg, highlightthickness=0)
                        l.configure(bg=row_bg, fg="#B7D8F0")
                        for child in r.winfo_children():
                            try:
                                child.configure(bg=row_bg)
                            except Exception:
                                pass
                    except Exception:
                        pass
                row.configure(bg=active_bg, highlightthickness=1, highlightbackground=color)
                label_w.configure(bg=active_bg, fg="#FFFFFF")
                for child in row.winfo_children():
                    try:
                        child.configure(bg=active_bg)
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                command()
            except Exception as e:
                try:
                    self.status_var.set(f"Navigation error: {e}")
                except Exception:
                    pass

        def bind_tree(widget):
            try:
                widget.configure(cursor="hand2")
            except Exception:
                pass
            try:
                widget.bind("<Button-1>", invoke, add="+")
            except Exception:
                pass
            try:
                for child in widget.winfo_children():
                    bind_tree(child)
            except Exception:
                pass

        bind_tree(row)
        return row

    def neon_metric_tile(self, parent, title, value_key, icon, color, subtitle="", bucket="overview", width_pack=True):
        shell, panel = self.rounded_panel(parent, fill="#071827", border=color, radius=18, padding=1)
        shell.configure(height=138)
        shell.pack_propagate(False)
        if width_pack:
            shell.pack(side="left", fill="x", expand=True, padx=6, pady=6)
        else:
            shell.pack(fill="x", padx=6, pady=6)

        body = tk.Frame(panel, bg="#071827")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        top = tk.Frame(body, bg="#071827")
        top.pack(fill="x")
        self.glow_icon(top, icon, color, size=24, bg="#071827").pack(side="left", padx=(0, 12))
        title_box = tk.Frame(top, bg="#071827")
        title_box.pack(side="left", fill="x", expand=True)
        tk.Label(title_box, text=title.upper(), bg="#071827", fg="#CDEBFF", font=(self.font_ui, 9, "bold")).pack(anchor="w")
        val = tk.Label(title_box, text="--", bg="#071827", fg=color, font=(self.font_display, 24, "bold"))
        val.pack(anchor="w", pady=(4, 0))
        hint = tk.Label(body, text=subtitle or "Live telemetry", bg="#071827", fg="#AFC9DE", font=(self.font_ui, 9), anchor="w")
        hint.pack(fill="x", pady=(8, 0))
        if not hasattr(self, "neon_tiles"):
            self.neon_tiles = {}
        self.neon_tiles[value_key] = {"value": val, "hint": hint, "base": color, "shell": shell, "panel": panel}
        return shell

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT, font=(self.font_ui, 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=(self.font_ui, 10))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=(self.font_display, 24, "bold"))
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT, font=(self.font_display, 24, "bold"))
        style.configure("SmallCard.TLabel", background=PANEL, foreground=MUTED, font=(self.font_ui, 10))
        style.configure("TButton", font=(self.font_ui, 10, "bold"), padding=8)
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT, font=(self.font_ui, 10))
        style.configure("TEntry", fieldbackground="#0F1524", foreground=TEXT, insertcolor=TEXT, bordercolor="#24304A")
        style.configure("Dasher.TNotebook", background=BG, borderwidth=0, tabmargins=(0, 8, 0, 0))
        style.configure("MainHidden.TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("SubHidden.TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        try:
            style.layout("MainHidden.TNotebook.Tab", [])
        except Exception:
            pass
        try:
            style.layout("SubHidden.TNotebook.Tab", [])
        except Exception:
            pass
        style.configure("Dasher.TNotebook.Tab", background="#101620", foreground=MUTED, padding=(24, 12), font=(self.font_ui, 10, "bold"), borderwidth=0)
        style.map("Dasher.TNotebook.Tab",
                  background=[("selected", "#223044"), ("active", "#17212D")],
                  foreground=[("selected", TEXT), ("active", TEXT)])
        style.configure("Dasher.Treeview",
                  background="#071827",
                  foreground="#F2F8FF",
                  fieldbackground="#071827",
                  rowheight=31,
                  borderwidth=0,
                  relief="flat",
                  font=(self.font_ui, 10))
        style.configure("Dasher.Treeview.Heading",
                  background="#18324B",
                  foreground="#F5FBFF",
                  relief="flat",
                  padding=(8, 8),
                  font=(self.font_ui, 10, "bold"))
        style.map("Dasher.Treeview",
                  background=[("selected", "#1A456B")],
                  foreground=[("selected", TEXT)])

    def make_scrollable_page(self, parent, show_scrollbar=False):
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0)
        inner = tk.Frame(canvas, bg=BG)
        win = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_inner_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event):
            canvas.itemconfigure(win, width=event.width)

        inner.bind("<Configure>", on_inner_configure)
        canvas.bind("<Configure>", on_canvas_configure)

        canvas.pack(side="left", fill="both", expand=True)

        if show_scrollbar:
            scroll = tk.Scrollbar(outer, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")

            def on_wheel(event):
                try:
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                except Exception:
                    pass

            canvas.bind("<Enter>", lambda event: canvas.bind_all("<MouseWheel>", on_wheel))
            canvas.bind("<Leave>", lambda event: canvas.unbind_all("<MouseWheel>"))

        return inner

    def _build(self):
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True, padx=8, pady=4)

        main_shell = tk.Frame(shell, bg=BG)
        main_shell.pack(fill="both", expand=True)

        self._build_left_nav(main_shell)

        content_shell = tk.Frame(main_shell, bg=BG)
        content_shell.pack(side="left", fill="both", expand=True)

        header = tk.Frame(content_shell, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text="", bg=BG, fg=TEXT, font=(self.font_display, 1, "bold")).pack(side="left")
        tk.Label(header, text="Defender priority • Intune estate • UniFi health  ●", bg=BG, fg="#AFC3D8", font=(self.font_ui, 11, "bold")).pack(side="left", padx=18, pady=(14,0))
        tk.Button(header, text="⚙  Setup connectors", command=self.open_setup, bg="#101B2A", fg=TEXT, activebackground="#1D2D42", relief="flat", padx=18, pady=10, font=(self.font_ui, 10, "bold"), highlightthickness=1, highlightbackground=HAIRLINE).pack(side="right")
        tk.Button(header, text="⇩  Export UniFi debug", command=self.export_unifi_debug, bg="#101B2A", fg=TEXT, activebackground="#1D2D42", relief="flat", padx=18, pady=10, font=(self.font_ui, 9, "bold"), highlightthickness=1, highlightbackground=HAIRLINE).pack(side="right", padx=(0, 10))

        self.overview = tk.Frame(shell, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        # self.overview.pack(fill="x", pady=(14, 6))  # Hidden: status now lives in the Overview page itself.
        self.state_badge = tk.Label(self.overview, text="INITIALISING", bg=PANEL, fg=BLUE, font=(self.font_ui, 10, "bold"))
        self.state_badge.pack(side="left", padx=(18, 10), pady=12)
        self.state_detail = tk.Label(self.overview, text="Waiting for first telemetry pull...", bg=PANEL, fg=TEXT, font=(self.font_ui, 10))
        self.state_detail.pack(side="left", padx=(0, 8), pady=12)
        self.live_badge = tk.Label(self.overview, text="LIVE: NONE", bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold"))
        self.live_badge.pack(side="right", padx=(8, 18), pady=12)

        self.main_tab_names = []
        self.main_tab_buttons = {}
        self.main_tab_bar = tk.Frame(content_shell, bg=BG)
        self.main_tab_bar.pack(fill="x", pady=(0, 2))

        self.main_tabs = ttk.Notebook(content_shell, style="MainHidden.TNotebook")
        self.main_tabs.pack(fill="both", expand=True)

        self.tab_overview = tk.Frame(self.main_tabs, bg=BG)
        self.tab_defender = tk.Frame(self.main_tabs, bg=BG)
        self.tab_intune = tk.Frame(self.main_tabs, bg=BG)
        self.tab_unifi = tk.Frame(self.main_tabs, bg=BG)
        self.tab_software = tk.Frame(self.main_tabs, bg=BG)

        self.main_tabs.add(self.tab_overview, text="Overview")
        self.main_tabs.add(self.tab_defender, text="Defender")
        self.main_tabs.add(self.tab_intune, text="Intune")
        self.main_tabs.add(self.tab_unifi, text="UniFi")
        self.main_tabs.add(self.tab_software, text="Software")
        self._build_main_tab_pills()

        body = self.make_scrollable_page(self.tab_overview, show_scrollbar=True)

        self.overview_focus_bar = tk.Frame(body, bg=GLASS, highlightthickness=1, highlightbackground=HAIRLINE)
        self.overview_focus_bar.pack(fill="x", pady=(0, 4))
        tk.Label(self.overview_focus_bar, text="", bg=GLASS, fg="#58C7FF", font=(self.font_ui, 8, "bold")).pack(anchor="w", padx=14, pady=(7, 1))
        self.overview_focus_text = tk.Label(self.overview_focus_bar, text="Defender • Intune • Software • UniFi • scrollable live tables", bg=GLASS, fg=TEXT, font=(self.font_ui, 12, "bold"), justify="left")
        self.overview_focus_text.pack(anchor="w", padx=14, pady=(0, 7))
        self.hero_strip = tk.Frame(body, bg=BG)
        self.hero_strip.pack(fill="x", pady=(0, 4))

        self.hero_priority_shell, self.hero_priority_panel = self.rounded_panel(self.hero_strip, fill=PANEL, border=HAIRLINE, radius=24, padding=1)
        self.hero_priority_shell.configure(height=150, width=1160)
        self.hero_priority_shell.pack_propagate(False)
        self.hero_priority_shell.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=2)

        hero_top = tk.Frame(self.hero_priority_panel, bg=PANEL)
        hero_top.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(hero_top, text="Defender priority", bg=PANEL, fg=MUTED, font=(self.font_ui, 11, "bold")).pack(side="left")
        self.hero_priority_pill = tk.Label(hero_top, text="LIVE", bg="#132235", fg=BLUE, font=(self.font_ui, 8, "bold"), padx=10, pady=3)
        self.hero_priority_pill.pack(side="right")
        self.hero_priority_value = tk.Label(self.hero_priority_panel, text="DEFENDER ACTION", bg=PANEL, fg=ORANGE, font=(self.font_display, 30, "bold"))
        self.hero_priority_value.pack(anchor="w", padx=22, pady=(16, 0))
        self.hero_priority_detail = tk.Label(self.hero_priority_panel, text="5 active Defender alert(s) need triage.", bg=PANEL, fg=TEXT, font=(self.font_ui, 12, "bold"), justify="left")
        self.hero_priority_detail.pack(anchor="w", padx=22, pady=(4, 0))
        self.hero_priority_meta = tk.Label(self.hero_priority_panel, text="Medium and informational Defender alerts stay visible in the focus table.", bg=PANEL, fg="#C4D2E3", font=(self.font_ui, 11), justify="left")
        self.hero_priority_meta.pack(anchor="w", padx=22, pady=(6, 12))

        self.heartbeat_shell, self.heartbeat_panel = self.rounded_panel(self.hero_strip, fill=GLASS, border=HAIRLINE, radius=24, padding=1)
        self.heartbeat_shell.configure(height=150, width=560)
        self.heartbeat_shell.pack_propagate(False)
        self.heartbeat_shell.pack(side="left", fill="x", expand=False, padx=(0, 0), pady=2)

        hb_top = tk.Frame(self.heartbeat_panel, bg=GLASS)
        hb_top.pack(fill="x", padx=16, pady=(12, 2))
        tk.Label(hb_top, text="Live heartbeat", bg=GLASS, fg=MUTED, font=(self.font_ui, 10, "bold")).pack(side="left")
        self.heartbeat_state = tk.Label(hb_top, text="CONNECTING", bg=GLASS, fg=BLUE, font=(self.font_ui, 10, "bold"))
        self.heartbeat_state.pack(side="right")
        self.heartbeat_meta = tk.Label(self.heartbeat_panel, text="Polling links not yet active", bg=GLASS, fg=TEXT, font=(self.font_ui, 9, "bold"), anchor="w")
        self.heartbeat_meta.pack(fill="x", padx=16, pady=(0, 4))
        self.heartbeat_canvas = tk.Canvas(self.heartbeat_panel, height=74, bg=GLASS, highlightthickness=0, bd=0)
        self.heartbeat_canvas.pack(fill="x", padx=14, pady=(0, 12))

        self.overview_status_cards = tk.Frame(body, bg=BG)
        self.overview_status_cards.pack(fill="x", pady=(0, 4))
        self.overview_status = {}
        for title, key, color in [
            ("Defender", "overview_defender", ORANGE),
            ("Intune", "overview_intune", AMBER),
            ("UniFi", "overview_unifi", BLUE),
            ("Software", "overview_software", GREEN),
        ]:
            shell, panel = self.rounded_panel(self.overview_status_cards, fill=PANEL, border=HAIRLINE, radius=20, padding=1)
            shell.configure(height=178)
            shell.pack_propagate(False)
            shell.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=(6, 10))

            card_body = tk.Frame(panel, bg=PANEL)
            card_body.pack(fill="both", expand=True, padx=22, pady=16)
            top = tk.Frame(card_body, bg=PANEL)
            top.pack(fill="x")
            icon_text = {"Defender": "🛡", "Intune": "👤", "UniFi": "📶", "Software": "💾"}.get(title, "•")
            dot = self.glow_icon(top, icon_text, color, size=26, bg=PANEL, halo=True, glow_layers=7)
            dot.pack(side="left", padx=(0, 16))
            title_col = tk.Frame(top, bg=PANEL)
            title_col.pack(side="left", fill="x", expand=True)
            tk.Label(title_col, text=title, bg=PANEL, fg=TEXT, font=(self.font_ui, 10, "bold"), anchor="w").pack(anchor="w")
            micro_text = {
                "Defender": "Open Defender details ->",
                "Intune": "Open Intune posture ->",
                "UniFi": "Open UniFi estate ->",
                "Software": "Open software inventory ->",
            }.get(title, "Open details ->")
            tk.Label(title_col, text=micro_text, bg=PANEL, fg="#58C7FF", font=(self.font_ui, 8, "bold"), anchor="w").pack(anchor="w", pady=(1, 0))

            value = tk.Label(card_body, text="Awaiting data", bg=PANEL, fg=color, font=(self.font_display, 20, "bold"), anchor="w")
            value.pack(fill="x", pady=(14, 4))
            detail = tk.Label(card_body, text="Connector warming up", bg=PANEL, fg=MUTED, font=(self.font_ui, 9), wraplength=520, justify="left", anchor="w")
            detail.pack(fill="x")

            self.overview_status[key] = {
                "shell": shell,
                "panel": panel,
                "dot": dot,
                "value": value,
                "detail": detail,
                "base": color,
                "pulse": 0,
            }


        self.trend_strip = tk.Frame(body, bg=BG)
        # Trend strip hidden from Overview to keep the front page readable.
        # Detailed sortable tables carry the operational view.
        # self.trend_strip.pack(fill="x", pady=(0, 4))
        for col in range(2):
            self.trend_strip.grid_columnconfigure(col, weight=1)

        for idx, (title, key, color) in enumerate([
            ("Active alerts", "defender", ORANGE),
            ("Compliance drift", "compliance", BLUE),
            ("Offline site trend", "network", RED),
            ("Signal composition", "security_signals", BLUE),
        ]):
            panel_shell, panel = self.rounded_panel(self.trend_strip, fill=GLASS, border=HAIRLINE, radius=22, padding=1)
            panel_shell.configure(height=108)
            panel_shell.grid(row=idx // 2, column=idx % 2, sticky="nsew", padx=(0 if idx % 2 else 0, 8 if idx % 2 == 0 else 0), pady=4)
            panel_shell.grid_propagate(False)

            tk.Label(panel, text=title, bg=GLASS, fg=MUTED, font=(self.font_ui, 8, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
            val = tk.Label(panel, text="--", bg=GLASS, fg=color, font=(self.font_display, 18, "bold"))
            val.pack(anchor="w", padx=12)
            c = tk.Canvas(panel, height=66, bg=GLASS, highlightthickness=0, bd=0)
            c.pack(fill="both", expand=True, padx=10, pady=(0, 10))
            if key == "security_signals":
                self.security_signals_canvas = c
                self.trend_labels[key] = val
            else:
                self.trend_labels[key] = val
                self.trend_canvases[key] = (c, color)

        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        # Right-side Overview signal rail removed. Full signal feed now owns the lower Overview area.
        self.feed = None
        self.feed_canvas = None

        self.security_posture_strip = tk.Frame(left, bg=BG)
        self.security_posture_strip.pack(fill="x", pady=(6, 10))
        self.posture_labels = {}
        for label, key, color, icon in [
            ("Stale 30+ days", "stale_30_count", BLUE, "🥖"),
            ("Unencrypted", "unencrypted_count", RED, "🔑"),
            ("No primary user", "no_user_count", AMBER, "👤"),
            ("Degraded sites", "unifi_degraded_sites", ORANGE, "⚠"),
        ]:
            shell, panel = self.rounded_panel(self.security_posture_strip, fill=GLASS, border=HAIRLINE, radius=18, padding=1)
            shell.configure(height=134)
            shell.pack_propagate(False)
            shell.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=(0, 4))
            body_row = tk.Frame(panel, bg=GLASS)
            body_row.pack(fill="both", expand=True, padx=20, pady=15)
            badge = tk.Canvas(body_row, width=58, height=58, bg=GLASS, highlightthickness=0, bd=0)
            badge.pack(side="left", padx=(0, 16))
            # Row 3 icon glow: no badge circles, just a clean neon glyph.
            # Tkinter has no native blur, so layer translucent-looking text offsets
            # to create a soft halo around each icon.
            for dx, dy in ((0, -2), (0, 2), (-2, 0), (2, 0), (-1, -1), (1, -1), (-1, 1), (1, 1)):
                badge.create_text(29 + dx, 29 + dy, text=icon, fill="#12324A", font=(self.font_ui, 25, "bold"))
            for dx, dy in ((0, -1), (0, 1), (-1, 0), (1, 0)):
                badge.create_text(29 + dx, 29 + dy, text=icon, fill=color, font=(self.font_ui, 23, "bold"))
            badge.create_text(29, 29, text=icon, fill="#F4FBFF", font=(self.font_ui, 22, "bold"))
            text_col = tk.Frame(body_row, bg=GLASS)
            text_col.pack(side="left", fill="both", expand=True)
            tk.Label(text_col, text=label, bg=GLASS, fg="#D7E7F7", font=(self.font_ui, 10, "bold")).pack(anchor="w")
            subcopy = {
                "Stale 30+ days": "last check-in drift",
                "Unencrypted": "device protection gap",
                "No primary user": "ownership missing",
                "Degraded sites": "UniFi site health",
            }.get(label, "live posture")
            tk.Label(text_col, text=subcopy + "  ->", bg=GLASS, fg="#58C7FF", font=(self.font_ui, 7, "bold")).pack(anchor="w", pady=(1, 0))
            val = tk.Label(text_col, text="--", bg=GLASS, fg=color, font=(self.font_display, 24, "bold"))
            val.pack(anchor="w", pady=(0, 0))
            self.posture_labels[key] = val

        cards = tk.Frame(left, bg=BG)
        # Legacy KPI grid hidden on Overview. Status cards + graphs now carry the front page.
        # cards.pack(fill="x")
        for i in range(4):
            cards.grid_columnconfigure(i, weight=1)
        self.card(cards, 0, 0, "Defender priority", "priority_state", ORANGE)
        self.card(cards, 0, 1, "Active security items", "alerts", ORANGE)
        self.card(cards, 0, 2, "Intune compliance gap", "noncompliant", AMBER)
        self.card(cards, 0, 3, "High/Critical Defender", "critical", RED)
        self.card(cards, 1, 0, "Intune devices", "devices", GREEN)
        self.card(cards, 1, 1, "UniFi devices", "unifi_devices", BLUE)
        self.card(cards, 1, 2, "UniFi sites", "unifi_sites", GREEN)
        self.card(cards, 1, 3, "Offline sites", "unifi_critical_sites", RED)


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
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=(self.font_ui, 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="--", bg=PANEL, fg=color, font=(self.font_display, 14, "bold"))
            val.pack(anchor="w")
            self.unifi_labels[key] = val


        self.network_summary_bar = tk.Frame(left, bg=GLASS, highlightthickness=1, highlightbackground=HAIRLINE)
        # Overview now keeps network detail in the top cards and executive snapshot.
        # Full site detail lives on the UniFi tab.
        # self.network_summary_bar.pack(fill="x", pady=(8, 0))
        ns_left = tk.Frame(self.network_summary_bar, bg=GLASS)
        ns_left.pack(side="left", fill="x", expand=True, padx=12, pady=6)
        tk.Label(ns_left, text="Network site status", bg=GLASS, fg=MUTED, font=(self.font_ui, 8, "bold")).pack(anchor="w")
        self.network_status_big = tk.Label(ns_left, text="--", bg=GLASS, fg=BLUE, font=(self.font_display, 15, "bold"))
        self.network_status_big.pack(anchor="w")
        ns_right = tk.Frame(self.network_summary_bar, bg=GLASS)
        ns_right.pack(side="right", fill="x", expand=True, padx=12, pady=6)
        tk.Label(ns_right, text="UniFi site health summary", bg=GLASS, fg=MUTED, font=(self.font_ui, 8, "bold")).pack(anchor="w")
        self.network_status_detail = tk.Label(ns_right, text="Waiting for UniFi site data", bg=GLASS, fg=TEXT, font=(self.font_ui, 10, "bold"), justify="left")
        self.network_status_detail.pack(anchor="w")

        self.unifi_site_health_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        site_header = tk.Frame(self.unifi_site_health_bar, bg=PANEL)
        site_header.pack(fill="x", padx=12, pady=(8, 2))
        self.unifi_site_health_title = tk.Label(site_header, text="UniFi network sites", bg=PANEL, fg=TEXT, font=(self.font_ui, 10, "bold"))
        self.unifi_site_health_title.pack(side="left")
        self.unifi_site_health_summary = tk.Label(site_header, text="Waiting for UniFi site health...", bg=PANEL, fg=MUTED, font=(self.font_ui, 8, "bold"))
        self.unifi_site_health_summary.pack(side="right")

        self.unifi_site_table_canvas = tk.Canvas(self.unifi_site_health_bar, bg=PANEL, highlightthickness=0, bd=0, height=150)
        self.unifi_site_table_scrollbar = tk.Scrollbar(self.unifi_site_health_bar, orient="vertical", command=self.unifi_site_table_canvas.yview, bg=PANEL, troughcolor=BG)
        self.unifi_site_table_canvas.configure(yscrollcommand=self.unifi_site_table_scrollbar.set)
        self.unifi_site_table_canvas.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=(0, 4))
        self.unifi_site_table_scrollbar.pack(side="right", fill="y", padx=(0, 12), pady=(0, 4))

        self.unifi_site_table = tk.Frame(self.unifi_site_table_canvas, bg=PANEL)
        self.unifi_site_table_window = self.unifi_site_table_canvas.create_window((0, 0), window=self.unifi_site_table, anchor="nw")
        self.unifi_site_table.bind("<Configure>", self._on_unifi_site_table_configure)
        self.unifi_site_table_canvas.bind("<Configure>", self._on_unifi_site_table_canvas_configure)
        self.unifi_site_table_canvas.bind("<Enter>", self._bind_unifi_site_table_mousewheel)
        self.unifi_site_table_canvas.bind("<Leave>", self._unbind_unifi_site_table_mousewheel)


        self.platform_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        # self.platform_bar.pack(fill="x", pady=(8, 0))  # Dropped from Overview for a cleaner status-led front page.

        self.overview_defender_feed_shell, self.overview_defender_feed_panel = self.rounded_panel(left, fill=GLASS, border=HAIRLINE, radius=22, padding=1)
        self.overview_defender_feed_shell.pack(fill="both", expand=False, pady=(8, 0))

        defender_feed_header = tk.Frame(self.overview_defender_feed_panel, bg=GLASS)
        defender_feed_header.pack(fill="x", padx=14, pady=(6, 2))
        tk.Label(defender_feed_header, text="🛡  Defender / Microsoft security incidents & alerts", bg=GLASS, fg=TEXT, font=(self.font_display, 21, "bold")).pack(side="left")
        self.overview_defender_feed_summary = tk.Label(defender_feed_header, text="6 active Defender item(s)  •  0 high/critical  •  1 medium  •  click headers to sort", bg=GLASS, fg="#B7C9DB", font=(self.font_ui, 8, "bold"))
        self.overview_defender_feed_summary.pack(side="right")

        self.overview_defender_feed_table_wrap = tk.Frame(self.overview_defender_feed_panel, bg=GLASS)
        self.overview_defender_feed_table_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.overview_defender_feed_scrollbar = tk.Scrollbar(self.overview_defender_feed_table_wrap, orient="vertical")
        self.overview_defender_feed_scrollbar.pack(side="right", fill="y")
        self.overview_defender_feed_table = ttk.Treeview(
            self.overview_defender_feed_table_wrap,
            columns=("severity", "time", "title", "status", "detail"),
            show="headings",
            style="Dasher.Treeview",
            yscrollcommand=self.overview_defender_feed_scrollbar.set,
            selectmode="browse",
            height=6,
        )
        self.setup_tree_columns(self.overview_defender_feed_table, [
            ("severity", "Severity", 105),
            ("time", "Time", 160),
            ("title", "Alert / finding", 520),
            ("status", "Status", 120),
            ("detail", "Detail", 760),
        ])
        self.overview_defender_feed_table.pack(side="left", fill="both", expand=True)
        self.overview_defender_feed_scrollbar.config(command=self.overview_defender_feed_table.yview)
        self.overview_defender_feed_table.tag_configure("sev_critical", background="#0E2134", foreground="#FF6B8A")
        self.overview_defender_feed_table.tag_configure("sev_high", background="#0E2134", foreground="#FFB45E")
        self.overview_defender_feed_table.tag_configure("sev_medium", background="#0E2134", foreground="#FFD75A")
        self.overview_defender_feed_table.tag_configure("sev_info", background="#0A2031", foreground="#58C7FF")
        self.overview_defender_feed_table.tag_configure("sev_low", background="#0B2232", foreground="#72F26B")
        self._bind_treeview_mousewheel(self.overview_defender_feed_table)

        self.overview_full_feed_shell, self.overview_full_feed_panel = self.rounded_panel(left, fill=GLASS, border=HAIRLINE, radius=22, padding=1)
        self.overview_full_feed_shell.pack(fill="both", expand=False, pady=(8, 0))

        full_feed_header = tk.Frame(self.overview_full_feed_panel, bg=GLASS)
        full_feed_header.pack(fill="x", padx=14, pady=(6, 2))
        tk.Label(full_feed_header, text="⚡  Full signal feed", bg=GLASS, fg=TEXT, font=(self.font_display, 18, "bold")).pack(side="left")
        tk.Label(full_feed_header, text="Color-coded live event table  •  severity first, newest items first", bg=GLASS, fg="#B7C9DB", font=(self.font_ui, 8, "bold")).pack(side="right")

        self.overview_full_feed_table_wrap = tk.Frame(self.overview_full_feed_panel, bg=GLASS)
        self.overview_full_feed_table_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.overview_full_feed_scrollbar = tk.Scrollbar(self.overview_full_feed_table_wrap, orient="vertical")
        self.overview_full_feed_scrollbar.pack(side="right", fill="y")
        self.overview_full_feed_table = ttk.Treeview(
            self.overview_full_feed_table_wrap,
            columns=("severity", "source", "time", "title", "detail"),
            show="headings",
            style="Dasher.Treeview",
            yscrollcommand=self.overview_full_feed_scrollbar.set,
            selectmode="browse",
            height=5,
        )
        self.setup_tree_columns(self.overview_full_feed_table, [
            ("severity", "Severity", 96),
            ("source", "Source", 168),
            ("time", "Time", 158),
            ("title", "Alert / finding", 520),
            ("detail", "Detail", 820),
        ])
        self.overview_full_feed_table.pack(side="left", fill="both", expand=True)
        self.overview_full_feed_scrollbar.config(command=self.overview_full_feed_table.yview)
        self.overview_full_feed_table.tag_configure("sev_critical", background="#0E2134", foreground="#FF6B8A")
        self.overview_full_feed_table.tag_configure("sev_high", background="#0E2134", foreground="#FFB45E")
        self.overview_full_feed_table.tag_configure("sev_medium", background="#0E2134", foreground="#FFD75A")
        self.overview_full_feed_table.tag_configure("sev_info", background="#0A2031", foreground="#58C7FF")
        self.overview_full_feed_table.tag_configure("sev_low", background="#0B2232", foreground="#72F26B")
        self.overview_full_feed_table.tag_configure("oddrow", background="#0F2234", foreground="#D8E8F8")
        self.overview_full_feed_table.tag_configure("alt", background="#102235", foreground="#DCEBFA")
        self._bind_treeview_mousewheel(self.overview_full_feed_table)
        self.overview_full_feed_canvas = self.overview_full_feed_table
        self.overview_full_feed = self.overview_full_feed_table
        for label, key, color in [
            ("Windows devices", "windows", BLUE),
            ("iPhone / iPad", "ios", GREEN),
            ("Mac devices", "macos", PURPLE),
            ("Android", "android", AMBER),
            ("Other OS", "other_os", MUTED),
        ]:
            box = tk.Frame(self.platform_bar, bg=PANEL)
            box.pack(side="left", fill="x", expand=True, padx=14, pady=12)
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=(self.font_ui, 8, "bold")).pack(anchor="w")
            val = tk.Label(box, text="0", bg=PANEL, fg=color, font=(self.font_display, 15, "bold"))
            val.pack(anchor="w")
            self.platform_labels[key] = val


        self.alert_table_panel = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        # Overview is intentionally executive: detailed alert rows live on the Defender tab.
        # self.alert_table_panel.pack(fill="both", expand=True, pady=(12, 0))

        table_header = tk.Frame(self.alert_table_panel, bg=PANEL)
        table_header.pack(fill="x", padx=12, pady=(7, 3))
        tk.Label(table_header, text="Security alert table", bg=PANEL, fg=TEXT, font=(self.font_display, 14, "bold")).pack(side="left")
        self.alert_table_summary = tk.Label(table_header, text="Waiting for live rows...", bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold"))
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

        self._build_focus_tabs()
        self._rebuild_defender_page_v2()
        self._normalize_defender_tables()
        self._enforce_soc_console_overview()
        self._polish_all_table_chrome()
        self._bind_overview_action_navigation()
        self.bind("<Configure>", self._fit_soc_console_overview, add="+")

        footer = tk.Frame(shell, bg=BG)
        footer.pack_forget()  # hidden to match the one-screen SOC console reference
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED, font=(self.font_ui, 10)).pack(side="left")
        tk.Label(footer, text="Overview shows the big hitters. Detail lives in Defender, Intune, UniFi and Software. No simulated telemetry.", bg=BG, fg="#526078", font=(self.font_ui, 10)).pack(side="right")


    def _enforce_soc_console_overview(self):
        """Final Overview layout guard: force the polished SOC-console composition.

        This prevents older chart-heavy Overview widgets from reappearing when an
        earlier file version or stale geometry setting is mixed in.
        """
        for widget_name in ("trend_strip", "unifi_bar", "network_summary_bar", "unifi_site_health_bar", "platform_bar", "alert_table_panel"):
            widget = getattr(self, widget_name, None)
            if widget is not None:
                try:
                    widget.pack_forget()
                    widget.grid_forget()
                except Exception:
                    pass

        layout_heights = {
            "hero_priority_shell": 150,
            "heartbeat_shell": 150,
            "overview_defender_feed_shell": 260,
            "overview_full_feed_shell": 285,
        }
        for name, height in layout_heights.items():
            widget = getattr(self, name, None)
            if widget is not None:
                try:
                    widget.configure(height=height)
                    widget.pack_propagate(False)
                    widget.grid_propagate(False)
                except Exception:
                    pass

    def _fit_soc_console_overview(self, event=None):
        """Keep the Overview inside one screen without the outer page clipping."""
        try:
            if event is not None and event.widget is not self:
                return
            h = max(780, self.winfo_height())
            compact = h < 900
            extra = max(0, h - 900)

            sizes = {
                "hero_priority_shell": 142 if compact else 150,
                "heartbeat_shell": 142 if compact else 150,
                "overview_defender_feed_shell": 232 if compact else 260,
                "overview_full_feed_shell": (246 if compact else 285) + extra,
            }
            for name, height in sizes.items():
                widget = getattr(self, name, None)
                if widget is not None:
                    widget.configure(height=height)

            for tree_name, rows in (
                ("overview_defender_feed_table", 6 if compact else 7),
                ("overview_full_feed_table", max(8, (8 if compact else 10) + extra // 34)),
            ):
                tree = getattr(self, tree_name, None)
                if tree is not None:
                    tree.configure(height=rows)
        except Exception:
            pass

    def _polish_all_table_chrome(self):
        """Apple-meets-Linux table pass: glass rows, capsule text, no muddy slabs."""
        try:
            style = ttk.Style()
            style.configure("Dasher.Treeview",
                            background="#071A2A",
                            fieldbackground="#071A2A",
                            foreground="#EAF4FF",
                            rowheight=32,
                            borderwidth=0,
                            relief="flat",
                            font=(self.font_ui, 10))
            style.configure("Dasher.Treeview.Heading",
                            background="#162C43",
                            foreground="#F3FAFF",
                            relief="flat",
                            font=(self.font_ui, 10, "bold"))
            style.map("Dasher.Treeview",
                      background=[("selected", "#1A3B5C")],
                      foreground=[("selected", TEXT)])
        except Exception:
            pass

        for tree_name in (
            "overview_defender_feed_table", "overview_full_feed_table",
            "defender_alert_table", "defender_signal_table",
            "intune_noncompliant_table", "intune_stale_table", "intune_posture_table",
            "unifi_sites_table", "unifi_notes_table",
            "software_new_table", "software_all_table",
        ):
            tree = getattr(self, tree_name, None)
            if tree is None:
                continue
            try:
                tree.tag_configure("bad", foreground="#FF5C94", background="#2B071D")
                tree.tag_configure("high", foreground="#FFC84A", background="#292304")
                tree.tag_configure("warn", foreground="#FFE25A", background="#2A2604")
                tree.tag_configure("good", foreground="#7DFF57", background="#07301B")
                tree.tag_configure("info", foreground="#36CFFF", background="#08263E")
                tree.tag_configure("alt", foreground="#E5F4FF", background="#0A1D30")
                tree.tag_configure("sev_critical", foreground="#FF5C94", background="#2B071D")
                tree.tag_configure("sev_high", foreground="#FFC84A", background="#292304")
                tree.tag_configure("sev_medium", foreground="#FFE25A", background="#2A2604")
                tree.tag_configure("sev_info", foreground="#36CFFF", background="#08263E")
                tree.tag_configure("sev_low", foreground="#7DFF57", background="#07301B")
                tree.tag_configure("os_windows", foreground="#65D1FF", background="#09233A")
                tree.tag_configure("os_ios", foreground="#8DFF82", background="#0B2A25")
                tree.tag_configure("os_macos", foreground="#C19BFF", background="#161D34")
                tree.tag_configure("os_android", foreground="#FFE36E", background="#1D2531")
                tree.tag_configure("os_other", foreground="#C9D6E5", background="#0B1F31")
            except Exception:
                pass

    def _make_clickable_recursive(self, widget, command, cursor="hand2"):
        """Make a composite card feel like one clickable action tile."""
        try:
            widget.configure(cursor=cursor)
        except Exception:
            pass
        try:
            widget.bind("<Button-1>", lambda event: command(), add="+")
        except Exception:
            pass
        try:
            for child in widget.winfo_children():
                self._make_clickable_recursive(child, command, cursor=cursor)
        except Exception:
            pass

    def _bind_overview_action_navigation(self):
        """Wire the Overview action ribbon to the matching detailed tabs."""
        mapping = {
            "overview_defender": self.tab_defender,
            "overview_intune": self.tab_intune,
            "overview_unifi": self.tab_unifi,
            "overview_software": self.tab_software,
        }
        for key, target in mapping.items():
            card = getattr(self, "overview_status", {}).get(key)
            if not card:
                continue
            def go(tab=target):
                self.select_main_tab(tab)
            for part in ("shell", "panel", "dot", "value", "detail"):
                widget = card.get(part)
                if widget is not None:
                    self._make_clickable_recursive(widget, go)

        # Posture ribbon shortcuts: the first three belong in Intune, degraded sites in UniFi.
        for key, label in getattr(self, "posture_labels", {}).items():
            target = self.tab_unifi if key == "unifi_degraded_sites" else self.tab_intune
            def go(tab=target):
                self.select_main_tab(tab)
            self._make_clickable_recursive(label, go)
            try:
                parent = label.master
                while parent is not None and str(parent) != str(self):
                    self._make_clickable_recursive(parent, go)
                    if parent.master is self.security_posture_strip:
                        break
                    parent = parent.master
            except Exception:
                pass

        # The hero itself is a Defender shortcut.
        if hasattr(self, "hero_priority_shell"):
            self._make_clickable_recursive(self.hero_priority_shell, lambda: self.nav_to(self.tab_defender))

    def select_detail_tab(self, main_frame, sub_notebook=None, sub_frame=None):
        self.select_main_tab(main_frame)
        try:
            if sub_notebook is not None and sub_frame is not None:
                self.select_subtab(sub_notebook, sub_frame)
        except Exception:
            pass



    def _safe_select_subtab_by_text(self, notebook, wanted):
        """Select a ttk.Notebook subtab by visible tab text, safely."""
        try:
            wanted_l = str(wanted or "").lower()
            synonyms = {
                "newly observed": ("newly observed", "new", "observed"),
                "detected apps": ("detected apps", "detected", "all software", "software inventory", "all"),
                "notes": ("notes", "connector notes", "notes / help"),
                "incidents & alerts": ("incidents", "alerts", "security alerts"),
                "signal feed": ("signal feed", "signal", "events"),
                "security recommendations": ("security recommendations", "recommendations", "tvm"),
                "vulnerabilities": ("vulnerabilities", "cve"),
                "machines / forensics": ("machines", "forensics"),
                "sites": ("sites", "network sites"),
                "connector": ("connector", "notes"),
            }
            wanted_terms = synonyms.get(wanted_l, (wanted_l,))
            for tab_id in notebook.tabs():
                txt = str(notebook.tab(tab_id, "text") or "").lower()
                if wanted_l and wanted_l in txt:
                    notebook.select(tab_id)
                    try:
                        self._sync_subtab_pills(notebook)
                    except Exception:
                        pass
                    return True
            for tab_id in notebook.tabs():
                txt = str(notebook.tab(tab_id, "text") or "").lower()
                if any(term and term in txt for term in wanted_terms):
                    notebook.select(tab_id)
                    try:
                        self._sync_subtab_pills(notebook)
                    except Exception:
                        pass
                    return True
        except Exception:
            pass
        return False

    def nav_to(self, main_frame, subtab_text=None):
        """Real sidebar navigation: main tab plus matching internal/nested subtab."""
        try:
            self.select_main_tab(main_frame)
            if subtab_text:
                notebooks = []
                for nb_name in (
                    "defender_tabs", "defender_enrich_tabs",
                    "intune_tabs", "unifi_tabs", "software_tabs",
                    "sub_defender_tabs", "sub_intune_tabs", "sub_unifi_tabs", "sub_software_tabs",
                ):
                    nb = getattr(self, nb_name, None)
                    if nb is not None:
                        notebooks.append(nb)
                stack = list(main_frame.winfo_children())
                while stack:
                    w = stack.pop(0)
                    if isinstance(w, ttk.Notebook):
                        notebooks.append(w)
                    try:
                        stack.extend(w.winfo_children())
                    except Exception:
                        pass
                seen = set()
                for nb in notebooks:
                    if str(nb) in seen:
                        continue
                    seen.add(str(nb))
                    if self._safe_select_subtab_by_text(nb, subtab_text):
                        return
        except Exception as e:
            try:
                self.status_var.set(f"Navigation warning: {e}")
            except Exception:
                pass

    def _build_left_nav(self, shell):
        """Left rail inspired by the generated SOC cockpit reference."""
        self.left_nav_shell, self.left_nav = self.rounded_panel(shell, fill="#061827", border="#183A55", radius=16, padding=1)
        self.left_nav_shell.configure(width=214)
        self.left_nav_shell.pack(side="left", fill="y", padx=(0, 14), pady=(0, 0))
        self.left_nav_shell.pack_propagate(False)

        brand = tk.Frame(self.left_nav, bg="#061827")
        brand.pack(fill="x", padx=10, pady=(12, 10))
        self.glow_icon(brand, "🛡", BLUE, size=24, bg="#061827").pack(side="left", padx=(0, 8))
        btxt = tk.Frame(brand, bg="#061827")
        btxt.pack(side="left", fill="x", expand=True)
        tk.Label(btxt, text="SMARTBOX", bg="#061827", fg=TEXT, font=(self.font_display, 15, "bold")).pack(anchor="w")
        tk.Label(btxt, text="SECURITY BY MARC", bg="#061827", fg="#36CFFF", font=(self.font_ui, 8, "bold")).pack(anchor="w")

        def section(label, color=BLUE):
            tk.Label(self.left_nav, text=label.upper(), bg="#061827", fg=color, font=(self.font_ui, 8, "bold")).pack(anchor="w", padx=14, pady=(12, 4))

        section("Overview")
        self.neon_sidebar_item(self.left_nav, "Overview", "⌂", lambda: self.nav_to(self.tab_overview), BLUE, True)

        section("Microsoft Defender")
        self.neon_sidebar_item(self.left_nav, "Defender view", "🛡", lambda: self.nav_to(self.tab_defender, "Incidents & alerts"), BLUE)
        self.neon_sidebar_item(self.left_nav, "Alert focus", "⚡", lambda: self.nav_to(self.tab_defender, "Incidents & alerts"), RED)
        self.neon_sidebar_item(self.left_nav, "Full signal feed", "✦", lambda: self.nav_to(self.tab_defender, "Signal feed"), PURPLE)
        self.neon_sidebar_item(self.left_nav, "Recommendations", "⚙", lambda: self.nav_to(self.tab_defender, "Security recommendations"), ORANGE)
        self.neon_sidebar_item(self.left_nav, "Vulnerabilities", "◆", lambda: self.nav_to(self.tab_defender, "Vulnerabilities"), RED)
        self.neon_sidebar_item(self.left_nav, "Machines / forensics", "⌬", lambda: self.nav_to(self.tab_defender, "Machines / forensics"), BLUE)

        section("Intune", PURPLE)
        self.neon_sidebar_item(self.left_nav, "Device posture", "👤", lambda: self.nav_to(self.tab_intune, "Security posture"), PURPLE)
        self.neon_sidebar_item(self.left_nav, "Non-compliant", "▲", lambda: self.nav_to(self.tab_intune, "Non-compliant"), AMBER)
        self.neon_sidebar_item(self.left_nav, "Stale devices", "🔗", lambda: self.nav_to(self.tab_intune, "Stale"), BLUE)

        section("UniFi", GREEN)
        self.neon_sidebar_item(self.left_nav, "Sites overview", "📡", lambda: self.nav_to(self.tab_unifi, "Sites"), GREEN)
        self.neon_sidebar_item(self.left_nav, "Alerts & events", "⚠", lambda: self.nav_to(self.tab_unifi, "Connector"), ORANGE)

        section("Software", ORANGE)
        self.neon_sidebar_item(self.left_nav, "Detected apps", "💾", lambda: self.nav_to(self.tab_software, "Detected apps"), ORANGE)
        self.neon_sidebar_item(self.left_nav, "Newly observed", "✦", lambda: self.nav_to(self.tab_software, "Newly observed"), AMBER)
        self.neon_sidebar_item(self.left_nav, "Notes", "◆", lambda: self.nav_to(self.tab_software, "Notes"), RED)

        spacer = tk.Frame(self.left_nav, bg="#061827")
        spacer.pack(fill="both", expand=True)
        status = tk.Frame(self.left_nav, bg="#061827")
        status.pack(fill="x", padx=12, pady=12)
        tk.Label(status, text="●", bg="#061827", fg=GREEN, font=(self.font_ui, 14, "bold")).pack(side="left")
        tk.Label(status, text="Connected", bg="#061827", fg="#CFFFE8", font=(self.font_ui, 9, "bold")).pack(side="left", padx=(6, 0))


    def _build_main_tab_pills(self):
        for child in self.main_tab_bar.winfo_children():
            child.destroy()
        tabs = [
            ("Overview", "⌂", self.tab_overview, BLUE),
            ("Defender", "🛡", self.tab_defender, GREEN),
            ("Intune", "👤", self.tab_intune, PURPLE),
            ("UniFi", "📡", self.tab_unifi, BLUE),
            ("Software", "💾", self.tab_software, ORANGE),
        ]
        self.main_tab_buttons = {}
        for label, icon, frame, color in tabs:
            def go(f=frame):
                self.select_main_tab(f)
            shell = self.neon_button(self.main_tab_bar, label, icon, go, color=color, width=130, active=(frame == self.tab_overview))
            shell.pack(side="left", padx=(0, 10), pady=(0, 4))
            self.main_tab_buttons[frame] = {"shell": shell, "label": label, "icon": icon, "color": color}
        self.select_main_tab(self.tab_overview)

    def select_main_tab(self, frame):
        try:
            self.main_tabs.select(frame)
            self.current_main_frame = frame
        except Exception:
            return

        try:
            for child in self.main_tab_bar.winfo_children():
                child.destroy()
            tabs = [
                ("Overview", "⌂", self.tab_overview, BLUE),
                ("Defender", "🛡", self.tab_defender, GREEN),
                ("Intune", "👤", self.tab_intune, PURPLE),
                ("UniFi", "📡", self.tab_unifi, BLUE),
                ("Software", "💾", self.tab_software, ORANGE),
            ]
            self.main_tab_buttons = {}
            for label, icon, tab_frame, color in tabs:
                def go(f=tab_frame):
                    self.select_main_tab(f)
                shell = self.neon_button(self.main_tab_bar, label, icon, go, color=color, width=130, active=(tab_frame == frame))
                shell.pack(side="left", padx=(0, 10), pady=(0, 4))
                self.main_tab_buttons[tab_frame] = {"shell": shell, "label": label, "icon": icon, "color": color}
        except Exception as e:
            try:
                self.status_var.set(f"Tab ribbon error: {e}")
            except Exception:
                pass
        try:
            self._normalize_defender_tables()
            if self.last_payload:
                self._stable_paint_all_tables(self.last_payload)
        except Exception:
            pass

    def _build_subtab_pills(self, bar, notebook, tabs):
        if not hasattr(self, "subtab_buttons"):
            self.subtab_buttons = {}
        for child in bar.winfo_children():
            child.destroy()

        buttons = {}
        for label, frame in tabs:
            width = min(170, max(102, 12 * len(label) + 22))
            shell = tk.Frame(bar, bg=BG, width=width, height=34)
            shell.pack(side="left", padx=(0, 8), pady=(0, 2))
            shell.pack_propagate(False)

            canvas = tk.Canvas(shell, bg=BG, highlightthickness=0, bd=0, width=width, height=34)
            canvas.pack(fill="both", expand=True)
            btn = tk.Label(
                canvas,
                text=label,
                bg="#111925",
                fg="#8EDCFF",
                font=(self.font_ui, 9, "bold"),
                cursor="hand2"
            )
            canvas.create_window((width // 2, 17), window=btn, width=width - 10, height=28)

            def draw(active=False, c=canvas, b=btn, w=width):
                c.delete("panel")
                bg = "#173A56" if active else "#0A1A2A"
                border = "#5FE8FF" if active else "#234965"
                pts = self._rounded_points(2, 2, w - 2, 32, 14)
                c.create_polygon(pts, smooth=True, splinesteps=24, fill=bg, outline=border, width=1.3, tags="panel")
                c.tag_lower("panel")
                b.configure(bg=bg, fg="#F7FBFF" if active else "#8EDCFF")

            for widget in (shell, canvas, btn):
                try:
                    widget.configure(cursor="hand2")
                except Exception:
                    pass
                widget.bind("<Button-1>", lambda e, f=frame, nb=notebook: self.select_subtab(nb, f), add="+")
            buttons[frame] = {"draw": draw}
            draw(active=False)

        self.subtab_buttons[notebook] = buttons
        notebook.bind("<<NotebookTabChanged>>", lambda e, nb=notebook: self._sync_subtab_pills(nb), add="+")
        if tabs:
            self.select_subtab(notebook, tabs[0][1])

    def select_subtab(self, notebook, frame):
        notebook.select(frame)
        self._sync_subtab_pills(notebook)

    def _sync_subtab_pills(self, notebook):
        current = notebook.select()
        for frame, parts in self.subtab_buttons.get(notebook, {}).items():
            try:
                fid = str(frame)
            except Exception:
                fid = ""
            parts["draw"](active=(fid == current))

    def _tree_sort_value(self, raw):
        value = "" if raw is None else str(raw).strip()
        if value == "":
            return (2, "")

        # Numeric sort first.
        try:
            cleaned = value.replace(",", "").replace("%", "")
            return (0, float(cleaned))
        except Exception:
            pass

        # ISO-ish dates and common timestamp strings sort acceptably as text
        # once normalized to lowercase.
        return (1, value.lower())

    def sort_treeview(self, tree, column, reverse=False, remember=True):
        try:
            rows = [(self._tree_sort_value(tree.set(item, column)), item) for item in tree.get_children("")]
            rows.sort(reverse=reverse)
            for index, (_, item) in enumerate(rows):
                tree.move(item, "", index)

            if remember:
                self.table_sort_state[str(tree)] = (column, reverse)

            for col in tree["columns"]:
                heading = tree.heading(col).get("text", col).replace(" ▲", "").replace(" ▼", "")
                if col == column:
                    heading += " ▼" if reverse else " ▲"
                tree.heading(col, text=heading, command=lambda c=col: self._toggle_tree_sort(tree, c))
        except Exception:
            pass

    def _toggle_tree_sort(self, tree, column):
        current_col, current_reverse = self.table_sort_state.get(str(tree), (None, False))
        next_reverse = (not current_reverse) if current_col == column else False
        self.sort_treeview(tree, column, next_reverse, remember=True)

    def _column_anchor(self, key, label):
        raw = f"{key} {label}".lower()
        centered = (
            "severity", "status", "time", "days", "devices", "online", "offline",
            "degraded", "unknown", "version", "source", "os", "compliance",
            "last_sync", "last sync", "publisher"
        )
        numeric = ("count", "total", "active", "returned", "resolved", "critical", "alerts")
        if any(x in raw for x in centered + numeric):
            return "center"
        return "w"

    def setup_tree_columns(self, tree, columns):
        # Keep human labels on the widget so inserts can render status/severity
        # values as compact "bubble" text consistently across every tab.
        try:
            tree._smart_columns = list(columns)
            tree._smart_col_labels = {str(k): str(label) for k, label, _ in columns}
        except Exception:
            pass
        for key, label, width in columns:
            anchor = self._column_anchor(key, label)
            tree.heading(key, text=label, anchor="center", command=lambda c=key, t=tree: self._toggle_tree_sort(t, c))
            tree.column(key, width=width, anchor=anchor, stretch=True)

    def _tree_mousewheel_units(self, event):
        """Return a cross-platform wheel delta for Treeview widgets."""
        try:
            if getattr(event, "num", None) == 4:
                return -3
            if getattr(event, "num", None) == 5:
                return 3
            delta = getattr(event, "delta", 0)
            if delta == 0:
                return 0
            # Windows reports +/-120. macOS can report smaller values, so keep
            # at least one unit of movement for every real wheel event.
            direction = -1 if delta > 0 else 1
            steps = max(1, abs(int(delta / 120)))
            return direction * steps
        except Exception:
            return 0

    def _scroll_treeview(self, tree, event):
        try:
            units = self._tree_mousewheel_units(event)
            if units:
                tree.yview_scroll(units, "units")
            return "break"
        except Exception:
            return "break"

    def _bind_treeview_mousewheel(self, tree):
        """Bind wheel scrolling directly to a table without global bind_all side effects."""
        if tree is None:
            return
        try:
            tree.bind("<MouseWheel>", lambda event, t=tree: self._scroll_treeview(t, event), add="+")
            tree.bind("<Button-4>", lambda event, t=tree: self._scroll_treeview(t, event), add="+")
            tree.bind("<Button-5>", lambda event, t=tree: self._scroll_treeview(t, event), add="+")
        except Exception:
            pass

    def table_panel(self, parent, title, columns, height=9):
        shell, panel = self.rounded_panel(parent, fill=PANEL, border=HAIRLINE, radius=18, padding=1)
        shell.pack(fill="both", expand=True, padx=6, pady=6)
        header = tk.Frame(panel, bg=PANEL)
        header.pack(fill="x", padx=12, pady=(7, 3))
        tk.Label(header, text=title, bg=PANEL, fg=TEXT, font=(self.font_display, 15, "bold")).pack(side="left")
        tk.Label(header, text="signal-coloured rows  •  glass bands  •  click headers to sort", bg=PANEL, fg="#7F94AA", font=(self.font_ui, 8, "bold")).pack(side="right")

        frame = tk.Frame(panel, bg=PANEL)
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height, style="Dasher.Treeview")
        self.setup_tree_columns(tree, columns)
        yscroll = tk.Scrollbar(frame, orient="vertical", command=tree.yview, bg=PANEL, troughcolor=GLASS)
        xscroll = tk.Scrollbar(frame, orient="horizontal", command=tree.xview, bg=PANEL, troughcolor=GLASS)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        # Screenshot-style glass rows. Keep row bands calm; the pill text carries severity/status.
        tree.tag_configure("bad", foreground="#FF7895", background="#241526")
        tree.tag_configure("warn", foreground="#FFE36E", background="#1D2531")
        tree.tag_configure("high", foreground="#FFB66B", background="#221D25")
        tree.tag_configure("good", foreground="#8DFF82", background="#0B2A25")
        tree.tag_configure("info", foreground="#65D1FF", background="#092235")
        tree.tag_configure("alt", foreground="#DCEBFA", background="#0B1F31")
        tree.tag_configure("os_windows", foreground="#65D1FF", background="#09233A")
        tree.tag_configure("os_ios", foreground="#8DFF82", background="#0B2A25")
        tree.tag_configure("os_macos", foreground="#C19BFF", background="#161D34")
        tree.tag_configure("os_android", foreground="#FFE36E", background="#1D2531")
        tree.tag_configure("os_other", foreground="#C9D6E5", background="#0B1F31")
        tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        xscroll.pack(side="bottom", fill="x")
        self._bind_treeview_mousewheel(tree)
        return tree

    def clear_table(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def _bubble_token(self, value, kind="status"):
        raw = str(value if value is not None else "").strip()
        if not raw:
            return ""
        upper = raw.upper()

        aliases = {
            "INFORMATIONAL": "INFO",
            "NONCOMPLIANT": "NONCOMPLIANT",
            "NON-COMPLIANT": "NONCOMPLIANT",
            "INGRACEPERIOD": "GRACE",
            "RESOLVED/CLOS": "RESOLVED/CLOSED",
            "RESOLVED/CLOSED": "RESOLVED/CLOSED",
            "REMediated".upper(): "REMEDIATED",
            "PENDINGAPPROVAL": "PENDING",
        }
        label = aliases.get(upper.replace(" ", ""), aliases.get(upper, upper if len(upper) <= 22 else raw))

        icon = {
            "CRITICAL": "◆",
            "HIGH": "▲",
            "MEDIUM": "●",
            "LOW": "•",
            "INFO": "✦",
            "ACTIVE": "●",
            "NEW": "✦",
            "VISIBLE": "◇",
            "CHECK": "◇",
            "PENDING": "⌁",
            "REMEDIATED": "✓",
            "RESOLVED/CLOSED": "✓",
            "HEALTHY": "✓",
            "CONNECTED": "✓",
            "OK": "✓",
            "CLEAR": "✓",
            "COMPLIANT": "✓",
            "NONCOMPLIANT": "▲",
            "GRACE": "⌁",
            "DEGRADED": "▲",
            "OFFLINE": "◆",
            "ONLINE": "✓",
            "THROTTLED": "⏱",
            "RISK": "▲",
            "LOWRISK": "•",
            "MEDIUMRISK": "●",
            "HIGHRISK": "▲",
        }.get(label, "✦")
        return f"  {icon} {label}  "

    def _should_bubble_column(self, tree, column_key, index, value):
        key = str(column_key).lower()
        label = str(getattr(tree, "_smart_col_labels", {}).get(column_key, "")).lower()
        raw = str(value if value is not None else "").strip().lower()
        bubble_cols = ("severity", "status", "compliance", "os", "finding")
        bubble_values = (
            "info", "low", "medium", "high", "critical", "active", "resolved/closed",
            "resolved", "closed", "noncompliant", "non-compliant", "compliant",
            "healthy", "degraded", "critical", "visible", "unencrypted", "jailbreak/root flag",
            "android", "ios", "macos", "windows", "ok", "check", "throttled"
        )
        return any(x in key or x in label for x in bubble_cols) or raw in bubble_values

    def _bubble_row_values(self, tree, values):
        cols = list(tree["columns"]) if hasattr(tree, "__getitem__") else []
        out = []
        for idx, value in enumerate(values):
            col = cols[idx] if idx < len(cols) else ""
            if self._should_bubble_column(tree, col, idx, value):
                out.append(self._bubble_token(value, "severity" if "severity" in str(col).lower() else "status"))
            else:
                out.append(value)
        return out


    def _unifi_status_tag(self, status):
        raw = str(status or "").strip().upper()
        if raw in ("CRITICAL", "OFFLINE", "DOWN"):
            return "bad"
        if raw in ("DEGRADED", "WARNING", "WARN"):
            return "warn"
        if raw in ("HEALTHY", "GOOD", "ONLINE", "OK"):
            return "good"
        return "info"

    def _decorate_unifi_status(self, status):
        raw = str(status or "VISIBLE").strip().upper()
        if raw == "CRITICAL":
            raw = "OFFLINE"
        icon = {"HEALTHY": "●", "GOOD": "●", "ONLINE": "●", "DEGRADED": "▲", "OFFLINE": "■", "CRITICAL": "■", "VISIBLE": "◆"}.get(raw, "◆")
        return f"  {icon} {raw}  "

    def _decorate_count_cell(self, value, role="neutral"):
        try:
            n = int(value or 0)
        except Exception:
            n = 0
        if role == "online":
            return f"● {n}" if n else str(n)
        if role == "degraded":
            return f"▲ {n}" if n else str(n)
        if role == "offline":
            return f"■ {n}" if n else str(n)
        return str(n)

    def _os_visual_tag(self, os_value):
        raw = str(os_value or "").strip().lower()
        if "windows" in raw:
            return "os_windows"
        if raw in ("ios", "ipados") or "iphone" in raw or "ipad" in raw:
            return "os_ios"
        if "mac" in raw or "darwin" in raw:
            return "os_macos"
        if "android" in raw:
            return "os_android"
        return "os_other"

    def _decorate_os_cell(self, os_value):
        raw = str(os_value or "Other").strip() or "Other"
        low = raw.lower()
        if "windows" in low:
            return "▦  " + raw
        if low in ("ios", "ipados") or "iphone" in low or "ipad" in low:
            return "●  " + raw
        if "mac" in low or "darwin" in low:
            return "◆  " + raw
        if "android" in low:
            return "▲  " + raw
        return "◇  " + raw

    def _intune_row_tag(self, row_type, os_value=None):
        if row_type in ("unencrypted", "jailbreak"):
            return "bad"
        return self._os_visual_tag(os_value)

    def _source_icon_label(self, source):
        raw = str(source or "")
        low = raw.lower()
        if "microsoft 365 defender" in low or "incident" in low:
            return "▣  " + raw
        if "unifi" in low:
            return "▥  " + raw
        if "defender" in low:
            return "🛡  " + raw
        if "intune" in low or "microsoft graph" in low or "graph security" in low:
            return "♟  " + raw
        if "software" in low or "detected" in low:
            return "▤  " + raw
        if "rocket" in low:
            return "◆  " + raw
        if "datto" in low:
            return "◇  " + raw
        return "✦  " + raw
        if "unifi" in low:
            return "📡  " + raw
        if "defender" in low:
            return "🛡  " + raw
        if "intune" in low or "microsoft graph" in low or "graph security" in low:
            return "👤  " + raw
        if "software" in low or "detected" in low:
            return "💾  " + raw
        if "rocket" in low:
            return "◆  " + raw
        if "datto" in low:
            return "◇  " + raw
        return "✦  " + raw

    def _event_visual_tag(self, severity, source, title, detail):
        text = " ".join(str(x).lower() for x in (severity, source, title, detail))
        src = str(source or "").lower()
        title_l = str(title or "").lower()

        # UniFi health rows mention healthy/degraded/critical counts in one sentence.
        # Do not turn every UniFi row red just because the detail contains the word
        # critical; reserve red for true offline/down/failure rows.
        if "unifi" in src:
            if any(x in text for x in ("offline", " down", "failed", "failure")):
                return "bad"
            if "site health calculated" in title_l:
                return "warn" if any(x in text for x in ("degraded", "critical 1", "critical 2", "critical 3", "critical 4", "critical 5")) else "good"
            if any(x in text for x in ("degraded", "warning", "mapping incomplete")):
                return "warn"
            if any(x in text for x in ("api live", "healthy", "connected", "not configured", "returned no active", "calculated")):
                return "good"
            return "info"

        if any(x in text for x in ("offline", "critical", " down", "failed")):
            return "bad"
        if any(x in text for x in ("degraded", "medium", "non-compliant", "noncompliant", "unencrypted", "stale", "throttled", "warning")):
            return "warn"
        if any(x in text for x in ("healthy", "connected", "clear", "ok", "compliant", "live", "loaded")):
            return "good"
        if str(severity).lower() in ("critical",):
            return "bad"
        if str(severity).lower() in ("high",):
            return "high"
        if str(severity).lower() in ("medium",):
            return "warn"
        return "info"

    def _table_tag_from_values(self, values, fallback=None):
        text = " ".join(str(v).lower() for v in values)
        # Respect explicit calculated tags first. This keeps UniFi healthy/degraded/
        # offline rows correctly green/yellow/red instead of being hijacked by
        # detail text like "offline 0".
        if fallback in ("bad", "high", "warn", "good", "info", "sev_critical", "sev_high", "sev_medium", "sev_info", "sev_low"):
            return fallback
        # Colour the data, not the whole dashboard. Tags use dark glass backgrounds
        # with brighter foregrounds so rows read like signal lanes instead of slabs.
        if any(x in text for x in ("offline", "critical", " crit ", "unencrypted", "jailbreak/root")):
            return "bad"
        if any(x in text for x in (" high ", "high / critical")):
            return "high"
        if any(x in text for x in ("medium", " med ", "noncompliant", "non-compliant", "stale", "degraded", "throttled", "no primary")):
            return "warn"
        if any(x in text for x in ("active", "healthy", "compliant", " ok ", "clear", "connected", "loaded")):
            return "good"
        if any(x in text for x in ("info", "graph", "microsoft", "unifi", "intune")):
            return "info"
        return None

    def insert_table_row(self, tree, values, tag=None):
        values = list(values)
        values = self._bubble_row_values(tree, values)
        # UniFi site rows contain words like "offline 0" in the detail column;
        # trust the calculated site status tag instead of letting detail text paint
        # healthy rows red.
        if tree is getattr(self, "unifi_sites_table", None) and tag in ("good", "warn", "bad", "info", "high"):
            row_tag = tag
        elif tree in (getattr(self, "intune_noncompliant_table", None), getattr(self, "intune_stale_table", None)):
            # Make Intune inventory rows visually useful: OS drives the row lane colour.
            row_tag = self._os_visual_tag(values[1] if len(values) > 1 else "")
        elif tree is getattr(self, "intune_posture_table", None):
            row_tag = tag if tag in ("bad", "warn", "good", "info", "high") else self._os_visual_tag(values[2] if len(values) > 2 else "")
        else:
            row_tag = self._table_tag_from_values(values, tag)
        # Add an alternate-row tag when there is no stronger severity tag.
        try:
            idx = len(tree.get_children(""))
            tags = []
            if row_tag:
                tags.append(row_tag)
            elif idx % 2:
                tags.append("alt")
            tree.insert("", "end", values=values, tags=tuple(tags))
        except Exception:
            tree.insert("", "end", values=values, tags=(row_tag,) if row_tag else ())


    def focus_card(self, parent, title, color, bucket, key, width_pack=True):
        shell, f = self.rounded_panel(parent, fill=PANEL, border=HAIRLINE, radius=18, padding=1)
        shell.configure(height=132)
        shell.pack_propagate(False)
        if width_pack:
            shell.pack(side="left", fill="x", expand=True, padx=6, pady=4)
        else:
            shell.pack(fill="x", padx=6, pady=4)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold")).pack(anchor="w", padx=16, pady=(16, 3))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=(self.font_display, 18, "bold"))
        val.pack(anchor="w", padx=16, pady=(8, 2))
        hint = tk.Label(f, text="Awaiting data", bg=PANEL, fg="#8290A7", font=(self.font_ui, 10))
        hint.pack(anchor="w", padx=16, pady=(6, 12))
        self.focus_cards[bucket][key] = {"frame": shell, "value": val, "hint": hint, "base": color}
        return shell

    def text_panel(self, parent, title):
        wrap, panel = self.rounded_panel(parent, fill=PANEL, border=HAIRLINE, radius=18, padding=1)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        top = tk.Frame(panel, bg=PANEL)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text=title, bg=PANEL, fg=TEXT, font=(self.font_display, 14, "bold")).pack(side="left")
        text_frame = tk.Frame(panel, bg=PANEL)
        text_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        widget = tk.Text(
            text_frame,
            bg=GLASS_2,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=(self.font_ui, 10),
            padx=14,
            pady=12
        )
        scroll = tk.Scrollbar(text_frame, orient="vertical", command=widget.yview, bg=PANEL, troughcolor=GLASS)
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


    def _rebuild_defender_page_v2(self):
        """Replace the old stitched Defender page with one clean tab system.

        Tabs:
        - Incidents & alerts
        - Signal feed
        - Security recommendations
        - Vulnerabilities
        - Machines / forensics
        """
        try:
            for child in self.tab_defender.winfo_children():
                child.destroy()
        except Exception:
            pass

        defender_wrap = tk.Frame(self.tab_defender, bg=BG)
        defender_wrap.pack(fill="both", expand=True, padx=6, pady=6)

        title = tk.Frame(defender_wrap, bg=BG)
        title.pack(anchor="w", padx=8, pady=(0, 4))
        self.glow_icon(title, "🛡", ORANGE, size=22, bg=BG).pack(side="left", padx=(0, 10))
        tk.Label(title, text="Defender security view", bg=BG, fg=TEXT, font=(self.font_display, 22, "bold")).pack(side="left")

        tk.Label(
            defender_wrap,
            text="Microsoft 365 Defender incidents, Defender for Endpoint alerts, TVM recommendations, vulnerabilities and machine readiness.",
            bg=BG,
            fg=MUTED,
            font=(self.font_ui, 10),
        ).pack(anchor="w", padx=8, pady=(0, 4))

        cards = tk.Frame(defender_wrap, bg=BG)
        cards.pack(fill="x")
        self.focus_card(cards, "Defender priority", GREEN, "defender", "priority_state")
        self.focus_card(cards, "Active alerts", BLUE, "defender", "defender_alerts")
        self.focus_card(cards, "M365 incidents", ORANGE, "defender", "graph_incidents")
        self.focus_card(cards, "TVM recommendations", PURPLE, "defender", "defender_recommendations")
        self.focus_card(cards, "Vulnerabilities", RED, "defender", "defender_vulnerabilities")
        self.focus_card(cards, "Machines", BLUE, "defender", "defender_machines")

        tab_bar = tk.Frame(defender_wrap, bg=BG)
        tab_bar.pack(fill="x", padx=6, pady=(4, 0))

        self.defender_tables = ttk.Notebook(defender_wrap, style="SubHidden.TNotebook")
        self.defender_tables.pack(fill="both", expand=True, padx=0, pady=6)

        self.defender_alert_tab = tk.Frame(self.defender_tables, bg=BG)
        self.defender_signal_tab = tk.Frame(self.defender_tables, bg=BG)
        self.defender_recommendations_page = tk.Frame(self.defender_tables, bg=BG)
        self.defender_vulnerabilities_page = tk.Frame(self.defender_tables, bg=BG)
        self.defender_machines_page = tk.Frame(self.defender_tables, bg=BG)

        self.defender_tables.add(self.defender_alert_tab, text="Incidents & alerts")
        self.defender_tables.add(self.defender_signal_tab, text="Signal feed")
        self.defender_tables.add(self.defender_recommendations_page, text="Security recommendations")
        self.defender_tables.add(self.defender_vulnerabilities_page, text="Vulnerabilities")
        self.defender_tables.add(self.defender_machines_page, text="Machines / forensics")

        self._build_subtab_pills(tab_bar, self.defender_tables, [
            ("Incidents & alerts", self.defender_alert_tab),
            ("Signal feed", self.defender_signal_tab),
            ("Security recommendations", self.defender_recommendations_page),
            ("Vulnerabilities", self.defender_vulnerabilities_page),
            ("Machines / forensics", self.defender_machines_page),
        ])

        self.defender_alert_table = self.table_panel(self.defender_alert_tab, "Defender / Microsoft security incidents & alerts", [
            ("severity", "Severity", 120),
            ("time", "Time", 170),
            ("title", "Alert / finding", 620),
            ("status", "Status", 150),
            ("detail", "Detail", 880),
        ], height=22)

        self.defender_signal_table = self.table_panel(self.defender_signal_tab, "Microsoft security signal feed", [
            ("time", "Time", 170),
            ("severity", "Severity", 120),
            ("source", "Source", 220),
            ("signal", "Signal", 520),
            ("detail", "Detail", 880),
        ], height=22)

        self.defender_recommendations_table = self.table_panel(self.defender_recommendations_page, "Security recommendations / TVM", [
            ("title", "Recommendation", 500),
            ("severity", "Severity", 130),
            ("category", "Category", 210),
            ("impact", "Impact", 130),
            ("status", "Status", 160),
            ("detail", "Detail", 850),
        ], height=22)

        self.defender_vulnerabilities_table = self.table_panel(self.defender_vulnerabilities_page, "Vulnerabilities", [
            ("id", "CVE / ID", 170),
            ("severity", "Severity", 130),
            ("cvss", "CVSS", 100),
            ("published", "Published", 170),
            ("updated", "Updated", 170),
            ("detail", "Detail", 920),
        ], height=22)

        self.defender_machines_table = self.table_panel(self.defender_machines_page, "Machines / forensic readiness", [
            ("name", "Machine", 340),
            ("risk", "Risk / exposure", 170),
            ("health", "Health", 170),
            ("os", "OS", 200),
            ("last_seen", "Last seen", 190),
            ("ip", "IP", 190),
        ], height=22)

        note = tk.Label(
            self.defender_machines_page,
            text="Forensic collection is an action permission. This dashboard reads readiness/inventory. To collect packages, add an explicit action workflow later.",
            bg=BG,
            fg="#8FB8D4",
            font=(self.font_ui, 9, "bold"),
        )
        note.pack(anchor="w", padx=12, pady=(2, 8))

        self._lock_defender_table_shapes()
        self.after(100, self.hard_repaint_all_tables)


    def _build_focus_tabs(self):
        # Defender tab
        defender_wrap = tk.Frame(self.tab_defender, bg=BG)
        defender_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        defender_title = tk.Frame(defender_wrap, bg=BG)
        defender_title.pack(anchor="w", padx=8, pady=(0, 4))
        self.glow_icon(defender_title, "🛡", ORANGE, size=20, bg=BG).pack(side="left", padx=(0, 8))
        tk.Label(defender_title, text="Defender security view", bg=BG, fg=TEXT, font=(self.font_display, 20, "bold")).pack(side="left")
        tk.Label(defender_wrap, text="A calmer, focused page for Microsoft security alerts and signal quality.", bg=BG, fg=MUTED, font=(self.font_ui, 10)).pack(anchor="w", padx=8, pady=(0, 4))

        row = tk.Frame(defender_wrap, bg=BG)
        row.pack(fill="x")
        self.focus_card(row, "Defender priority", AMBER, "defender", "priority_state")
        self.focus_card(row, "Defender active alerts", BLUE, "defender", "defender_alerts")
        self.focus_card(row, "High / critical Defender", RED, "defender", "defender_critical")
        self.focus_card(row, "Graph security context", PURPLE, "defender", "graph_alerts")
        defender_subtabs = tk.Frame(defender_wrap, bg=BG)
        defender_subtabs.pack(fill="x", padx=6, pady=(4, 0))
        self.defender_tables = ttk.Notebook(defender_wrap, style="SubHidden.TNotebook")
        self.defender_tables.pack(fill="both", expand=True, padx=0, pady=6)

        defender_alert_tab = tk.Frame(self.defender_tables, bg=BG)
        defender_signal_tab = tk.Frame(self.defender_tables, bg=BG)
        self.defender_tables.add(defender_alert_tab, text="Security alerts")
        self.defender_tables.add(defender_signal_tab, text="Signal events")
        self._build_subtab_pills(defender_subtabs, self.defender_tables, [
            ("Security alerts", defender_alert_tab),
            ("Signal events", defender_signal_tab),
        ])

        self.defender_alert_table = self.table_panel(defender_alert_tab, "Defender / Microsoft security incidents & alerts", [
            ("time", "Time", 150),
            ("status", "Status", 115),
            ("severity", "Severity", 90),
            ("source", "Source", 180),
            ("title", "Alert / finding", 360),
            ("detail", "Detail", 420),
        ], height=28)

        self.defender_signal_table = self.table_panel(defender_signal_tab, "Microsoft security signal feed", [
            ("time", "Time", 150),
            ("severity", "Severity", 90),
            ("source", "Source", 180),
            ("title", "Signal", 360),
            ("detail", "Detail", 520),
        ], height=28)


        # Defender enrichment section: recommendations, vulnerabilities and machine readiness.
        defender_enrich = tk.Frame(defender_wrap, bg=BG)
        defender_enrich.pack(fill="both", expand=True, pady=(8, 0))

        enrich_cards = tk.Frame(defender_enrich, bg=BG)
        enrich_cards.pack(fill="x")
        self.focus_card(enrich_cards, "TVM recommendations", ORANGE, "defender", "defender_recommendations")
        self.focus_card(enrich_cards, "Vulnerabilities", RED, "defender", "defender_vulnerabilities")
        self.focus_card(enrich_cards, "Defender machines", BLUE, "defender", "defender_machines")

        self.defender_enrich_bar = tk.Frame(defender_enrich, bg=BG)
        self.defender_enrich_bar.pack(fill="x", pady=(6, 4))
        self.defender_enrich_tabs = ttk.Notebook(defender_enrich, style="SubHidden.TNotebook")
        self.defender_enrich_tabs.pack(fill="both", expand=True)

        self.defender_recommendations_page = tk.Frame(self.defender_enrich_tabs, bg=BG)
        self.defender_vulnerabilities_page = tk.Frame(self.defender_enrich_tabs, bg=BG)
        self.defender_machines_page = tk.Frame(self.defender_enrich_tabs, bg=BG)

        self.defender_enrich_tabs.add(self.defender_recommendations_page, text="Recommendations")
        self.defender_enrich_tabs.add(self.defender_vulnerabilities_page, text="Vulnerabilities")
        self.defender_enrich_tabs.add(self.defender_machines_page, text="Machines / forensics")
        self._build_subtab_pills(self.defender_enrich_bar, self.defender_enrich_tabs, [
            ("Recommendations", self.defender_recommendations_page),
            ("Vulnerabilities", self.defender_vulnerabilities_page),
            ("Machines / forensics", self.defender_machines_page),
        ])

        self.defender_recommendations_table = self.table_panel(self.defender_recommendations_page, "Security recommendations / TVM", [
            ("title", "Recommendation", 420),
            ("severity", "Severity", 120),
            ("category", "Category", 180),
            ("impact", "Impact", 120),
            ("status", "Status", 150),
            ("detail", "Detail", 640),
        ], height=10)

        self.defender_vulnerabilities_table = self.table_panel(self.defender_vulnerabilities_page, "Vulnerabilities", [
            ("id", "CVE / ID", 160),
            ("severity", "Severity", 120),
            ("cvss", "CVSS", 90),
            ("published", "Published", 160),
            ("updated", "Updated", 160),
            ("detail", "Detail", 760),
        ], height=10)

        self.defender_machines_table = self.table_panel(self.defender_machines_page, "Machines / forensic readiness", [
            ("name", "Machine", 300),
            ("risk", "Risk / exposure", 150),
            ("health", "Health", 160),
            ("os", "OS", 180),
            ("last_seen", "Last seen", 180),
            ("ip", "IP", 180),
        ], height=10)

        # Intune tab
        intune_wrap = tk.Frame(self.tab_intune, bg=BG)
        intune_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        intune_title = tk.Frame(intune_wrap, bg=BG)
        intune_title.pack(anchor="w", padx=8, pady=(0, 4))
        self.glow_icon(intune_title, "👤", BLUE, size=20, bg=BG).pack(side="left", padx=(0, 8))
        tk.Label(intune_title, text="Intune estate view", bg=BG, fg=TEXT, font=(self.font_display, 20, "bold")).pack(side="left")
        tk.Label(intune_wrap, text="Device inventory and compliance context, separated cleanly from Defender priority.", bg=BG, fg=MUTED, font=(self.font_ui, 10)).pack(anchor="w", padx=8, pady=(0, 4))

        row = tk.Frame(intune_wrap, bg=BG)
        row.pack(fill="x")
        self.focus_card(row, "Intune devices", GREEN, "intune", "devices")
        self.focus_card(row, "Non-compliant devices", AMBER, "intune", "noncompliant")
        self.focus_card(row, "Stale 30+ days", ORANGE, "intune", "stale_30_count")
        self.focus_card(row, "Unencrypted devices", RED, "intune", "unencrypted_count")

        row2 = tk.Frame(intune_wrap, bg=BG)
        row2.pack(fill="x")
        self.focus_card(row2, "Compliant devices", BLUE, "intune", "compliant_devices")
        self.focus_card(row2, "Compliance rate", PURPLE, "intune", "compliance_percent")
        self.focus_card(row2, "Jailbreak/root flags", RED, "intune", "jailbroken_count")
        self.focus_card(row2, "No primary user", AMBER, "intune", "no_user_count")

        platform = tk.Frame(intune_wrap, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        platform.pack(fill="x", padx=6, pady=6)
        tk.Label(platform, text="Platform breakdown", bg=PANEL, fg=TEXT, font=(self.font_display, 14, "bold")).pack(anchor="w", padx=14, pady=(10, 8))
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
            tk.Label(box, text=label, bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold")).pack(anchor="w")
            val = tk.Label(box, text="--", bg=PANEL, fg=color, font=(self.font_display, 15, "bold"))
            val.pack(anchor="w")
            self.intune_platform_focus[key] = val

        intune_subtabs = tk.Frame(intune_wrap, bg=BG)
        intune_subtabs.pack(fill="x", padx=6, pady=(4, 0))
        self.intune_tables = ttk.Notebook(intune_wrap, style="SubHidden.TNotebook")
        self.intune_tables.pack(fill="both", expand=True, padx=0, pady=6)

        int_tab_non = tk.Frame(self.intune_tables, bg=BG)
        int_tab_stale = tk.Frame(self.intune_tables, bg=BG)
        int_tab_posture = tk.Frame(self.intune_tables, bg=BG)
        int_tab_summary = tk.Frame(self.intune_tables, bg=BG)
        self.intune_tables.add(int_tab_non, text="Non-compliant")
        self.intune_tables.add(int_tab_stale, text="Stale 30+ days")
        self.intune_tables.add(int_tab_posture, text="Security posture")
        self.intune_tables.add(int_tab_summary, text="Summary")
        self._build_subtab_pills(intune_subtabs, self.intune_tables, [
            ("Non-compliant", int_tab_non),
            ("Stale 30+ days", int_tab_stale),
            ("Security posture", int_tab_posture),
            ("Summary", int_tab_summary),
        ])

        self.intune_noncompliant_table = self.table_panel(int_tab_non, "Non-compliant Intune devices", [
            ("name", "Device", 230),
            ("os", "OS", 90),
            ("user", "User", 260),
            ("compliance", "Compliance", 120),
            ("last_sync", "Last sync", 160),
        ], height=28)
        self.intune_stale_table = self.table_panel(int_tab_stale, "Devices not contacted for 30+ days", [
            ("name", "Device", 230),
            ("os", "OS", 90),
            ("days", "Days stale", 90),
            ("user", "User", 260),
            ("last_sync", "Last sync", 160),
        ], height=28)
        self.intune_posture_table = self.table_panel(int_tab_posture, "Device security posture flags", [
            ("type", "Finding", 170),
            ("device", "Device", 230),
            ("os", "OS", 90),
            ("user", "User", 260),
            ("last_sync", "Last sync", 160),
        ], height=28)
        self.intune_text = self.text_panel(int_tab_summary, "Intune inventory summary")

        # UniFi tab
        unifi_wrap = tk.Frame(self.tab_unifi, bg=BG)
        unifi_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        unifi_title = tk.Frame(unifi_wrap, bg=BG)
        unifi_title.pack(anchor="w", padx=8, pady=(0, 4))
        self.glow_icon(unifi_title, "📶", BLUE, size=20, bg=BG).pack(side="left", padx=(0, 8))
        tk.Label(unifi_title, text="UniFi network view", bg=BG, fg=TEXT, font=(self.font_display, 20, "bold")).pack(side="left")
        tk.Label(unifi_wrap, text="All network context on its own page, without affecting Defender headline severity.", bg=BG, fg=MUTED, font=(self.font_ui, 10)).pack(anchor="w", padx=8, pady=(0, 4))

        status_shell = tk.Frame(unifi_wrap, bg=BG)
        status_shell.pack(fill="x")
        left_big = tk.Frame(status_shell, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
        left_big.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        tk.Label(left_big, text="Network site status", bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        self.unifi_tab_status_big = tk.Label(left_big, text="--", bg=PANEL, fg=BLUE, font=(self.font_display, 26, "bold"))
        self.unifi_tab_status_big.pack(anchor="w", padx=16, pady=(0, 2))
        self.unifi_tab_status_hint = tk.Label(left_big, text="Awaiting data", bg=PANEL, fg="#8290A7", font=(self.font_ui, 8))
        self.unifi_tab_status_hint.pack(anchor="w", padx=12, pady=(0, 6))

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

        unifi_subtabs = tk.Frame(unifi_wrap, bg=BG)
        unifi_subtabs.pack(fill="x", padx=6, pady=(4, 0))
        self.unifi_tables = ttk.Notebook(unifi_wrap, style="SubHidden.TNotebook")
        self.unifi_tables.pack(fill="both", expand=True, padx=0, pady=6)

        unifi_sites_tab = tk.Frame(self.unifi_tables, bg=BG)
        unifi_notes_tab = tk.Frame(self.unifi_tables, bg=BG)
        self.unifi_tables.add(unifi_sites_tab, text="Sites")
        self.unifi_tables.add(unifi_notes_tab, text="Connector notes")
        self._build_subtab_pills(unifi_subtabs, self.unifi_tables, [
            ("Sites", unifi_sites_tab),
            ("Connector notes", unifi_notes_tab),
        ])

        self.unifi_sites_table = self.table_panel(unifi_sites_tab, "UniFi network sites", [
            ("site", "Site", 260),
            ("status", "Status", 100),
            ("devices", "Devices", 80),
            ("online", "Online", 80),
            ("offline", "Offline", 80),
            ("degraded", "Degraded", 90),
            ("unknown", "Unknown", 90),
            ("detail", "Detail", 420),
        ], height=28)

        self.unifi_notes_table = self.table_panel(unifi_notes_tab, "UniFi connector notes", [
            ("severity", "Severity", 90),
            ("title", "Finding", 300),
            ("detail", "Detail", 700),
        ], height=28)


        # Software tab
        software_wrap = tk.Frame(self.tab_software, bg=BG)
        software_wrap.pack(fill="both", expand=True, padx=6, pady=6)
        software_title = tk.Frame(software_wrap, bg=BG)
        software_title.pack(anchor="w", padx=8, pady=(0, 4))
        self.glow_icon(software_title, "💾", GREEN, size=20, bg=BG).pack(side="left", padx=(0, 8))
        tk.Label(software_title, text="Software change view", bg=BG, fg=TEXT, font=(self.font_display, 20, "bold")).pack(side="left")
        tk.Label(software_wrap, text="Detected apps from Intune. Newly observed means new to this local dashboard baseline, not guaranteed install time.", bg=BG, fg=MUTED, font=(self.font_ui, 10)).pack(anchor="w", padx=8, pady=(0, 4))

        sw_row = tk.Frame(software_wrap, bg=BG)
        sw_row.pack(fill="x")
        self.focus_card(sw_row, "Detected apps", BLUE, "software", "detected_app_count")
        self.focus_card(sw_row, "Newly observed apps", AMBER, "software", "new_software_count")
        self.focus_card(sw_row, "Inventory source", BLUE, "software", "detected_apps_source")
        self.focus_card(sw_row, "DetectedApps status", ORANGE, "software", "software_issue_state")
        software_subtabs = tk.Frame(software_wrap, bg=BG)
        software_subtabs.pack(fill="x", padx=6, pady=(4, 0))
        self.software_tables = ttk.Notebook(software_wrap, style="SubHidden.TNotebook")
        self.software_tables.pack(fill="both", expand=True, padx=0, pady=6)

        sw_new_tab = tk.Frame(self.software_tables, bg=BG)
        sw_all_tab = tk.Frame(self.software_tables, bg=BG)
        sw_notes_tab = tk.Frame(self.software_tables, bg=BG)
        self.software_tables.add(sw_new_tab, text="Newly observed")
        self.software_tables.add(sw_all_tab, text="Detected apps")
        self.software_tables.add(sw_notes_tab, text="Notes")
        self._build_subtab_pills(software_subtabs, self.software_tables, [
            ("Newly observed", sw_new_tab),
            ("Detected apps", sw_all_tab),
            ("Notes", sw_notes_tab),
        ])

        self.software_new_table = self.table_panel(sw_new_tab, "Newly observed software", [
            ("name", "Application", 320),
            ("version", "Version", 140),
            ("publisher", "Publisher", 240),
            ("devices", "Devices", 90),
        ], height=28)
        self.software_all_table = self.table_panel(sw_all_tab, "Detected software inventory", [
            ("name", "Application", 320),
            ("version", "Version", 140),
            ("publisher", "Publisher", 240),
            ("devices", "Devices", 90),
        ], height=28)
        self.software_text = self.text_panel(sw_notes_tab, "Software detection notes")


    def card(self, parent, row, col, title, key, color):
        shell, f = self.rounded_panel(parent, fill=PANEL, border=HAIRLINE, radius=20, padding=1)
        shell.configure(height=100)
        shell.grid(row=row, column=col, sticky="nsew", padx=7, pady=6)
        shell.grid_propagate(False)
        tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold")).pack(anchor="w", padx=16, pady=(12, 1))
        val = tk.Label(f, text="--", bg=PANEL, fg=color, font=(self.font_display, 22, "bold"))
        val.pack(anchor="w", padx=16, pady=(5, 1))
        hint = tk.Label(f, text="Awaiting data", bg=PANEL, fg="#8C98AD", font=(self.font_ui, 10))
        hint.pack(anchor="w", padx=16, pady=(2, 10))
        self.metric_labels[key] = val
        self.metric_cards[key] = {"frame": shell, "value": val, "hint": hint, "base": color}

    def metric_style(self, key, val):
        raw = str(val)
        num = safe_float(val, 0)
        if key == "priority_state":
            state = raw.upper()
            if state == "CRITICAL":
                return RED, "Defender high/critical active"
            if state == "HIGH":
                return ORANGE, "high Defender volume"
            if state == "ACTION":
                return AMBER, "Defender investigation required"
            return GREEN, "no active Defender alerts"
        if key == "risk":
            return MUTED, "deprecated"
        if key == "alerts":
            if num >= 100:
                return RED, "active security alert volume"
            if num >= 25:
                return ORANGE, "active security alert volume"
            if num > 0:
                return BLUE, "active security context"
            return GREEN, "no active security alerts"
        if key == "noncompliant":
            if num >= 100:
                return ORANGE, "device compliance context"
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
            tk.Label(empty, text="No UniFi site rows returned yet.", bg=PANEL, fg=MUTED, font=(self.font_ui, 8)).pack(anchor="w", padx=6, pady=6)
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
            tk.Label(header, text=title, bg="#1A2230", fg=MUTED, font=(self.font_ui, 8, "bold"), width=width, anchor="w").pack(side="left", padx=3, pady=4)

        status_color = {"HEALTHY": GREEN, "GOOD": GREEN, "ONLINE": GREEN, "DEGRADED": AMBER, "CRITICAL": RED, "OFFLINE": RED, "VISIBLE": BLUE}
        for site in sites[:80]:
            status = str(site.get("status", "VISIBLE")).upper()
            color = status_color.get(status, BLUE)
            row = tk.Frame(self.unifi_site_table, bg=PANEL, highlightthickness=1, highlightbackground=HAIRLINE)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=str(site.get("name", "UniFi site"))[:48], bg=PANEL, fg=TEXT, font=(self.font_ui, 8, "bold"), width=36, anchor="w").pack(side="left", padx=3, pady=4)
            tk.Label(row, text=self._decorate_unifi_status(status), bg=PANEL, fg=color, font=(self.font_ui, 8, "bold"), width=10, anchor="w").pack(side="left", padx=3, pady=4)
            for key, width in [("total", 8), ("online", 8), ("offline", 8), ("degraded", 9), ("unknown", 9)]:
                tk.Label(row, text=str(site.get(key, 0)), bg=PANEL, fg=MUTED if key != "offline" or int(site.get(key, 0) or 0) == 0 else RED, font=(self.font_ui, 8), width=width, anchor="w").pack(side="left", padx=3, pady=4)

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
            tk.Label(header_row, text=title, bg="#1A2230", fg=MUTED, font=(self.font_ui, 8, "bold"), width=width, anchor="w").pack(side="left", padx=4, pady=5)

        sev_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": AMBER, "INFO": BLUE, "LOW": GREEN}
        active_rows = rows[:120]
        if not active_rows:
            empty = tk.Frame(self.alert_table, bg=PANEL)
            empty.pack(fill="x", pady=4)
            tk.Label(empty, text="No live alert rows returned by configured connectors.", bg=PANEL, fg=MUTED, font=(self.font_ui, 10)).pack(anchor="w", padx=8, pady=8)
        for row in active_rows:
            sev = str(row.get("severity", "INFO")).upper()
            color = sev_color.get(sev, BLUE)
            status = str(row.get("status", "ACTIVE"))
            bg = "#121827" if status != "RESOLVED/CLOSED" else "#101522"
            r = tk.Frame(self.alert_table, bg=bg, highlightthickness=1, highlightbackground=HAIRLINE)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=row.get("source", ""), bg=bg, fg=TEXT, font=(self.font_ui, 8, "bold"), width=18, anchor="w").pack(side="left", padx=4, pady=5)
            tk.Label(r, text=sev, bg=bg, fg=color, font=(self.font_ui, 8, "bold"), width=10, anchor="w").pack(side="left", padx=4, pady=5)
            status_fg = GREEN if status == "ACTIVE" else BLUE if status == "NETWORK" else MUTED
            tk.Label(r, text=status, bg=bg, fg=status_fg, font=(self.font_ui, 8, "bold"), width=14, anchor="w").pack(side="left", padx=4, pady=5)
            text_value = row.get("title", "")
            detail = row.get("detail", "")
            if detail:
                text_value = f"{text_value} | {detail}"
            tk.Label(r, text=text_value, bg=bg, fg=TEXT if status == "ACTIVE" else MUTED, font=(self.font_ui, 8), anchor="w", justify="left", wraplength=620).pack(side="left", fill="x", expand=True, padx=4, pady=5)

        self.alert_table.update_idletasks()
        self.alert_table_canvas.configure(scrollregion=self.alert_table_canvas.bbox("all"))


    def _on_feed_configure(self, event=None):
        if getattr(self, "feed_canvas", None):
            self.feed_canvas.configure(scrollregion=self.feed_canvas.bbox("all"))

    def _on_feed_canvas_configure(self, event):
        if hasattr(self, "feed_canvas") and hasattr(self, "feed_window"):
            self.feed_canvas.itemconfigure(self.feed_window, width=event.width)

    def _overview_full_feed_mousewheel(self, event):
        canvas = getattr(self, "overview_full_feed_canvas", None)
        if canvas is None:
            return
        try:
            delta = -1 * int(event.delta / 120) if getattr(event, "delta", 0) else 0
            canvas.yview_scroll(delta, "units")
        except Exception:
            pass

    def _overview_full_feed_mousewheel_linux_up(self, event):
        canvas = getattr(self, "overview_full_feed_canvas", None)
        if canvas is not None:
            try:
                canvas.yview_scroll(-3, "units")
            except Exception:
                pass

    def _overview_full_feed_mousewheel_linux_down(self, event):
        canvas = getattr(self, "overview_full_feed_canvas", None)
        if canvas is not None:
            try:
                canvas.yview_scroll(3, "units")
            except Exception:
                pass

    def _bind_overview_full_feed_mousewheel(self, event=None):
        canvas = getattr(self, "overview_full_feed_canvas", None)
        if canvas is None:
            return
        try:
            canvas.bind_all("<MouseWheel>", self._overview_full_feed_mousewheel)
            canvas.bind_all("<Button-4>", self._overview_full_feed_mousewheel_linux_up)
            canvas.bind_all("<Button-5>", self._overview_full_feed_mousewheel_linux_down)
        except Exception:
            pass

    def _unbind_overview_full_feed_mousewheel(self, event=None):
        canvas = getattr(self, "overview_full_feed_canvas", None)
        if canvas is None:
            return
        try:
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")
        except Exception:
            pass

    def _feed_mousewheel(self, event):
        if getattr(self, "feed_canvas", None):
            delta = -1 * int(event.delta / 120) if event.delta else 0
            self.feed_canvas.yview_scroll(delta, "units")

    def _feed_mousewheel_linux_up(self, event):
        if getattr(self, "feed_canvas", None):
            self.feed_canvas.yview_scroll(-3, "units")

    def _feed_mousewheel_linux_down(self, event):
        if getattr(self, "feed_canvas", None):
            self.feed_canvas.yview_scroll(3, "units")

    def _bind_feed_mousewheel(self, event=None):
        if getattr(self, "feed_canvas", None):
            self.feed_canvas.bind_all("<MouseWheel>", self._feed_mousewheel)
            self.feed_canvas.bind_all("<Button-4>", self._feed_mousewheel_linux_up)
            self.feed_canvas.bind_all("<Button-5>", self._feed_mousewheel_linux_down)

    def _unbind_feed_mousewheel(self, event=None):
        if getattr(self, "feed_canvas", None):
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
                    pass  # network quick stats moved into top overview cards
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
        win.title("Security setup")
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
                tk.Label(frame, text=label, bg=PANEL, fg=MUTED, font=(self.font_ui, 10, "bold")).grid(row=row, column=0, sticky="w", padx=18, pady=(8, 2))
                var = tk.StringVar(value=self.cfg[section].get(key, ""))
                ent = tk.Entry(frame, textvariable=var, show="*" if secret else "", bg="#0F1524", fg=TEXT, insertbackground=TEXT, relief="flat", font=(self.font_ui, 10))
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

        tk.Button(win, text="Save and restart telemetry", command=save, bg="#182435", fg=TEXT, activebackground="#24364B", relief="flat", padx=14, pady=12, font=(self.font_ui, 10, "bold")).pack(pady=(0, 16))

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
        self._stable_paint_all_tables(payload)
        try:
            self._repair_section_cards(payload.get("metrics", {}) or {})
            self._update_overview_action_cards(payload.get("metrics", {}) or {})
        except Exception:
            pass
        self.hard_repaint_all_tables(payload)
        self.after(100, lambda p=payload: self.hard_repaint_all_tables(p))
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

        if hasattr(self, "overview_status"):
            defender_active = int(m.get("defender_alerts", 0) or 0)
            defender_critical = int(m.get("defender_critical", 0) or 0)
            graph_active = int(m.get("graph_alerts", 0) or 0)
            noncompliant = int(m.get("noncompliant", 0) or 0)
            stale = int(m.get("stale_30_count", 0) or 0)
            unencrypted = int(m.get("unencrypted_count", 0) or 0)
            no_user = int(m.get("no_user_count", 0) or 0)
            sites = int(m.get("unifi_sites", 0) or 0)
            offline = int(m.get("unifi_critical_sites", 0) or 0)
            degraded = int(m.get("unifi_degraded_sites", 0) or 0)
            software_new = int(m.get("new_software_count", 0) or 0)
            software_state = str(m.get("software_issue_state", "ok") or "ok")

            status_data = {
                "overview_defender": (
                    "ACT NOW" if defender_critical else "ACTION" if defender_active else "OK",
                    f"{defender_active} active Defender • {defender_critical} high/critical • {graph_active} Graph\nMDO context",
                    RED if defender_critical else ORANGE if defender_active else GREEN,
                ),
                "overview_intune": (
                    "POSTURE RISK" if unencrypted or stale or noncompliant else "OK",
                    f"{noncompliant} non-compliant • {stale} stale 30+\n{unencrypted} unencrypted • {no_user} no primary user",
                    RED if unencrypted else ORANGE if stale or noncompliant else GREEN,
                ),
                "overview_unifi": (
                    "NETWORK ISSUE" if offline else "DEGRADED" if degraded else "OK",
                    f"{sites} sites • {max(0, sites - offline - degraded)} online • {degraded} degraded • {offline} offline\n{m.get('unifi_alerts', 0)} UniFi alert endpoints",
                    RED if offline else AMBER if degraded else GREEN,
                ),
                "overview_software": (
                    "GRAPH THROTTLED" if "429" in software_state or "backoff" in software_state else "WATCHING",
                    f"{m.get('detected_app_count', 0)} detected apps returned this run\n{software_new} newly observed",
                    ORANGE if "429" in software_state or "backoff" in software_state else BLUE,
                ),
            }

            for key, (headline, detail, color) in status_data.items():
                card = self.overview_status.get(key)
                if not card:
                    continue
                card["base"] = color
                card["value"].config(text=headline, fg=color)
                card["detail"].config(text=detail)
                try:
                    card["shell"].canvas.delete("panel")
                    w = max(card["shell"].canvas.winfo_width() - 1, 80)
                    h = max(card["shell"].canvas.winfo_height() - 1, 50)
                    card["shell"].canvas.create_polygon(
                        self._rounded_points(1, 1, w, h, 20),
                        smooth=True,
                        splinesteps=24,
                        fill=PANEL,
                        outline=color,
                        width=1.3,
                        tags="panel"
                    )
                    card["shell"].canvas.tag_lower("panel")
                except Exception:
                    pass

            if hasattr(self, "hero_priority_value"):
                live_sources = [str(s).upper() for s in payload.get("sources", {}).get("live", []) if s]
                connected = bool(live_sources)
                hot_events = []
                for ev in payload.get("events", []) or []:
                    sev = str(ev.get("severity", "")).lower()
                    if sev in ("critical", "high"):
                        hot_events.append(ev)
                hot_events.sort(key=lambda ev: parse_dt_safe(ev.get("timestamp")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc), reverse=True)

                if defender_critical > 0:
                    hero_head = "DEFENDER CRITICAL"
                    hero_detail = f"{defender_critical} high / critical Defender alert(s) active. Immediate triage recommended."
                    hero_color = RED
                elif defender_active > 0:
                    hero_head = "DEFENDER ACTION"
                    hero_detail = f"{defender_active} active Defender alert(s) need triage."
                    hero_color = ORANGE
                else:
                    hero_head = "DEFENDER CLEAR"
                    hero_detail = "No active Defender alerts currently driving priority."
                    hero_color = GREEN

                # Keep posture/network issues visible as context, but never let them steal
                # the Overview headline from Defender.
                context_bits = []
                if graph_active:
                    context_bits.append(f"{graph_active} Graph")
                if noncompliant:
                    context_bits.append(f"{noncompliant} Intune non-compliant")
                if unencrypted:
                    context_bits.append(f"{unencrypted} unencrypted")
                if stale:
                    context_bits.append(f"{stale} stale 30+")
                if no_user:
                    context_bits.append(f"{no_user} no primary user")
                if offline or degraded:
                    context_bits.append(f"UniFi {offline} offline / {degraded} degraded")
                context = " • ".join(context_bits) if context_bits else "Intune and UniFi context clear"
                hero_meta_text = "Medium and informational Defender alerts stay visible in the focus table. " + context

                self.hero_priority_value.config(text=hero_head, fg=hero_color)
                self.hero_priority_detail.config(text=hero_detail, fg=TEXT)
                self.hero_priority_meta.config(text=hero_meta_text, fg="#C6D2E0")
                self.hero_priority_pill.config(text=("CONNECTED" if connected else "CACHE MODE"), fg=(GREEN if connected else AMBER), bg=("#12281E" if connected else "#2A1D11"))
                self.heartbeat_color = GREEN if connected else AMBER
                self.heartbeat_state.config(text=("CONNECTED" if connected else "CACHE MODE"), fg=(GREEN if connected else AMBER))
                self.heartbeat_meta.config(text=f"Polling {' + '.join(live_sources) if live_sources else 'local / cached telemetry'} • heartbeat pulse active", fg=TEXT)
                try:
                    self.hero_priority_shell.canvas.delete("panel")
                    w = max(self.hero_priority_shell.canvas.winfo_width() - 1, 120)
                    h = max(self.hero_priority_shell.canvas.winfo_height() - 1, 70)
                    self.hero_priority_shell.canvas.create_polygon(
                        self._rounded_points(1, 1, w, h, 24),
                        smooth=True, splinesteps=24, fill=PANEL, outline=hero_color, width=1.8, tags="panel"
                    )
                    self.hero_priority_shell.canvas.tag_lower("panel")
                    self.heartbeat_shell.canvas.delete("panel")
                    w2 = max(self.heartbeat_shell.canvas.winfo_width() - 1, 120)
                    h2 = max(self.heartbeat_shell.canvas.winfo_height() - 1, 70)
                    self.heartbeat_shell.canvas.create_polygon(
                        self._rounded_points(1, 1, w2, h2, 24),
                        smooth=True, splinesteps=24, fill=GLASS, outline=(GREEN if connected else AMBER), width=1.6, tags="panel"
                    )
                    self.heartbeat_shell.canvas.tag_lower("panel")
                except Exception:
                    pass
                self.draw_heartbeat()

        if hasattr(self, "posture_labels"):
            for key, label in self.posture_labels.items():
                value = int(m.get(key, 0) or 0)
                label.config(text=str(value))
                if key == "unencrypted_count":
                    label.config(fg=RED if value else GREEN)
                elif key in ("stale_30_count", "no_user_count", "unifi_degraded_sites"):
                    label.config(fg=AMBER if value else GREEN)

        if hasattr(self, "overview_focus_text"):
            defender = int(m.get("defender_alerts", 0) or 0)
            defender_critical = int(m.get("defender_critical", 0) or 0)
            noncompliant = int(m.get("noncompliant", 0) or 0)
            intune_devices = int(m.get("devices", 0) or 0)
            offline_sites = int(m.get("unifi_critical_sites", 0) or 0)
            total_sites = int(m.get("unifi_sites", 0) or 0)
            self.overview_focus_text.config(
                text=f"Defender: {defender} active, {defender_critical} high/critical   •   Intune: {intune_devices} devices, {noncompliant} non-compliant   •   Software: {m.get('new_software_count', 0)} newly observed   •   UniFi: {total_sites} sites, {offline_sites} offline, {m.get('unifi_degraded_sites', 0)} degraded",
                fg=TEXT,
            )

        self.spark.append(m.get("alerts", 0))
        self.spark = self.spark[-80:]
        self.render_alert_table(payload.get("alert_rows", []), m)
        self.render_focus_views(payload)
        self.render_overview_defender_feed(payload)
        self.render_overview_full_feed(payload)
        self.default_sort_tables()

        if getattr(self, "feed", None) is not None and getattr(self, "feed_canvas", None) is not None:
            for child in self.feed.winfo_children():
                child.destroy()

            sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sev_color = {"critical": RED, "high": ORANGE, "medium": AMBER, "info": BLUE, "low": GREEN}
            sev_bg = {"critical": "#24141A", "high": "#23190F", "medium": "#211D13", "info": "#121B28", "low": "#102019"}
            events = sorted(payload["events"][:100], key=lambda e: sev_priority.get(str(e.get("severity", "info")).lower(), 9))
            for event in events:
                sev = str(event.get("severity", "info")).lower()
                color = sev_color.get(sev, BLUE)
                bg = sev_bg.get(sev, PANEL)
                f = tk.Frame(self.feed, bg=bg, highlightthickness=1, highlightbackground="#334055")
                f.pack(fill="x", pady=5)
                top = tk.Frame(f, bg=bg)
                top.pack(fill="x", padx=12, pady=(8, 0))
                tk.Label(top, text=sev.upper(), bg=bg, fg=color, font=(self.font_ui, 8, "bold")).pack(side="left")
                tk.Label(top, text=event.get("source", "source"), bg=bg, fg="#8D9BB5", font=(self.font_ui, 8, "bold")).pack(side="right")
                tk.Label(f, text=event.get("title", "event"), bg=bg, fg=TEXT, font=(self.font_ui, 10, "bold"), wraplength=330, justify="left").pack(anchor="w", padx=12, pady=(4,0))
                tk.Label(f, text=event.get("detail", ""), bg=bg, fg=MUTED, font=(self.font_ui, 8), wraplength=330, justify="left").pack(anchor="w", padx=12, pady=(0, 4))

            self.feed.update_idletasks()
            self.feed_canvas.configure(scrollregion=self.feed_canvas.bbox("all"))

        unifi_footer = f" | UniFi: {m.get('unifi_alerts', 0)}" if int(m.get("unifi_connected", 0) or 0) > 0 else ""
        self.status_var.set(f"Updated {dt.datetime.now().strftime('%H:%M:%S')} | state: {state_text.lower()} | live: {live} | active: {m.get('active_alerts', m.get('alerts', 0))} | returned: {m.get('returned_alerts', 0)} | resolved/closed: {m.get('resolved_alerts', 0)} | Defender critical: {m.get('defender_critical', 0)} | Intune devices: {m.get('devices', 0)} | compliance gap: {m.get('noncompliant', 0)}")

    def make_feed_spark(self, seed, count=16):
        base = max(3, int(seed or 1))
        return [max(1, int(base * 0.45) + (((i * 7) + base) % 13)) for i in range(count)]

    def draw_mini_sparkline(self, canvas, values, color, bg):
        try:
            canvas.delete("all")
            w = max(canvas.winfo_width(), 120)
            h = max(canvas.winfo_height(), 36)
            canvas.create_rectangle(0, 0, w, h, fill=bg, outline="")
            vals = [max(0, int(v or 0)) for v in (values or [1, 2, 3, 2, 4])]
            if len(vals) == 1:
                vals = vals * 2
            vmax = max(vals) or 1
            pts = []
            left, top, right, bottom = 6, 6, w - 6, h - 6
            for i, v in enumerate(vals):
                x = left + (i / max(1, len(vals) - 1)) * (right - left)
                y = bottom - ((v / vmax) * (bottom - top))
                pts.append((x, y))
            flat = [c for p in pts for c in p]
            area = [(pts[0][0], bottom)] + pts + [(pts[-1][0], bottom)]
            canvas.create_polygon(*[c for p in area for c in p], fill=color, outline="", stipple="gray50")
            canvas.create_line(*flat, fill="#132235", width=5, smooth=True, splinesteps=14)
            canvas.create_line(*flat, fill=color, width=1.8, smooth=True, splinesteps=14)
        except Exception:
            pass

    def bubble_severity(self, value):
        sev = str(value or "INFO").upper().strip()
        if sev == "CRITICAL":
            return "  CRIT  "
        if sev == "MEDIUM":
            return "  MED  "
        return f"  {sev}  "

    def bubble_status(self, value):
        status = str(value or "ACTIVE").upper().strip()
        if status == "RESOLVED/CLOSED":
            return "  RESOLVED  "
        return f"  {status}  "

    def render_overview_defender_feed(self, payload):
        tree = getattr(self, "overview_defender_feed_table", None)
        if tree is None:
            return
        try:
            tree.delete(*tree.get_children())
        except Exception:
            return

        rows = []
        for row in payload.get("alert_rows", []) or []:
            source = str(row.get("source", ""))
            title = str(row.get("title", ""))
            detail = str(row.get("detail", ""))
            if self._is_defender_related_row(source, title, detail):
                rows.append(row)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
        def row_key(row):
            sev = sev_order.get(str(row.get("severity", "INFO")).upper(), 9)
            parsed = parse_dt_safe(row.get("timestamp"))
            stamp = parsed.timestamp() if parsed else 0
            return (sev, -stamp)
        rows.sort(key=row_key)

        active_count = len(rows)
        medium_count = sum(1 for r in rows if str(r.get("severity", "")).upper() == "MEDIUM")
        high_count = sum(1 for r in rows if str(r.get("severity", "")).upper() in ("HIGH", "CRITICAL"))
        if hasattr(self, "overview_defender_feed_summary"):
            self.overview_defender_feed_summary.config(text=f"{active_count} Defender/M365 item(s) · {high_count} high/critical · {medium_count} medium · click headers to sort")

        for row in rows[:150]:
            sev = str(row.get("severity", "INFO")).upper()
            tag = self._event_visual_tag(sev, row.get("source", "Defender"), row.get("title", ""), row.get("detail", ""))
            title = str(row.get("title", ""))
            detail = str(row.get("detail", ""))
            if len(title) > 118:
                title = title[:115] + "..."
            if len(detail) > 170:
                detail = detail[:167] + "..."
            tree.insert(
                "",
                "end",
                values=(
                    self._bubble_token(sev, "severity"),
                    short_ts(row.get("timestamp", "")),
                    title,
                    self._bubble_token(row.get("status", "ACTIVE"), "status"),
                    detail,
                ),
                tags=(tag,),
            )

        if not rows:
            tree.insert(
                "",
                "end",
                values=(
                    self._bubble_token("INFO", "severity"),
                    "",
                    "No Defender or Microsoft 365 Defender rows returned yet.",
                    self._bubble_token("INFO", "status"),
                    "Check Graph incidents permissions and Defender API connector health.",
                ),
                tags=("sev_info",),
            )

    def render_overview_full_feed(self, payload):
        tree = getattr(self, "overview_full_feed_table", None)
        if tree is None:
            return
        try:
            tree.delete(*tree.get_children())
        except Exception:
            return

        events = list(payload.get("events", []) or [])[:400]
        sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3, "low": 4}

        def event_key(event):
            sev = sev_order.get(str(event.get("severity", "info")).lower(), 9)
            parsed = parse_dt_safe(event.get("timestamp"))
            stamp = parsed.timestamp() if parsed else 0
            return (sev, -stamp)

        events.sort(key=event_key)

        for event in events:
            sev = str(event.get("severity", "info")).lower()
            src = str(event.get("source", "source"))
            when = short_ts(event.get("timestamp", ""))
            title = str(event.get("title", "event"))
            detail = str(event.get("detail", ""))

            if len(title) > 108:
                title = title[:105] + "..."
            if len(detail) > 168:
                detail = detail[:165] + "..."

            tag = self._event_visual_tag(sev, src, title, detail)
            tree.insert("", "end", values=(self._bubble_token(sev, "severity"), self._source_icon_label(src), when, title, detail), tags=(tag,))

        if not events:
            tree.insert("", "end", values=(self._bubble_token("INFO", "severity"), "System", "", "Waiting for live signal feed data.", "No events returned yet."), tags=("sev_info",))

    def draw_trend(self, key, values, color):
        if key not in self.trend_canvases:
            return
        canvas, _ = self.trend_canvases[key]
        canvas.delete("all")
        w = max(canvas.winfo_width(), 320)
        h = max(canvas.winfo_height(), 72)
        canvas.create_rectangle(0, 0, w, h, fill=GLASS, outline="")

        left, top, right, bottom = 10, 8, w - 10, h - 8
        for i in range(4):
            y = top + ((bottom - top) * i / 3)
            canvas.create_line(left, y, right, y, fill="#10243A")
        for i in range(10):
            x = left + ((right - left) * i / 9)
            canvas.create_line(x, top, x, bottom, fill="#0A1523")

        vals = [max(0, int(v or 0)) for v in (values[-32:] if values else [])]
        if not vals:
            canvas.create_text(left + 8, bottom - 6, text="Awaiting signal history", anchor="sw", fill=MUTED, font=(self.font_ui, 8, "bold"))
            return
        if len(vals) == 1:
            vals = vals * 2

        vmax = max(max(vals), 1)
        floor = max(1, int(vmax * 0.72))
        pts = []
        for i, v in enumerate(vals):
            scaled = 0.18 + 0.82 * ((v - min(0, min(vals))) / max(vmax, 1))
            x = left + (i / max(1, len(vals) - 1)) * (right - left)
            y = bottom - (scaled * (bottom - top - 8))
            pts.append((x, y))

        for x, y in pts[::2]:
            canvas.create_line(x, bottom, x, y, fill="#10233A")

        area = [(pts[0][0], bottom)] + pts + [(pts[-1][0], bottom)]
        flat_area = [coord for p in area for coord in p]
        flat = [coord for p in pts for coord in p]
        canvas.create_polygon(flat_area, fill=color, outline="", stipple="gray50")
        canvas.create_line(*flat, fill="#03101A", width=11, smooth=True, splinesteps=24)
        canvas.create_line(*flat, fill=color, width=4, smooth=True, splinesteps=24)
        canvas.create_line(*flat, fill="#F8FEFF", width=1, smooth=True, splinesteps=24)

        pulse_x, pulse_y = pts[-1]
        canvas.create_oval(pulse_x - 6, pulse_y - 6, pulse_x + 6, pulse_y + 6, outline=color, width=2)
        canvas.create_oval(pulse_x - 2.5, pulse_y - 2.5, pulse_x + 2.5, pulse_y + 2.5, fill="#FFFFFF", outline=color)

        last = vals[-1]
        prev = vals[-2] if len(vals) > 1 else vals[-1]
        delta = last - prev
        canvas.create_text(left + 2, top + 1, text=f"Live {last}", anchor="nw", fill=color, font=(self.font_ui, 8, "bold"))
        canvas.create_text(right - 2, top + 1, text=f"Peak {vmax} · Δ {delta:+d}", anchor="ne", fill="#BBD1E5", font=(self.font_ui, 8))

    def draw_security_signals(self, values):
        canvas = self.security_signals_canvas
        if not canvas:
            return
        canvas.delete("all")
        w = max(canvas.winfo_width(), 320)
        h = max(canvas.winfo_height(), 72)
        canvas.create_rectangle(0, 0, w, h, fill=GLASS, outline="")

        parts = [
            ("Def", int(values.get("defender", 0) or 0), ORANGE),
            ("Graph", int(values.get("graph", 0) or 0), BLUE),
            ("Intune", int(values.get("intune", 0) or 0), AMBER),
            ("UniFi", int(values.get("unifi", 0) or 0), RED),
        ]
        total = max(sum(v for _, v, _ in parts), 1)

        left, top, right = 12, 12, w - 12
        bar_h = 14
        canvas.create_rectangle(left, top, right, top + bar_h, fill="#08101A", outline="#19334F", width=1)
        x = left + 1
        usable = (right - left - 2)
        for label, val, color in parts:
            seg = max(0, int((val / total) * usable)) if val else 0
            if seg > 0:
                canvas.create_rectangle(x, top + 1, min(right - 1, x + seg), top + bar_h - 1, fill=color, outline="")
                canvas.create_line(x, top + 1, min(right - 1, x + seg), top + 1, fill="#FFFFFF")
                x += seg

        total_live = sum(v for _, v, _ in parts)
        canvas.create_text(left, top + 22, text=f"Live security signals {total_live}", anchor="nw", fill=TEXT, font=(self.font_ui, 8, "bold"))
        ly = top + 47
        positions = [left, left + 130, left + 260, left + 400]
        for (label, val, color), cx in zip(parts, positions):
            canvas.create_oval(cx, ly - 4, cx + 8, ly + 4, fill=color, outline="#EAFBFF")
            canvas.create_text(cx + 12, ly, text=f"{label} {val}", fill=TEXT if val else MUTED, anchor="w", font=(self.font_ui, 8, "bold"))

    def draw_heartbeat(self):
        canvas = getattr(self, "heartbeat_canvas", None)
        if canvas is None:
            return
        canvas.delete("all")
        w = max(canvas.winfo_width(), 280)
        h = max(canvas.winfo_height(), 64)
        canvas.create_rectangle(0, 0, w, h, fill=GLASS, outline="")

        phase = int(getattr(self, "heartbeat_phase", 0))
        self.heartbeat_phase = phase + 1
        color = getattr(self, "heartbeat_color", GREEN)
        mid = int(h * 0.58)

        for y in (12, mid, h - 12):
            canvas.create_line(10, y, w - 10, y, fill="#182435")
        for x in range(10, w, 28):
            canvas.create_line(x, 10, x, h - 10, fill="#101827")

        offset = (phase * 10) % 56
        pts = []
        x = -offset
        while x < w + 56:
            pts.extend([
                (x, mid),
                (x + 10, mid),
                (x + 14, mid - 2),
                (x + 18, mid),
                (x + 24, mid),
                (x + 28, mid + 4),
                (x + 32, mid - 26),
                (x + 36, mid + 18),
                (x + 42, mid),
                (x + 56, mid),
            ])
            x += 56

        flat = [coord for p in pts for coord in p]
        canvas.create_line(*flat, fill="#13301E", width=7, smooth=True, splinesteps=18)
        canvas.create_line(*flat, fill=color, width=2.4, smooth=True, splinesteps=18)

        scan_x = 16 + ((phase * 16) % max(40, w - 32))
        canvas.create_line(scan_x, 8, scan_x, h - 8, fill="#3DA6FF", dash=(3, 3))
        canvas.create_text(w - 8, 8, text="LIVE PULSE", anchor="ne", fill=color, font=(self.font_ui, 8, "bold"))

    def sync_neon_tiles(self, metrics):
        try:
            if not hasattr(self, "neon_tiles"):
                return
            vals = {
                "priority_state": metrics.get("priority_state", "CLEAR"),
                "defender_alerts": metrics.get("defender_alerts", 0),
                "graph_incidents": metrics.get("graph_incidents", 0),
                "critical": metrics.get("critical", 0),
                "devices": metrics.get("devices", 0),
                "new_software_count": metrics.get("new_software_count", 0),
                "unifi_sites": metrics.get("unifi_sites", 0),
                "stale_30_count": metrics.get("stale_30_count", 0),
                "unencrypted_count": metrics.get("unencrypted_count", 0),
                "no_user_count": metrics.get("no_user_count", 0),
                "unifi_degraded_sites": metrics.get("unifi_degraded_sites", 0),
            }
            for key, val in vals.items():
                tile = self.neon_tiles.get(key)
                if tile:
                    tile["value"].configure(text=str(val))
        except Exception:
            pass



    def _safe_tree_clear(self, tree):
        try:
            for item in tree.get_children():
                tree.delete(item)
        except Exception:
            pass

    def _safe_insert_tree(self, tree, values, tag="info"):
        try:
            cols = list(tree["columns"])
            vals = list(values)
            if len(vals) < len(cols):
                vals += [""] * (len(cols) - len(vals))
            elif len(vals) > len(cols):
                vals = vals[:len(cols)]
            tree.insert("", "end", values=vals, tags=(tag,))
        except Exception:
            pass


    def recommendation_row(self, r):
        return {
            "title": r.get("recommendationName") or r.get("title") or r.get("name") or "Security recommendation",
            "severity": r.get("severity") or r.get("exposureImpact") or r.get("riskScore") or "",
            "status": r.get("status") or r.get("implementationStatus") or "",
            "category": r.get("category") or r.get("productName") or "",
            "impact": r.get("impact") or r.get("exposedMachinesCount") or r.get("exposedMachineCount") or "",
            "detail": r.get("description") or r.get("remediationType") or r.get("remediation") or "",
        }

    def vulnerability_row(self, v):
        return {
            "id": v.get("id") or v.get("cveId") or v.get("name") or "vulnerability",
            "severity": v.get("severity") or v.get("cvssV3") or v.get("cvssScore") or "",
            "cvss": v.get("cvssV3") or v.get("cvssScore") or "",
            "published": v.get("publishedOn") or v.get("publishedDate") or "",
            "updated": v.get("updatedOn") or v.get("lastModified") or "",
            "detail": v.get("description") or v.get("name") or "",
        }

    def machine_row(self, m):
        return {
            "name": m.get("computerDnsName") or m.get("machineName") or m.get("deviceName") or m.get("id") or "machine",
            "risk": m.get("riskScore") or m.get("exposureLevel") or "",
            "health": m.get("healthStatus") or m.get("onboardingStatus") or "",
            "os": m.get("osPlatform") or m.get("osProcessor") or "",
            "last_seen": m.get("lastSeen") or "",
            "ip": m.get("lastIpAddress") or "",
        }


    def _is_defender_related_row(self, source, title="", detail=""):
        raw = " ".join([str(source or ""), str(title or ""), str(detail or "")]).lower()
        return any(x in raw for x in (
            "defender", "microsoft 365", "graph incidents", "security incidents",
            "mdo", "office 365", "email messages", "malicious url", "phish",
            "credential phish", "safe links", "exchange", "mailbox"
        ))

    def _stable_event_tag(self, severity, source="", title="", detail=""):
        raw = " ".join([str(severity or ""), str(source or ""), str(title or ""), str(detail or "")]).lower()
        if any(x in raw for x in ("critical", "high", "offline", "malicious", "credential phish", "exploit", "ransom", "failed")):
            return "bad"
        if any(x in raw for x in ("medium", "warning", "noncompliant", "non-compliant", "stale", "unencrypted", "degraded", "throttled", "missing", "permission")):
            return "warn"
        if any(x in raw for x in ("healthy", "connected", "compliant", "resolved", "remediated", "loaded", "live", "online", "clear")):
            return "good"
        if any(x in raw for x in ("new", "observed", "pending", "check")):
            return "high"
        return "info"

    def _stable_source_label(self, source):
        raw = str(source or "")
        low = raw.lower()
        if "microsoft 365" in low or "graph incidents" in low or "incident" in low:
            return "▣  " + raw
        if "defender" in low:
            return "🛡  " + raw
        if "unifi" in low:
            return "📡  " + raw
        if "intune" in low:
            return "👤  " + raw
        if "graph" in low:
            return "♟  " + raw
        if "recommend" in low or "tvm" in low:
            return "⚙  " + raw
        if "vulnerab" in low or "cve" in low:
            return "◆  " + raw
        if "machine" in low:
            return "⌬  " + raw
        if "software" in low or "detected" in low:
            return "▤  " + raw
        return "✦  " + raw
        if "defender" in low:
            return "🛡  " + raw
        if "unifi" in low:
            return "📡  " + raw
        if "graph" in low or "intune" in low:
            return "♟  " + raw
        if "software" in low:
            return "▤  " + raw
        return "✦  " + raw

    def _stable_status(self, row):
        raw = " ".join([str(row.get("status", "")), str(row.get("title", "")), str(row.get("detail", ""))]).lower()
        if "pending approval" in raw or "pending action" in raw:
            return "PENDING"
        if "remediated" in raw:
            return "REMEDIATED"
        if any(x in raw for x in ("resolved", "closed", "dismissed", "cleared", "archived")):
            return "RESOLVED/CLOSED"
        if row.get("status"):
            return str(row.get("status", "ACTIVE")).upper()
        return "ACTIVE"







    def _force_table_shape(self, tree, columns):
        """Force a Treeview to keep the desired columns after repoll/subtab changes."""
        try:
            current = tuple(tree["columns"])
            wanted = tuple(c[0] for c in columns)
            if current != wanted:
                tree.configure(columns=wanted)
            self.setup_tree_columns(tree, columns)
        except Exception:
            pass

    def _lock_defender_table_shapes(self):
        """Prevent Defender pages from reverting to older/basic table layouts."""
        try:
            for name in ("overview_defender_feed_table", "defender_alert_table"):
                tree = getattr(self, name, None)
                if tree is not None:
                    self._force_table_shape(tree, [
                        ("severity", "Severity", 120),
                        ("time", "Time", 170),
                        ("title", "Alert / finding", 620),
                        ("status", "Status", 150),
                        ("detail", "Detail", 880),
                    ])

            tree = getattr(self, "defender_signal_table", None)
            if tree is not None:
                self._force_table_shape(tree, [
                    ("time", "Time", 170),
                    ("severity", "Severity", 120),
                    ("source", "Source", 220),
                    ("signal", "Signal", 520),
                    ("detail", "Detail", 880),
                ])
        except Exception:
            pass


    def _defender_row_status(self, row):
        raw = " ".join([str(row.get("status", "")), str(row.get("title", "")), str(row.get("detail", ""))]).lower()
        if "pending approval" in raw or "pending action" in raw:
            return "PENDING"
        if "remediated" in raw:
            return "REMEDIATED"
        if any(x in raw for x in ("resolved", "closed", "dismissed", "cleared", "archived")):
            return "RESOLVED/CLOSED"
        return str(row.get("status") or "ACTIVE").upper()

    def _direct_insert_defender_row(self, tree, row):
        sev = str(row.get("severity", "INFO")).upper()
        status = self._defender_row_status(row)
        tag = self._stable_event_tag(sev, row.get("source",""), row.get("title",""), row.get("detail",""))
        source = self._stable_source_label(row.get("source",""))
        title = str(row.get("title", ""))[:180]
        detail = str(row.get("detail", ""))[:300]
        time_v = short_ts(row.get("timestamp", ""))

        try:
            cols = list(tree["columns"])
        except Exception:
            cols = []

        values_by_col = {
            "severity": self._bubble_token(sev, "severity"),
            "time": time_v,
            "title": title,
            "signal": title,
            "status": self._bubble_token(status, "status"),
            "detail": detail,
            "source": source,
            "type": "Incident" if "incident" in str(row.get("source","")).lower() or "incident" in title.lower() else "Alert",
        }
        values = [values_by_col.get(str(c), "") for c in cols]
        try:
            tree.insert("", "end", values=values, tags=(tag,))
        except Exception:
            self._safe_insert_tree(tree, values, tag)

    def _normalize_defender_tables(self):
        """Make Overview and Defender tab use the same clean incident table."""
        try:
            for tree_name in ("defender_alert_table", "overview_defender_feed_table"):
                tree = getattr(self, tree_name, None)
                if tree is None:
                    continue
                tree.configure(columns=("severity", "time", "title", "status", "detail"))
                self.setup_tree_columns(tree, [
                    ("severity", "Severity", 120),
                    ("time", "Time", 170),
                    ("title", "Alert / finding", 620),
                    ("status", "Status", 150),
                    ("detail", "Detail", 880),
                ])
                try:
                    tree._smart_col_labels = {
                        "severity": "Severity",
                        "time": "Time",
                        "title": "Alert / finding",
                        "status": "Status",
                        "detail": "Detail",
                    }
                except Exception:
                    pass
        except Exception:
            pass


    def _defender_m365_rows(self, payload):
        """One source of truth for Overview Defender table and Defender tab."""
        rows = payload.get("alert_rows", []) or []
        out = []
        for r in rows:
            title_l = str(r.get("title", "")).lower()
            detail_l = str(r.get("detail", "")).lower()
            source_l = str(r.get("source", "")).lower()
            joined = " ".join([source_l, title_l, detail_l])

            # Exclude non-security inventory/status rows from the Defender table.
            if any(x in joined for x in (
                "full intune inventory loaded",
                "intune device posture summary",
                "detected apps inventory",
                "software inventory",
                "unifi",
                "site manager",
                "client and traffic",
            )):
                continue

            # Include all Microsoft security/incident/alert context.
            include = (
                self._is_defender_related_row(source_l, title_l, detail_l)
                or "graph security" in source_l
                or "security alert" in title_l
                or "security incidents" in title_l
                or "incidents live" in title_l
                or "alerts live" in title_l
                or "email messages" in title_l
                or "malicious" in joined
                or "phish" in joined
                or "microsoft defender" in joined
                or "microsoft 365 defender" in joined
            )
            if include:
                out.append(r)

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4}
        def key(r):
            sev = sev_rank.get(str(r.get("severity", "INFO")).upper(), 9)
            parsed = parse_dt_safe(r.get("timestamp", ""))
            stamp = parsed.timestamp() if parsed else 0
            return (sev, -stamp, str(r.get("title", "")))
        out.sort(key=key)
        return out

    def _paint_defender_table_like_reference(self, tree, rows, include_source=True):
        if tree is None:
            return
        self._lock_defender_table_shapes()
        self._safe_tree_clear(tree)

        for r in rows[:300]:
            self._direct_insert_defender_row(tree, r)

        if not rows:
            try:
                cols = list(tree["columns"])
            except Exception:
                cols = []
            empty_map = {
                "severity": self._bubble_token("INFO", "severity"),
                "time": "",
                "title": "No Defender/M365 rows returned",
                "status": self._bubble_token("INFO", "status"),
                "detail": "Check Graph throttling/backoff, SecurityIncident.Read.All, SecurityAlert.Read.All and Defender API permissions.",
                "source": "Microsoft 365 Defender",
                "type": "Info",
                "signal": "No Defender/M365 rows returned",
            }
            self._safe_insert_tree(tree, [empty_map.get(str(c), "") for c in cols], "info")

    def _stable_paint_all_tables(self, payload):
        """Last-mile table renderer.

        This intentionally does not depend on older tab-specific render functions.
        It repopulates visible Treeviews after telemetry arrives, so Overview,
        Defender, Intune, UniFi and Software cannot silently go blank after style edits.
        """
        try:
            metrics = payload.get("metrics", {}) or {}
            self._lock_defender_table_shapes()
            self._update_card_icon_severity_glow(metrics)
            rows = payload.get("alert_rows", []) or []
            events = payload.get("events", []) or []

            # Overview Defender/M365 table
            defender_rows = self._defender_m365_rows(payload)
            ov = getattr(self, "overview_defender_feed_table", None)
            self._paint_defender_table_like_reference(ov, defender_rows)
            if hasattr(self, "overview_defender_feed_summary"):
                high = sum(1 for r in defender_rows if str(r.get("severity","")).upper() in ("HIGH", "CRITICAL"))
                med = sum(1 for r in defender_rows if str(r.get("severity","")).upper() == "MEDIUM")
                self.overview_defender_feed_summary.config(text=f"{len(defender_rows)} Defender/M365 item(s) · {high} high/critical · {med} medium · click headers to sort")

            # Overview full signal table
            full = getattr(self, "overview_full_feed_table", None)
            if full is not None:
                self._safe_tree_clear(full)
                for r in rows[:180]:
                    sev = str(r.get("severity", "INFO")).upper()
                    tag = self._stable_event_tag(sev, r.get("source",""), r.get("title",""), r.get("detail",""))
                    self._safe_insert_tree(full, [
                        self._bubble_token(sev, "severity"),
                        self._stable_source_label(r.get("source","")),
                        short_ts(r.get("timestamp", "")),
                        str(r.get("title", ""))[:140],
                        str(r.get("detail", ""))[:220],
                    ], tag)

            # Defender tab alert table
            defender_rows = self._defender_m365_rows(payload)
            dtab = getattr(self, "defender_alert_table", None)
            self._paint_defender_table_like_reference(dtab, defender_rows, include_source=True)

            # Defender signal table if present
            dsig = getattr(self, "defender_signal_table", None)
            if dsig is not None:
                self._safe_tree_clear(dsig)
                for r in rows[:250]:
                    sev = str(r.get("severity", "INFO")).upper()
                    tag = self._stable_event_tag(sev, r.get("source",""), r.get("title",""), r.get("detail",""))
                    self._safe_insert_tree(dsig, [
                        short_ts(r.get("timestamp", "")),
                        self._bubble_token(sev, "severity"),
                        self._stable_source_label(r.get("source","")),
                        str(r.get("title", ""))[:180],
                        str(r.get("detail", ""))[:300],
                    ], tag)


            # Defender enrichment tables
            rec_tree = getattr(self, "defender_recommendations_table", None)
            if rec_tree is not None:
                self._safe_tree_clear(rec_tree)
                recs = metrics.get("defender_recommendation_rows", []) or []
                for r in recs[:500]:
                    sev = str(r.get("severity", "INFO")).upper()
                    tag = self._stable_event_tag(sev, "Defender Recommendations", r.get("title",""), r.get("detail",""))
                    self._safe_insert_tree(rec_tree, [
                        r.get("title",""),
                        self._bubble_token(sev or "INFO", "severity"),
                        r.get("category",""),
                        r.get("impact",""),
                        self._bubble_token(r.get("status","CHECK") or "CHECK", "status"),
                        r.get("detail",""),
                    ], tag)
                if not recs and metrics.get("defender_recommendation_error"):
                    self._safe_insert_tree(rec_tree, [
                        "Recommendations unavailable",
                        self._bubble_token("INFO", "severity"),
                        "Permission/API",
                        "",
                        self._bubble_token("CHECK", "status"),
                        ("Missing application role SecurityRecommendation.Read.All in WindowsDefenderATP, or Defender TVM not available. " + metrics.get("defender_recommendation_error", ""))[:300],
                    ], "info")

            vuln_tree = getattr(self, "defender_vulnerabilities_table", None)
            if vuln_tree is not None:
                self._safe_tree_clear(vuln_tree)
                vulns = metrics.get("defender_vulnerability_rows", []) or []
                for v in vulns[:500]:
                    sev = str(v.get("severity", "INFO")).upper()
                    tag = self._stable_event_tag(sev, "Defender Vulnerabilities", v.get("id",""), v.get("detail",""))
                    self._safe_insert_tree(vuln_tree, [
                        v.get("id",""),
                        self._bubble_token(sev or "INFO", "severity"),
                        v.get("cvss",""),
                        short_ts(v.get("published","")),
                        short_ts(v.get("updated","")),
                        v.get("detail",""),
                    ], tag)
                if not vulns and metrics.get("defender_vulnerability_error"):
                    self._safe_insert_tree(vuln_tree, [
                        "Vulnerabilities unavailable",
                        self._bubble_token("INFO", "severity"),
                        "",
                        "",
                        "",
                        ("Missing application role Vulnerability.Read.All in WindowsDefenderATP, or Defender TVM not available. " + metrics.get("defender_vulnerability_error", ""))[:300],
                    ], "info")

            machine_tree = getattr(self, "defender_machines_table", None)
            if machine_tree is not None:
                self._safe_tree_clear(machine_tree)
                machines = metrics.get("defender_machine_rows", []) or []
                for mrow in machines[:500]:
                    tag = self._stable_event_tag(mrow.get("risk","INFO"), "Defender Machines", mrow.get("name",""), mrow.get("health",""))
                    self._safe_insert_tree(machine_tree, [
                        mrow.get("name",""),
                        self._bubble_token(mrow.get("risk","INFO") or "INFO", "status"),
                        self._bubble_token(mrow.get("health","CHECK") or "CHECK", "status"),
                        mrow.get("os",""),
                        short_ts(mrow.get("last_seen","")),
                        mrow.get("ip",""),
                    ], tag)
                if not machines and metrics.get("defender_machine_error"):
                    self._safe_insert_tree(machine_tree, [
                        "Machines unavailable",
                        self._bubble_token("INFO", "status"),
                        self._bubble_token("CHECK", "status"),
                        "",
                        "",
                        ("Missing application role Machine.Read.All in WindowsDefenderATP, or machines API unavailable. " + metrics.get("defender_machine_error", ""))[:300],
                    ], "info")


            # Intune tables
            for attr, data_key, row_type in (
                ("intune_noncompliant_table", "noncompliant_devices", "noncompliant"),
                ("intune_stale_table", "stale_devices", "stale"),
            ):
                tree = getattr(self, attr, None)
                if tree is not None:
                    self._safe_tree_clear(tree)
                    for d in (metrics.get(data_key, []) or [])[:500]:
                        tag = self._intune_row_tag(row_type, d.get("os",""))
                        self._safe_insert_tree(tree, [
                            d.get("name",""),
                            self._decorate_os_cell(d.get("os","")),
                            d.get("user",""),
                            self._bubble_token(d.get("compliance","CHECK"), "status"),
                            short_ts(d.get("last_sync","")),
                        ], tag)

            posture = getattr(self, "intune_posture_table", None)
            if posture is not None:
                self._safe_tree_clear(posture)
                posture_rows = []
                for d in metrics.get("unencrypted_devices", []) or []:
                    posture_rows.append(("Unencrypted", d, "bad"))
                for d in metrics.get("jailbroken_devices", []) or []:
                    posture_rows.append(("Jailbreak/root flag", d, "bad"))
                for finding, d, tag in posture_rows[:500]:
                    self._safe_insert_tree(posture, [
                        self._bubble_token(finding, "status"),
                        d.get("name",""),
                        self._decorate_os_cell(d.get("os","")),
                        d.get("user",""),
                        d.get("compliance",""),
                        short_ts(d.get("last_sync","")),
                    ], tag)

            # UniFi site table
            utree = getattr(self, "unifi_sites_table", None)
            if utree is not None:
                self._safe_tree_clear(utree)
                for s in (metrics.get("unifi_site_health", []) or metrics.get("unifi_sites_rows", []) or metrics.get("unifi_sites_detail", []) or [])[:500]:
                    tag = self._unifi_status_tag(s.get("status", "VISIBLE"))
                    self._safe_insert_tree(utree, [
                        s.get("name",""),
                        self._decorate_unifi_status(s.get("status","VISIBLE")),
                        s.get("total",0),
                        self._decorate_count_cell(s.get("online",0), "online"),
                        self._decorate_count_cell(s.get("offline",0), "offline"),
                        self._decorate_count_cell(s.get("degraded",0), "degraded"),
                        s.get("unknown",0),
                        s.get("detail",""),
                    ], tag)

            # Software tables
            newt = getattr(self, "software_new_table", None)
            if newt is not None:
                self._safe_tree_clear(newt)
                for a in (metrics.get("new_software", []) or metrics.get("new_apps", []) or [])[:500]:
                    self._safe_insert_tree(newt, [
                        a.get("displayName",""),
                        a.get("version",""),
                        a.get("publisher",""),
                        a.get("deviceCount",0),
                        "Newly observed",
                    ], "warn")

            allt = getattr(self, "software_all_table", None)
            if allt is not None:
                self._safe_tree_clear(allt)
                for a in (metrics.get("detected_apps", []) or metrics.get("software_all", []) or metrics.get("detected_apps_rows", []) or [])[:1000]:
                    self._safe_insert_tree(allt, [
                        a.get("displayName",""),
                        a.get("version",""),
                        a.get("publisher",""),
                        a.get("deviceCount",0),
                        a.get("sizeInByte",0),
                    ], "info")
        except Exception as e:
            try:
                self.status_var.set(f"Table render recovered with warning: {e}")
            except Exception:
                pass





    def _overview_action_color(self, key, metrics):
        try:
            if key == "overview_defender":
                active = int(metrics.get("active_alerts", metrics.get("defender_alerts", 0)) or 0)
                high = int(metrics.get("critical", metrics.get("defender_critical", 0)) or 0)
                return RED if high else ORANGE if active else GREEN
            if key == "overview_intune":
                noncomp = int(metrics.get("noncompliant", metrics.get("noncompliant_count", 0)) or 0)
                return RED if noncomp else GREEN
            if key == "overview_unifi":
                offline = int(metrics.get("unifi_critical_sites", metrics.get("unifi_offline_sites", 0)) or 0)
                degraded = int(metrics.get("unifi_degraded_sites", 0) or 0)
                return RED if offline else ORANGE if degraded else GREEN
            if key == "overview_software":
                state = str(metrics.get("software_issue_state", metrics.get("software_state", ""))).lower()
                new_sw = int(metrics.get("new_software_count", 0) or 0)
                return ORANGE if "throttle" in state or new_sw else GREEN
        except Exception:
            pass
        return BLUE

    def _recolor_overview_action_icons(self, metrics):
        """Keep Overview row-2 icon glow and text synced to current action state."""
        try:
            cards = getattr(self, "overview_status", {}) or {}
            for key, card in cards.items():
                color = self._overview_action_color(key, metrics)
                dot = card.get("dot")
                if dot is not None:
                    self._set_glow_icon_color(dot, color)
                value = card.get("value")
                if value is not None:
                    try:
                        value.configure(fg=color)
                    except Exception:
                        pass
        except Exception:
            pass

    def _update_overview_action_cards(self, metrics):
        """Populate the four Overview action cards from real live metrics only."""
        try:
            cards = getattr(self, "overview_status", {}) or {}
            if not cards:
                return

            active = int(metrics.get("active_alerts", metrics.get("defender_alerts", 0)) or 0)
            high = int(metrics.get("critical", metrics.get("defender_critical", 0)) or 0)
            graph = int(metrics.get("graph_incidents", metrics.get("graph_alerts", 0)) or 0)
            if "overview_defender" in cards:
                state = "ACTION" if active or high else "OK"
                detail = f"{active} active Defender • {high} high/critical • {graph} Graph/M365 context"
                color = self._overview_action_color("overview_defender", metrics)
                cards["overview_defender"]["value"].configure(text=state, fg=color)
                cards["overview_defender"]["detail"].configure(text=detail)
                self._set_glow_icon_color(cards["overview_defender"]["dot"], color)

            total = int(metrics.get("devices", metrics.get("intune_devices", 0)) or 0)
            noncomp = int(metrics.get("noncompliant", metrics.get("noncompliant_count", 0)) or 0)
            stale = int(metrics.get("stale_30_count", 0) or 0)
            unenc = int(metrics.get("unencrypted_count", 0) or 0)
            no_user = int(metrics.get("no_user_count", 0) or 0)
            if "overview_intune" in cards:
                state = "POSTURE RISK" if noncomp or stale or unenc or no_user else "OK"
                detail = f"{noncomp} non-compliant • {stale} stale 30+ • {unenc} unencrypted • {no_user} no primary user"
                color = self._overview_action_color("overview_intune", metrics)
                cards["overview_intune"]["value"].configure(text=state, fg=color)
                cards["overview_intune"]["detail"].configure(text=detail)
                self._set_glow_icon_color(cards["overview_intune"]["dot"], color)

            sites = int(metrics.get("unifi_sites", 0) or 0)
            offline = int(metrics.get("unifi_critical_sites", metrics.get("unifi_offline_sites", 0)) or 0)
            degraded = int(metrics.get("unifi_degraded_sites", 0) or 0)
            online = int(metrics.get("unifi_online_sites", max(0, sites - offline)) or 0)
            if "overview_unifi" in cards:
                state = "NETWORK ISSUE" if offline or degraded else "OK"
                detail = f"{sites} sites • {online} online • {degraded} degraded • {offline} offline"
                color = self._overview_action_color("overview_unifi", metrics)
                cards["overview_unifi"]["value"].configure(text=state, fg=color)
                cards["overview_unifi"]["detail"].configure(text=detail)
                self._set_glow_icon_color(cards["overview_unifi"]["dot"], color)

            detected = int(metrics.get("detected_app_count", metrics.get("detected_apps_count", metrics.get("detected_apps_returned", 0))) or 0)
            new_sw = int(metrics.get("new_software_count", 0) or 0)
            sw_state = str(metrics.get("software_issue_state", metrics.get("software_state", "OK"))).upper()
            if "overview_software" in cards:
                state = "GRAPH THROTTLED" if "THROTTLE" in sw_state else "OK"
                detail = f"{detected} detected apps returned this run • {new_sw} newly observed"
                color = self._overview_action_color("overview_software", metrics)
                cards["overview_software"]["value"].configure(text=state, fg=color)
                cards["overview_software"]["detail"].configure(text=detail)
                self._set_glow_icon_color(cards["overview_software"]["dot"], color)
        except Exception:
            pass


    def _set_focus_value_safe(self, bucket, key, value, hint=None, color=None):
        try:
            card = getattr(self, "focus_cards", {}).get(bucket, {}).get(key)
            if not card:
                return
            if card.get("value") is not None:
                card["value"].configure(text=str(value), fg=color or card.get("base", BLUE))
            if hint is not None and card.get("hint") is not None:
                card["hint"].configure(text=str(hint))
        except Exception:
            pass

    def _repair_section_cards(self, metrics):
        try:
            total = int(metrics.get("devices", metrics.get("intune_devices", 0)) or 0)
            noncomp = int(metrics.get("noncompliant", metrics.get("noncompliant_count", 0)) or 0)
            stale = int(metrics.get("stale_30_count", 0) or 0)
            unenc = int(metrics.get("unencrypted_count", 0) or 0)
            compliant = max(0, total - noncomp)
            rate = f"{round((compliant / total) * 100)}%" if total else "--"

            self._set_focus_value_safe("intune", "devices", total or "--", "Intune inventory", BLUE)
            self._set_focus_value_safe("intune", "noncompliant", noncomp or 0, "Non-compliant devices", RED if noncomp else GREEN)
            self._set_focus_value_safe("intune", "stale_30_count", stale or 0, "Last sync older than 30 days", ORANGE if stale else GREEN)
            self._set_focus_value_safe("intune", "unencrypted_count", unenc or 0, "Encryption gap", RED if unenc else GREEN)
            self._set_focus_value_safe("intune", "compliant", compliant, "Compliant devices", GREEN)
            self._set_focus_value_safe("intune", "compliance_rate", rate, "Compliance rate", GREEN if total and noncomp == 0 else ORANGE)
            self._set_focus_value_safe("intune", "jailbreak_count", int(metrics.get("jailbreak_count", 0) or 0), "Jailbreak/root flags", RED)
            self._set_focus_value_safe("intune", "no_user_count", int(metrics.get("no_user_count", 0) or 0), "No primary user", AMBER)

            sites = int(metrics.get("unifi_sites", 0) or 0)
            devices = int(metrics.get("unifi_devices", 0) or 0)
            offline = int(metrics.get("unifi_offline_sites", 0) or 0)
            healthy = int(metrics.get("unifi_healthy_sites", max(0, sites - offline - int(metrics.get("unifi_degraded_sites", 0) or 0))) or 0)
            degraded = int(metrics.get("unifi_degraded_sites", 0) or 0)
            alerts = int(metrics.get("unifi_alerts", 0) or 0)

            self._set_focus_value_safe("unifi", "unifi_sites", sites or "--", "Sites", GREEN if sites else BLUE)
            self._set_focus_value_safe("unifi", "unifi_devices", devices or "--", "Devices", BLUE)
            self._set_focus_value_safe("unifi", "unifi_offline_sites", offline or 0, "Offline sites", RED if offline else GREEN)
            self._set_focus_value_safe("unifi", "unifi_healthy_sites", healthy or 0, "Healthy sites", GREEN)
            self._set_focus_value_safe("unifi", "unifi_degraded_sites", degraded or 0, "Degraded sites", ORANGE if degraded else GREEN)
            self._set_focus_value_safe("unifi", "unifi_alerts", alerts or 0, "UniFi alerts", ORANGE if alerts else GREEN)

            detected = int(metrics.get("detected_apps_count", metrics.get("detected_apps_returned", 0)) or 0)
            new_sw = int(metrics.get("new_software_count", 0) or 0)
            self._set_focus_value_safe("software", "detected_apps_count", detected or "--", "Detected apps", BLUE)
            self._set_focus_value_safe("software", "new_software_count", new_sw or 0, "Newly observed", ORANGE if new_sw else GREEN)
        except Exception:
            pass



    def _metric_first(self, metrics, *keys, default=0):
        for key in keys:
            try:
                value = metrics.get(key)
                if value not in (None, "", "--"):
                    return value
            except Exception:
                pass
        return default

    def _metric_count(self, metrics, *keys):
        value = self._metric_first(metrics, *keys, default=0)
        try:
            if isinstance(value, (list, tuple, set)):
                return len(value)
            return int(value or 0)
        except Exception:
            return 0

    def _set_focus_value_safe(self, bucket, key, value, hint=None, color=None):
        try:
            card = getattr(self, "focus_cards", {}).get(bucket, {}).get(key)
            if not card:
                return
            if card.get("value") is not None:
                card["value"].configure(text=str(value), fg=color or card.get("base", BLUE))
            if hint is not None and card.get("hint") is not None:
                card["hint"].configure(text=str(hint))
            dot = card.get("dot")
            if dot is not None:
                self._set_glow_icon_color(dot, color or card.get("base", BLUE))
        except Exception:
            pass

    def _repair_section_cards(self, metrics):
        """Populate tab cards from live metrics using the actual focus_card keys."""
        try:
            def count(*keys):
                for key in keys:
                    value = metrics.get(key)
                    if isinstance(value, (list, tuple, set)):
                        return len(value)
                    if value not in (None, "", "--"):
                        try:
                            return int(value)
                        except Exception:
                            return value
                return 0

            def first(*keys, default=""):
                for key in keys:
                    value = metrics.get(key)
                    if value not in (None, "", "--"):
                        return value
                return default

            # Intune cards. These keys must match the focus_card declarations.
            total = count("devices", "intune_devices", "device_count", "total_devices")
            noncomp = count("noncompliant", "noncompliant_count", "noncompliant_devices_count")
            stale = count("stale_30_count", "stale_count", "stale_devices_count")
            unenc = count("unencrypted_count", "unencrypted_devices_count")
            no_user = count("no_user_count", "no_primary_user_count")
            jailbroken = count("jailbroken_count", "jailbreak_count", "rooted_count")
            compliant = count("compliant_devices", "compliant", "compliant_count")
            if not compliant and total:
                compliant = max(0, int(total) - int(noncomp))
            compliance_percent = first("compliance_percent", "compliance_rate", default="")
            if compliance_percent == "" and total:
                try:
                    compliance_percent = f"{round((int(compliant) / int(total)) * 100)}%"
                except Exception:
                    compliance_percent = "--"

            self._set_focus_value_safe("intune", "devices", total or "--", "Intune inventory", BLUE)
            self._set_focus_value_safe("intune", "noncompliant", noncomp, "Non-compliant devices", RED if noncomp else GREEN)
            self._set_focus_value_safe("intune", "stale_30_count", stale, "Last sync older than 30 days", ORANGE if stale else GREEN)
            self._set_focus_value_safe("intune", "unencrypted_count", unenc, "Encryption gap", RED if unenc else GREEN)
            self._set_focus_value_safe("intune", "compliant_devices", compliant, "Compliant devices", GREEN)
            self._set_focus_value_safe("intune", "compliance_percent", compliance_percent or "--", "Compliance rate", GREEN if total and not noncomp else ORANGE)
            self._set_focus_value_safe("intune", "jailbroken_count", jailbroken, "Jailbreak/root flags", RED if jailbroken else GREEN)
            self._set_focus_value_safe("intune", "no_user_count", no_user, "No primary user", AMBER if no_user else GREEN)

            # UniFi cards and large status panel.
            sites = count("unifi_sites", "site_count", "unifi_site_count")
            devices = count("unifi_devices", "unifi_device_count")
            critical = count("unifi_critical_sites", "unifi_offline_sites", "offline_sites")
            degraded = count("unifi_degraded_sites", "degraded_sites")
            healthy = count("unifi_healthy_sites", "healthy_sites")
            if not healthy and sites:
                try:
                    healthy = max(0, int(sites) - int(critical) - int(degraded))
                except Exception:
                    healthy = 0
            alerts = count("unifi_alerts", "unifi_alert_count")
            site_state = "CRITICAL" if critical else "DEGRADED" if degraded else "HEALTHY" if sites else "--"
            site_color = RED if critical else ORANGE if degraded else GREEN if sites else BLUE

            self._set_focus_value_safe("unifi", "unifi_sites", sites or "--", "Sites", GREEN if sites else BLUE)
            self._set_focus_value_safe("unifi", "unifi_devices", devices or "--", "Devices", BLUE)
            self._set_focus_value_safe("unifi", "unifi_critical_sites", critical, "Offline sites", RED if critical else GREEN)
            self._set_focus_value_safe("unifi", "unifi_healthy_sites", healthy, "Healthy sites", GREEN)
            self._set_focus_value_safe("unifi", "unifi_degraded_sites", degraded, "Degraded sites", ORANGE if degraded else GREEN)
            self._set_focus_value_safe("unifi", "unifi_alerts", alerts, "UniFi alerts", ORANGE if alerts else GREEN)

            try:
                self.unifi_tab_status_big.configure(text=site_state, fg=site_color)
                self.unifi_tab_status_hint.configure(text=f"{sites} site(s), {critical} offline, {degraded} degraded")
            except Exception:
                pass

            # Software cards. The actual card key is detected_app_count, singular.
            detected = count("detected_app_count", "detected_apps_count", "detected_apps_returned", "software_count")
            if not detected:
                detected = len(metrics.get("detected_apps", []) or metrics.get("software_all", []) or metrics.get("detected_apps_rows", []) or [])
            new_sw = count("new_software_count", "new_apps_count")
            if not new_sw:
                new_sw = len(metrics.get("new_software", []) or metrics.get("new_apps", []) or [])
            source = first("detected_apps_source", default="Graph")
            issue = str(first("software_issue_state", default="OK")).upper()

            self._set_focus_value_safe("software", "detected_app_count", detected or "--", "Detected apps", BLUE)
            self._set_focus_value_safe("software", "new_software_count", new_sw, "Newly observed", ORANGE if new_sw else GREEN)
            self._set_focus_value_safe("software", "detected_apps_source", source, "Inventory source", BLUE)
            self._set_focus_value_safe("software", "software_issue_state", issue, "DetectedApps status", ORANGE if "THROTTLE" in issue else GREEN)

            # Defender enrichment cards.
            self._set_focus_value_safe("defender", "graph_incidents", count("graph_incidents", "m365_incidents"), "M365 incidents", ORANGE)
            self._set_focus_value_safe("defender", "defender_recommendations", count("defender_recommendations"), "TVM recommendations", PURPLE)
            self._set_focus_value_safe("defender", "defender_vulnerabilities", count("defender_vulnerabilities"), "Vulnerabilities", RED)
            self._set_focus_value_safe("defender", "defender_machines", count("defender_machines"), "Machines", BLUE)
        except Exception:
            pass



    def _is_defender_or_microsoft_security(self, row):
        """True for real Defender/M365/Graph security rows.

        This intentionally excludes Intune posture, UniFi and software inventory rows,
        but includes Graph incident cache/backoff rows so the Defender page explains
        why incidents are cached/throttled instead of appearing empty.
        """
        try:
            source = str(row.get("source", "")).lower()
            title = str(row.get("title", "")).lower()
            detail = str(row.get("detail", "")).lower()
        except Exception:
            source = title = detail = ""
        joined = " ".join([source, title, detail])

        excluded = (
            "intune device posture summary",
            "full intune inventory loaded",
            "detected apps inventory",
            "software inventory",
            "unifi",
            "site manager",
            "client and traffic",
        )
        if any(x in joined for x in excluded):
            return False

        included = (
            "defender",
            "microsoft 365",
            "m365",
            "graph incidents",
            "graph security",
            "security alert",
            "security incident",
            "incidents live",
            "alerts live",
            "email messages",
            "malicious",
            "phish",
            "credential",
            "safe links",
            "exchange",
            "mailbox",
            "cache/backoff",
            "graph incident",
            "connector degraded",
            "microsoftgraphconnector",
            "api/auth",
            "forbidden",
            "missing application roles",
        )
        return any(x in joined for x in included)

    def _intune_device_rows(self, metrics, kind):
        """Return real Intune device rows using all known key variants."""
        key_sets = {
            "noncompliant": (
                "noncompliant_devices",
                "intune_noncompliant_devices",
                "non_compliant_devices",
                "noncompliant_rows",
            ),
            "stale": (
                "stale_devices",
                "stale_30_devices",
                "intune_stale_devices",
                "stale_30_rows",
            ),
            "unencrypted": (
                "unencrypted_devices",
                "intune_unencrypted_devices",
                "unencrypted_rows",
            ),
            "nouser": (
                "no_user_devices",
                "no_primary_user_devices",
                "intune_no_user_devices",
                "no_user_rows",
            ),
            "all": (
                "devices_rows",
                "intune_device_rows",
                "managed_devices",
                "devices_detail",
            ),
        }
        for key in key_sets.get(kind, ()):
            rows = metrics.get(key)
            if isinstance(rows, list):
                return rows
        return []



    def _metric_first(self, metrics, *keys, default=0):
        for key in keys:
            try:
                value = metrics.get(key)
                if value not in (None, "", "--"):
                    return value
            except Exception:
                pass
        return default

    def _metric_count(self, metrics, *keys):
        value = self._metric_first(metrics, *keys, default=0)
        try:
            if isinstance(value, (list, tuple, set)):
                return len(value)
            return int(value or 0)
        except Exception:
            return 0

    def _safe_card_update(self, card, value=None, detail=None, color=None):
        if not card:
            return
        try:
            if value is not None and card.get("value") is not None:
                card["value"].configure(text=str(value), fg=color or card.get("base", BLUE))
            if detail is not None:
                target = card.get("detail") or card.get("hint")
                if target is not None:
                    target.configure(text=str(detail))
            dot = card.get("dot")
            if dot is not None and color is not None:
                self._set_glow_icon_color(dot, color)
            shell = card.get("shell") or card.get("panel")
            if shell is not None and color is not None:
                try:
                    shell.configure(highlightbackground=color)
                except Exception:
                    pass
        except Exception:
            pass

    def _repair_overview_cards_live(self, metrics):
        """Repair Overview action cards from live metrics only."""
        try:
            cards = getattr(self, "overview_status", {}) or {}

            active = self._metric_count(metrics, "active_alerts", "defender_alerts")
            high = self._metric_count(metrics, "critical", "defender_critical", "defender_high")
            graph = self._metric_count(metrics, "graph_incidents", "graph_alerts", "m365_incidents")
            defender_color = RED if high else ORANGE if active else GREEN
            self._safe_card_update(
                cards.get("overview_defender"),
                "ACTION" if active or high else "OK",
                f"{active} active Defender • {high} high/critical • {graph} Graph/M365 context",
                defender_color,
            )

            noncomp = self._metric_count(metrics, "noncompliant", "noncompliant_count")
            stale = self._metric_count(metrics, "stale_30_count", "stale_count")
            unenc = self._metric_count(metrics, "unencrypted_count")
            no_user = self._metric_count(metrics, "no_user_count")
            intune_color = RED if noncomp or unenc else ORANGE if stale or no_user else GREEN
            self._safe_card_update(
                cards.get("overview_intune"),
                "POSTURE RISK" if noncomp or stale or unenc or no_user else "OK",
                f"{noncomp} non-compliant • {stale} stale 30+ • {unenc} unencrypted • {no_user} no primary user",
                intune_color,
            )

            sites = self._metric_count(metrics, "unifi_sites", "site_count", "unifi_site_count")
            offline = self._metric_count(metrics, "unifi_critical_sites", "unifi_offline_sites", "offline_sites")
            degraded = self._metric_count(metrics, "unifi_degraded_sites", "degraded_sites")
            online = self._metric_count(metrics, "unifi_online_sites", "online_sites")
            if not online and sites:
                online = max(0, sites - offline)
            unifi_color = RED if offline else ORANGE if degraded else GREEN if sites else BLUE
            self._safe_card_update(
                cards.get("overview_unifi"),
                "NETWORK ISSUE" if offline or degraded else "OK",
                f"{sites} sites • {online} online • {degraded} degraded • {offline} offline",
                unifi_color,
            )

            detected = self._metric_count(metrics, "detected_app_count", "detected_apps_count", "detected_apps_returned")
            if not detected:
                detected = len(metrics.get("detected_apps", []) or metrics.get("software_all", []) or [])
            new_sw = self._metric_count(metrics, "new_software_count", "new_apps_count")
            if not new_sw:
                new_sw = len(metrics.get("new_software", []) or metrics.get("new_apps", []) or [])
            issue = str(self._metric_first(metrics, "software_issue_state", "software_state", default="OK")).upper()
            software_color = ORANGE if "THROTTLE" in issue else GREEN
            self._safe_card_update(
                cards.get("overview_software"),
                "GRAPH THROTTLED" if "THROTTLE" in issue else "WATCHING",
                f"{detected} detected apps returned this run • {new_sw} newly observed",
                software_color,
            )

            # Row 3 small labels.
            for key, value, color in (
                ("stale_30_count", stale, ORANGE if stale else GREEN),
                ("unencrypted_count", unenc, RED if unenc else GREEN),
                ("no_user_count", no_user, AMBER if no_user else GREEN),
                ("unifi_degraded_sites", degraded, ORANGE if degraded else GREEN),
            ):
                try:
                    lbl = getattr(self, "posture_labels", {}).get(key)
                    if lbl:
                        lbl.configure(text=str(value), fg=color)
                except Exception:
                    pass
        except Exception:
            pass

    def _repair_tab_cards_live(self, metrics):
        """Repair Defender, Intune, UniFi and Software cards from live metric keys."""
        try:
            # Defender
            self._set_focus_value_safe("defender", "priority_state", self._metric_first(metrics, "priority_state", default="CLEAR"), "Defender priority", GREEN)
            self._set_focus_value_safe("defender", "defender_alerts", self._metric_count(metrics, "defender_alerts", "active_alerts"), "Defender active alerts", ORANGE)
            self._set_focus_value_safe("defender", "graph_incidents", self._metric_count(metrics, "graph_incidents", "m365_incidents"), "M365 incidents", ORANGE)
            self._set_focus_value_safe("defender", "defender_recommendations", self._metric_count(metrics, "defender_recommendations"), "TVM recommendations", PURPLE)
            self._set_focus_value_safe("defender", "defender_vulnerabilities", self._metric_count(metrics, "defender_vulnerabilities"), "Vulnerabilities", RED)
            self._set_focus_value_safe("defender", "defender_machines", self._metric_count(metrics, "defender_machines"), "Machines", BLUE)

            # Intune
            total = self._metric_count(metrics, "devices", "intune_devices", "device_count", "total_devices")
            noncomp = self._metric_count(metrics, "noncompliant", "noncompliant_count")
            stale = self._metric_count(metrics, "stale_30_count", "stale_count")
            unenc = self._metric_count(metrics, "unencrypted_count")
            compliant = self._metric_count(metrics, "compliant_devices", "compliant", "compliant_count")
            if not compliant and total:
                compliant = max(0, total - noncomp)
            rate = self._metric_first(metrics, "compliance_percent", "compliance_rate", default="")
            if not rate and total:
                try:
                    rate = f"{round((compliant / total) * 100)}%"
                except Exception:
                    rate = "--"
            jail = self._metric_count(metrics, "jailbroken_count", "jailbreak_count", "rooted_count")
            no_user = self._metric_count(metrics, "no_user_count", "no_primary_user_count")

            self._set_focus_value_safe("intune", "devices", total or "--", "Intune inventory", BLUE)
            self._set_focus_value_safe("intune", "noncompliant", noncomp, "Non-compliant devices", RED if noncomp else GREEN)
            self._set_focus_value_safe("intune", "stale_30_count", stale, "Last sync older than 30 days", ORANGE if stale else GREEN)
            self._set_focus_value_safe("intune", "unencrypted_count", unenc, "Encryption gap", RED if unenc else GREEN)
            self._set_focus_value_safe("intune", "compliant_devices", compliant, "Compliant devices", GREEN)
            self._set_focus_value_safe("intune", "compliance_percent", rate or "--", "Compliance rate", GREEN if total and not noncomp else ORANGE)
            self._set_focus_value_safe("intune", "jailbroken_count", jail, "Jailbreak/root flags", RED if jail else GREEN)
            self._set_focus_value_safe("intune", "no_user_count", no_user, "No primary user", AMBER if no_user else GREEN)

            # UniFi
            sites = self._metric_count(metrics, "unifi_sites", "site_count", "unifi_site_count")
            devices = self._metric_count(metrics, "unifi_devices", "unifi_device_count")
            offline = self._metric_count(metrics, "unifi_critical_sites", "unifi_offline_sites", "offline_sites")
            degraded = self._metric_count(metrics, "unifi_degraded_sites", "degraded_sites")
            healthy = self._metric_count(metrics, "unifi_healthy_sites", "healthy_sites")
            if not healthy and sites:
                healthy = max(0, sites - offline - degraded)
            alerts = self._metric_count(metrics, "unifi_alerts", "unifi_alert_count")
            state = "CRITICAL" if offline else "DEGRADED" if degraded else "HEALTHY" if sites else "--"
            state_color = RED if offline else ORANGE if degraded else GREEN if sites else BLUE

            self._set_focus_value_safe("unifi", "unifi_sites", sites or "--", "Sites", GREEN if sites else BLUE)
            self._set_focus_value_safe("unifi", "unifi_devices", devices or "--", "Devices", BLUE)
            self._set_focus_value_safe("unifi", "unifi_critical_sites", offline, "Offline sites", RED if offline else GREEN)
            self._set_focus_value_safe("unifi", "unifi_healthy_sites", healthy, "Healthy sites", GREEN)
            self._set_focus_value_safe("unifi", "unifi_degraded_sites", degraded, "Degraded sites", ORANGE if degraded else GREEN)
            self._set_focus_value_safe("unifi", "unifi_alerts", alerts, "UniFi alerts", ORANGE if alerts else GREEN)
            try:
                self.unifi_tab_status_big.configure(text=state, fg=state_color)
                self.unifi_tab_status_hint.configure(text=f"{sites} site(s), {offline} offline, {degraded} degraded")
            except Exception:
                pass

            # Software
            detected = self._metric_count(metrics, "detected_app_count", "detected_apps_count", "detected_apps_returned")
            if not detected:
                detected = len(metrics.get("detected_apps", []) or metrics.get("software_all", []) or [])
            new_sw = self._metric_count(metrics, "new_software_count", "new_apps_count")
            if not new_sw:
                new_sw = len(metrics.get("new_software", []) or metrics.get("new_apps", []) or [])
            issue = str(self._metric_first(metrics, "software_issue_state", default="OK")).upper()
            source = self._metric_first(metrics, "detected_apps_source", default="Graph")
            self._set_focus_value_safe("software", "detected_app_count", detected or "--", "Detected apps", BLUE)
            self._set_focus_value_safe("software", "new_software_count", new_sw, "Newly observed", ORANGE if new_sw else GREEN)
            self._set_focus_value_safe("software", "detected_apps_source", source, "Inventory source", BLUE)
            self._set_focus_value_safe("software", "software_issue_state", issue, "DetectedApps status", ORANGE if "THROTTLE" in issue else GREEN)
        except Exception:
            pass

    def _os_tag(self, os_name, fallback="info"):
        raw = str(os_name or "").lower()
        if "windows" in raw:
            return "os_windows"
        if "android" in raw:
            return "os_android"
        if "ios" in raw or "iphone" in raw or "ipad" in raw:
            return "os_ios"
        if "mac" in raw:
            return "os_mac"
        return fallback

    def _apply_extra_table_tags(self, tree):
        try:
            tree.tag_configure("os_windows", foreground="#36CFFF", background="#08263E")
            tree.tag_configure("os_android", foreground="#7DFF57", background="#07301B")
            tree.tag_configure("os_ios", foreground="#FFC84A", background="#292304")
            tree.tag_configure("os_mac", foreground="#C06BFF", background="#20143A")
        except Exception:
            pass


    def hard_repaint_all_tables(self, payload=None):
        """Repaint all cards and tables from the latest live payload."""
        payload = payload or getattr(self, "last_payload", None)
        if not payload:
            return
        metrics = payload.get("metrics", {}) or {}
        rows = payload.get("alert_rows", []) or []

        try:
            self._repair_overview_cards_live(metrics)
            self._repair_tab_cards_live(metrics)
        except Exception:
            pass

        def clear(tree):
            try:
                for item in tree.get_children():
                    tree.delete(item)
            except Exception:
                pass

        def insert(tree, vals, tag="info"):
            try:
                self._apply_extra_table_tags(tree)
            except Exception:
                pass
            try:
                cols = list(tree["columns"])
                vals = list(vals)
                if len(vals) < len(cols):
                    vals += [""] * (len(cols) - len(vals))
                elif len(vals) > len(cols):
                    vals = vals[:len(cols)]
                tree.insert("", "end", values=vals, tags=(tag,))
            except Exception:
                pass

        def bubble(v, kind="status"):
            try:
                return self._bubble_token(v, kind)
            except Exception:
                return str(v)

        def tag_for(row):
            return self._stable_event_tag(row.get("severity", "INFO"), row.get("source", ""), row.get("title", ""), row.get("detail", ""))

        def is_defender(row):
            try:
                if hasattr(self, "_is_defender_or_microsoft_security"):
                    return self._is_defender_or_microsoft_security(row)
                return self._is_defender_related_row(row.get("source",""), row.get("title",""), row.get("detail",""))
            except Exception:
                joined = " ".join([str(row.get("source","")), str(row.get("title","")), str(row.get("detail",""))]).lower()
                return any(x in joined for x in ("defender", "microsoft 365", "graph incidents", "security incident", "email messages", "phish", "malicious"))

        # Defender / M365
        defender_rows = [r for r in rows if is_defender(r)]
        for tree_name in ("overview_defender_feed_table", "defender_alert_table"):
            tree = getattr(self, tree_name, None)
            if tree is None:
                continue
            try:
                tree.configure(columns=("severity", "time", "title", "status", "detail"))
                self.setup_tree_columns(tree, [
                    ("severity", "Severity", 120),
                    ("time", "Time", 170),
                    ("title", "Alert / finding", 620),
                    ("status", "Status", 150),
                    ("detail", "Detail", 880),
                ])
            except Exception:
                pass
            clear(tree)
            for r in defender_rows[:300]:
                sev = str(r.get("severity", "INFO")).upper()
                insert(tree, [
                    bubble(sev, "severity"),
                    short_ts(r.get("timestamp", "")),
                    "✦  " + str(r.get("title", ""))[:180],
                    bubble(str(r.get("status", "ACTIVE")).upper(), "status"),
                    str(r.get("detail", ""))[:300],
                ], tag_for(r))
            if not defender_rows:
                insert(tree, [bubble("INFO", "severity"), "", "✦  No Defender/M365 rows returned", bubble("INFO", "status"), "No Microsoft security rows returned in this poll. Check Full signal feed for API/auth diagnostics."], "info")

        # Full signal / Defender signal
        for tree_name in ("overview_full_feed_table", "defender_signal_table"):
            tree = getattr(self, tree_name, None)
            if tree is None:
                continue
            clear(tree)
            try:
                if tree_name == "defender_signal_table":
                    tree.configure(columns=("time", "severity", "source", "signal", "detail"))
                    self.setup_tree_columns(tree, [
                        ("time", "Time", 170),
                        ("severity", "Severity", 120),
                        ("source", "Source", 220),
                        ("signal", "Signal", 520),
                        ("detail", "Detail", 880),
                    ])
            except Exception:
                pass
            for r in rows[:350]:
                sev = str(r.get("severity", "INFO")).upper()
                if tree_name == "defender_signal_table":
                    insert(tree, [short_ts(r.get("timestamp", "")), bubble(sev, "severity"), self._stable_source_label(r.get("source", "")), "✦  " + str(r.get("title", ""))[:180], str(r.get("detail", ""))[:300]], tag_for(r))
                else:
                    insert(tree, [bubble(sev, "severity"), self._stable_source_label(r.get("source", "")), short_ts(r.get("timestamp", "")), "✦  " + str(r.get("title", ""))[:180], str(r.get("detail", ""))[:300]], tag_for(r))

        # Intune noncompliant
        tree = getattr(self, "intune_noncompliant_table", None)
        if tree is not None:
            clear(tree)
            devs = self._intune_device_rows(metrics, "noncompliant") if hasattr(self, "_intune_device_rows") else (metrics.get("noncompliant_devices", []) or [])
            for d in devs[:500]:
                os_name = d.get("os") or d.get("operatingSystem") or ""
                insert(tree, ["👤  " + str(d.get("name") or d.get("deviceName") or d.get("managedDeviceName") or ""), self._decorate_os_cell(os_name), d.get("user") or d.get("userPrincipalName") or d.get("emailAddress") or "", bubble(d.get("compliance") or d.get("complianceState") or "NONCOMPLIANT", "status"), short_ts(d.get("last_sync") or d.get("lastSyncDateTime") or "")], self._os_tag(os_name, "warn"))
            if not devs:
                insert(tree, ["✦  No non-compliant device rows returned", "", "", bubble("INFO", "status"), "No live rows returned for this table."], "info")

        # Intune stale
        tree = getattr(self, "intune_stale_table", None)
        if tree is not None:
            clear(tree)
            devs = self._intune_device_rows(metrics, "stale") if hasattr(self, "_intune_device_rows") else (metrics.get("stale_devices", []) or metrics.get("stale_30_devices", []) or [])
            for d in devs[:500]:
                os_name = d.get("os") or d.get("operatingSystem") or ""
                insert(tree, ["⏱  " + str(d.get("name") or d.get("deviceName") or d.get("managedDeviceName") or ""), self._decorate_os_cell(os_name), d.get("user") or d.get("userPrincipalName") or d.get("emailAddress") or "", bubble(d.get("compliance") or d.get("complianceState") or "CHECK", "status"), short_ts(d.get("last_sync") or d.get("lastSyncDateTime") or "")], self._os_tag(os_name, "warn"))
            if not devs:
                insert(tree, ["✦  No stale device rows returned", "", "", bubble("INFO", "status"), "No live rows returned for this table."], "info")

        # Intune posture
        tree = getattr(self, "intune_posture_table", None)
        if tree is not None:
            clear(tree)
            posture = []
            for d in (metrics.get("unencrypted_devices", []) or []):
                posture.append(("🔑 Unencrypted", d, "bad"))
            for d in (metrics.get("jailbroken_devices", []) or metrics.get("rooted_devices", []) or []):
                posture.append(("◆ Jailbreak/root flag", d, "bad"))
            for label, d, fallback_tag in posture[:500]:
                os_name = d.get("os") or d.get("operatingSystem") or ""
                insert(tree, [bubble(label, "status"), d.get("name") or d.get("deviceName") or "", self._decorate_os_cell(os_name), d.get("user") or d.get("userPrincipalName") or "", bubble(d.get("compliance") or d.get("complianceState") or "CHECK", "status"), short_ts(d.get("last_sync") or d.get("lastSyncDateTime") or "")], self._os_tag(os_name, fallback_tag))
            if not posture:
                insert(tree, [bubble("INFO", "severity"), "No posture rows returned", "", "", bubble("INFO", "status"), "No unencrypted/rooted rows in live data."], "info")

        # UniFi
        tree = getattr(self, "unifi_sites_table", None)
        if tree is not None:
            clear(tree)
            sites = metrics.get("unifi_site_health", []) or metrics.get("unifi_sites_rows", []) or metrics.get("unifi_sites_detail", []) or []
            for s in sites[:500]:
                status = str(s.get("status", "VISIBLE")).upper()
                tag = "bad" if status in ("CRITICAL", "OFFLINE") else "warn" if status == "DEGRADED" else "good"
                insert(tree, ["📡  " + str(s.get("name","")), self._decorate_unifi_status(status), self._decorate_count_cell(s.get("total",0)), self._decorate_count_cell(s.get("online",0), "online"), self._decorate_count_cell(s.get("offline",0), "offline"), self._decorate_count_cell(s.get("degraded",0), "degraded"), self._decorate_count_cell(s.get("unknown",0)), s.get("detail","")], tag)

        # Software
        tree = getattr(self, "software_new_table", None)
        if tree is not None:
            clear(tree)
            apps = metrics.get("new_software", []) or metrics.get("new_apps", []) or []
            for a in apps[:500]:
                insert(tree, ["✦  " + str(a.get("displayName") or a.get("name") or ""), a.get("version",""), a.get("publisher",""), self._decorate_count_cell(a.get("deviceCount",0)), bubble("NEW", "status")], self._software_tag(a, True))
            if not apps:
                insert(tree, ["✦  No newly observed software", "", "", "", bubble("INFO", "status")], "info")

        tree = getattr(self, "software_all_table", None)
        if tree is not None:
            clear(tree)
            apps = metrics.get("detected_apps", []) or metrics.get("software_all", []) or metrics.get("detected_apps_rows", []) or []
            for a in apps[:1000]:
                insert(tree, ["▤  " + str(a.get("displayName") or a.get("name") or ""), a.get("version",""), a.get("publisher",""), self._decorate_count_cell(a.get("deviceCount",0)), a.get("sizeInByte") or a.get("size") or ""], self._software_tag(a, False))
            if not apps:
                insert(tree, ["▤  No detected apps returned", "", "", "", "Awaiting live API data"], "info")

        # Defender enrichment
        tree = getattr(self, "defender_recommendations_table", None)
        if tree is not None:
            clear(tree)
            recs = metrics.get("defender_recommendation_rows", []) or []
            for r in recs[:500]:
                sev = str(r.get("severity", "INFO")).upper()
                insert(tree, ["⚙  " + str(r.get("title","")), bubble(sev or "INFO", "severity"), r.get("category",""), self._decorate_count_cell(r.get("impact","")), bubble(r.get("status","CHECK"), "status"), r.get("detail","")], self._recommendation_tag(r))
            if not recs:
                insert(tree, ["⚙  Recommendations unavailable", bubble("INFO", "severity"), "Permission/API", "", bubble("CHECK", "status"), (metrics.get("defender_recommendation_error") or "Awaiting live API data")[:300]], "info")

        tree = getattr(self, "defender_vulnerabilities_table", None)
        if tree is not None:
            clear(tree)
            vulns = metrics.get("defender_vulnerability_rows", []) or []
            for v in vulns[:500]:
                sev = str(v.get("severity", "INFO")).upper()
                insert(tree, ["◆  " + str(v.get("id","")), bubble(sev or "INFO", "severity"), v.get("cvss",""), short_ts(v.get("published","")), short_ts(v.get("updated","")), v.get("detail","")], self._stable_event_tag(sev, "Defender Vulnerabilities", v.get("id",""), v.get("detail","")))
            if not vulns:
                insert(tree, ["◆  Vulnerabilities unavailable", bubble("INFO", "severity"), "", "", "", (metrics.get("defender_vulnerability_error") or "Awaiting live API data")[:300]], "info")

        tree = getattr(self, "defender_machines_table", None)
        if tree is not None:
            clear(tree)
            machines = metrics.get("defender_machine_rows", []) or []
            for m in machines[:500]:
                risk = m.get("risk", "INFO")
                insert(tree, ["⌬  " + str(m.get("name","")), bubble(risk, "status"), bubble(m.get("health","CHECK"), "status"), self._decorate_os_cell(m.get("os","")), short_ts(m.get("last_seen","")), m.get("ip","")], self._stable_event_tag(risk, "Defender Machines", m.get("name",""), m.get("health","")))
            if not machines:
                insert(tree, ["⌬  Machines unavailable", bubble("INFO", "status"), bubble("CHECK", "status"), "", "", (metrics.get("defender_machine_error") or "Awaiting live API data")[:300]], "info")


    def _dashboard_connected(self):
        try:
            payload = getattr(self, "last_payload", None) or {}
            metrics = payload.get("metrics", {}) if isinstance(payload, dict) else {}
            if metrics:
                return True
            # fall back to footer/status text if metrics are not ready
            raw = ""
            try:
                raw += " " + str(self.status_var.get())
            except Exception:
                pass
            return "connected" in raw.lower() or "poll" in raw.lower()
        except Exception:
            return False

    def _set_heartbeat_visibility(self):
        try:
            connected = self._dashboard_connected()
            for name in ("heartbeat_canvas", "live_heartbeat_canvas", "overview_heartbeat_canvas"):
                canvas = getattr(self, name, None)
                if canvas is not None:
                    state = "normal" if connected else "hidden"
                    for item in canvas.find_all():
                        canvas.itemconfigure(item, state=state)
            for name in ("heartbeat_label", "live_heartbeat_label", "overview_heartbeat_label"):
                label = getattr(self, name, None)
                if label is not None:
                    label.configure(text="LIVE PULSE" if connected else "WAITING FOR CONNECTION", fg=GREEN if connected else MUTED)
        except Exception:
            pass


    def pulse_overview_status(self):
        self._set_heartbeat_visibility()
        if not hasattr(self, "overview_status"):
            return
        for item in self.overview_status.values():
            widget = item.get("dot")
            color = item.get("base", GREEN)
            item["pulse"] = (int(item.get("pulse", 0)) + 1) % 18
            # Some overview icons are labels, not canvases. Keep the heartbeat alive
            # instead of letting a label/canvas mismatch kill the visual loop.
            try:
                if hasattr(widget, "delete"):
                    radius = 4 + (item["pulse"] % 9)
                    widget.delete("pulse")
                    widget.create_oval(7 - radius, 7 - radius, 7 + radius, 7 + radius, fill="", outline=color, width=1, tags="pulse")
                    widget.create_oval(5 - radius//2, 5 - radius//2, 9 + radius//2, 9 + radius//2, fill="", outline=color, width=1, tags="pulse")
                    widget.create_oval(3, 3, 11, 11, fill=color, outline=color, tags="pulse")
                elif hasattr(widget, "configure"):
                    widget.configure(fg=color)
            except Exception:
                pass
        self.draw_heartbeat()
        try:
            self.after(450, self.pulse_overview_status)
        except Exception:
            pass

    def default_sort_tables(self):
        # First-load defaults only. Once the user clicks a header, repolls preserve that choice.
        sort_targets = [
            ("overview_defender_feed_table", "severity", False),
            ("overview_full_feed_table", "severity", False),
            ("defender_alert_table", "time", True),
            ("defender_signal_table", "time", True),
            ("intune_noncompliant_table", "last_sync", True),
            ("intune_stale_table", "days", True),
            ("intune_posture_table", "type", False),
            ("unifi_sites_table", "status", False),
            ("software_new_table", "name", False),
            ("software_all_table", "devices", True),
        ]
        for attr, col, rev in sort_targets:
            tree = getattr(self, attr, None)
            if tree is None:
                continue
            try:
                if col not in tree["columns"]:
                    continue
                state = self.table_sort_state.get(str(tree))
                if state:
                    self.sort_treeview(tree, state[0], state[1], remember=False)
                else:
                    self.sort_treeview(tree, col, rev, remember=False)
            except Exception:
                pass

    def render_focus_views(self, payload):
        m = payload.get("metrics", {})
        self.sync_neon_tiles(m)
        rows = payload.get("alert_rows", []) or []
        events = payload.get("events", []) or []

        self.trend_history["defender"].append(int(m.get("defender_alerts", 0) or 0))
        self.trend_history["compliance"].append(int(m.get("noncompliant", 0) or 0))
        self.trend_history["network"].append(int(m.get("unifi_critical_sites", 0) or 0))
        for k in self.trend_history:
            self.trend_history[k] = self.trend_history[k][-80:]
        if "defender" in self.trend_labels:
            self.trend_labels["defender"].config(text=str(m.get("defender_alerts", 0)))
            self.trend_labels["compliance"].config(text=str(m.get("noncompliant", 0)))
            self.trend_labels["network"].config(text=str(m.get("unifi_critical_sites", 0)))
            security_signals = {
                "defender": int(m.get("defender_alerts", 0) or 0),
                "graph": int(m.get("graph_alerts", 0) or 0),
                "intune": int(m.get("noncompliant", 0) or 0) + int(m.get("stale_30_count", 0) or 0) + int(m.get("unencrypted_count", 0) or 0),
                "unifi": int(m.get("unifi_critical_sites", 0) or 0) + int(m.get("unifi_degraded_sites", 0) or 0) + int(m.get("unifi_alerts", 0) or 0),
            }
            self.trend_labels["security_signals"].config(text=f"{sum(security_signals.values())} signals")
            self.draw_trend("defender", self.trend_history["defender"], ORANGE)
            self.draw_trend("compliance", self.trend_history["compliance"], BLUE)
            self.draw_trend("network", self.trend_history["network"], RED)
            self.draw_security_signals(security_signals)

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
                hint = "Graph / M365 active context"
            else:
                color, hint = BLUE, "live"
            card["value"].config(fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        ms_rows = []
        for r in rows:
            src = str(r.get("source", ""))
            title = str(r.get("title", ""))
            detail = str(r.get("detail", ""))
            if self._is_defender_related_row(src, title, detail):
                ms_rows.append(r)

        if hasattr(self, "defender_alert_table"):
            self.clear_table(self.defender_alert_table)
            if not ms_rows:
                self.insert_table_row(self.defender_alert_table, ["", "INFO", "INFO", "Microsoft 365 Defender", "No Defender/M365 security rows returned", ""], tag="info")
            for r in ms_rows[:2000]:
                sev = str(r.get("severity", "INFO")).upper()
                status = str(r.get("status", "ACTIVE"))
                src = str(r.get("source", ""))
                title = str(r.get("title", ""))
                detail = str(r.get("detail", ""))
                ts = short_ts(r.get("timestamp", ""))
                tag = "bad" if sev == "CRITICAL" else "high" if sev == "HIGH" else "warn" if sev == "MEDIUM" or status == "ACTIVE" else "info"
                self.insert_table_row(self.defender_alert_table, [ts, status, sev, self._source_icon_label(src), title, detail], tag=tag)

            self.clear_table(self.defender_signal_table)
            if events:
                for e in events[:500]:
                    src = str(e.get("source", ""))
                    if self._is_defender_related_row(src, str(e.get("title", "")), str(e.get("detail", ""))):
                        sev = str(e.get("severity", "info")).upper()
                        ts = short_ts(e.get("timestamp", ""))
                        tag = "bad" if sev == "CRITICAL" else "high" if sev == "HIGH" else "warn" if sev == "MEDIUM" else "info"
                        self.insert_table_row(self.defender_signal_table, [
                            ts,
                            sev,
                            self._source_icon_label(src),
                            e.get("title", ""),
                            e.get("detail", ""),
                        ], tag=tag)
            else:
                self.insert_table_row(self.defender_signal_table, ["", "INFO", "Microsoft", "No signal events returned", ""], tag="info")

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
            elif key == "stale_30_count":
                color = ORANGE if int(val or 0) > 0 else GREEN
                hint = "devices not contacted 30+ days"
            elif key == "unencrypted_count":
                color = RED if int(val or 0) > 0 else GREEN
                hint = "devices reporting not encrypted"
            elif key == "jailbroken_count":
                color = RED if int(val or 0) > 0 else GREEN
                hint = "jailbreak/root posture flags"
            elif key == "no_user_count":
                color = AMBER if int(val or 0) > 0 else GREEN
                hint = "devices without a primary user/email"
            card["value"].config(text=f"{val}{suffix}", fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        for key, label in getattr(self, "intune_platform_focus", {}).items():
            label.config(text=str(m.get(key, 0)))

        total = int(m.get("devices", 0) or 0)
        noncompliant = int(m.get("noncompliant", 0) or 0)
        compliant = int(m.get("compliant_devices", max(0, total - noncompliant)) or 0)
        pct = int(m.get("compliance_percent", 0) or 0)
        stale = int(m.get("stale_30_count", 0) or 0)
        unencrypted = int(m.get("unencrypted_count", 0) or 0)
        jailbroken = int(m.get("jailbroken_count", 0) or 0)
        no_user = int(m.get("no_user_count", 0) or 0)
        int_lines = [
            f"Total Intune devices : {total}",
            f"Compliant devices    : {compliant}",
            f"Non-compliant devices: {noncompliant}",
            f"Compliance rate      : {pct}%",
            f"Not contacted 30+ days: {stale}",
            f"Unencrypted devices  : {unencrypted}",
            f"Jailbreak/root flags : {jailbroken}",
            f"No primary user/email : {no_user}",
            "",
            "Monitoring interpretation",
            "-" * 90,
            "Non-compliant = policy/compliance attention",
            "Not contacted 30+ days = stale or retired assets to review",
            "Unencrypted = security control gap",
            "No primary user/email = ownership/investigation friction",
            "",
            "Platform breakdown",
            "-" * 90,
            f"Windows      : {m.get('windows', 0)}",
            f"iPhone / iPad: {m.get('ios', 0)}",
            f"Mac          : {m.get('macos', 0)}",
            f"Android      : {m.get('android', 0)}",
            f"Other OS     : {m.get('other_os', 0)}",
            "",
            "Non-compliant devices",
            "-" * 90,
        ]
        if not m.get("noncompliant_devices"):
            int_lines.append("No non-compliant device sample returned.")
        for d in (m.get("noncompliant_devices", []) or [])[:80]:
            int_lines.append(f"{d.get('name','unknown'):<32} | {d.get('os',''):<10} | {d.get('user',''):<34} | {d.get('compliance','')} | last sync {short_ts(d.get('last_sync',''))}")
        int_lines += [
            "",
            "Devices not contacted for 30+ days",
            "-" * 90,
        ]
        if not m.get("stale_devices"):
            int_lines.append("No stale device sample returned.")
        for d in (m.get("stale_devices", []) or [])[:80]:
            days = d.get("last_sync_days")
            int_lines.append(f"{d.get('name','unknown'):<32} | {d.get('os',''):<10} | {days if days is not None else '?'} days | {d.get('user','')} | last sync {short_ts(d.get('last_sync',''))}")
        int_lines += [
            "",
            "Device security posture flags",
            "-" * 90,
            f"Unencrypted sample count: {len(m.get('unencrypted_devices', []) or [])}",
            f"Jailbreak/root sample count: {len(m.get('jailbroken_devices', []) or [])}",
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

        # Intune tables
        if hasattr(self, "intune_noncompliant_table"):
            self.clear_table(self.intune_noncompliant_table)
            for d in (m.get("noncompliant_devices", []) or [])[:500]:
                self.insert_table_row(self.intune_noncompliant_table, [
                    "👤  " + str(d.get("name", "unknown")),
                    self._decorate_os_cell(d.get("os", "")),
                    d.get("user", ""),
                    d.get("compliance", ""),
                    short_ts(d.get("last_sync", "")),
                ], tag="warn")

            self.clear_table(self.intune_stale_table)
            for d in (m.get("stale_devices", []) or [])[:500]:
                self.insert_table_row(self.intune_stale_table, [
                    "🥖  " + str(d.get("name", "unknown")),
                    self._decorate_os_cell(d.get("os", "")),
                    d.get("last_sync_days", ""),
                    d.get("user", ""),
                    short_ts(d.get("last_sync", "")),
                ], tag="warn")

            self.clear_table(self.intune_posture_table)
            for d in (m.get("unencrypted_devices", []) or [])[:300]:
                self.insert_table_row(self.intune_posture_table, [
                    "🔑  Unencrypted",
                    "👤  " + str(d.get("name", "unknown")),
                    self._decorate_os_cell(d.get("os", "")),
                    d.get("user", ""),
                    short_ts(d.get("last_sync", "")),
                ], tag="bad")
            for d in (m.get("jailbroken_devices", []) or [])[:200]:
                self.insert_table_row(self.intune_posture_table, [
                    "⚠  Jailbreak/root flag",
                    "👤  " + str(d.get("name", "unknown")),
                    self._decorate_os_cell(d.get("os", "")),
                    d.get("user", ""),
                    short_ts(d.get("last_sync", "")),
                ], tag="bad")

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
        uni_rows = [r for r in rows if str(r.get("source","")) == "UniFi"]

        if hasattr(self, "unifi_sites_table"):
            self.clear_table(self.unifi_sites_table)
            if not sites:
                self.insert_table_row(self.unifi_sites_table, ["No UniFi site rows returned", "", "", "", "", "", "", ""], tag="info")
            for s in sites[:500]:
                status = str(s.get("status", "VISIBLE")).upper()
                tag = self._unifi_status_tag(status)
                self.insert_table_row(self.unifi_sites_table, [
                    "📶  " + str(s.get("name", "UniFi site")),
                    self._decorate_unifi_status(status),
                    int(s.get("total", 0) or 0),
                    self._decorate_count_cell(s.get("online", 0), "online"),
                    self._decorate_count_cell(s.get("offline", 0), "offline"),
                    self._decorate_count_cell(s.get("degraded", 0), "degraded"),
                    int(s.get("unknown", 0) or 0),
                    s.get("detail", ""),
                ], tag=tag)

            self.clear_table(self.unifi_notes_table)
            self.insert_table_row(self.unifi_notes_table, [
                "INFO",
                "Polling source",
                f"/v1/sites + /v1/devices + /v1/hosts; hostId join; client probe: {m.get('unifi_client_note', 'not checked')}; traffic probe: {m.get('unifi_traffic_note', 'not checked')}",
            ], tag="info")
            if uni_rows:
                for r in uni_rows[:250]:
                    sev = str(r.get("severity", "INFO")).upper()
                    tag = self._event_visual_tag(sev, "UniFi", r.get("title", ""), r.get("detail", ""))
                    self.insert_table_row(self.unifi_notes_table, [
                        sev,
                        "📶  " + str(r.get("title", "")),
                        r.get("detail", ""),
                    ], tag=tag)
            else:
                self.insert_table_row(self.unifi_notes_table, ["INFO", "No UniFi connector notes returned", ""], tag="info")

        # Software / change focused cards
        for key, card in self.focus_cards["software"].items():
            val = m.get(key, 0)
            color = card["base"]
            hint = "live"
            if key == "new_software_count":
                color = AMBER if int(val or 0) > 0 else GREEN
                hint = "new to this local dashboard baseline"
            elif key == "detected_app_count":
                color = BLUE if int(val or 0) > 0 else MUTED
                hint = "apps returned/cached from Graph detectedApps"
            elif key == "detected_apps_source":
                color = BLUE if str(val or "").lower() not in ("", "unavailable") else AMBER
                hint = "Graph source: v1.0, beta, cache, empty or unavailable"
                if str(val or "").lower() == "unavailable":
                    color = ORANGE
                    hint = "detectedApps did not return usable data this run"
            elif key == "software_issue_state":
                raw = str(val or "ok").lower()
                if "429" in raw or "backoff" in raw:
                    val = "Throttled"
                    color = ORANGE
                    hint = "Microsoft Graph returned 429 for detectedApps"
                elif raw == "ok":
                    val = "OK"
                    color = GREEN
                    hint = "Graph detectedApps status"
                else:
                    val = "Check"
                    color = AMBER
                    hint = "Graph detectedApps status"
            card["value"].config(text=str(val)[:18], fg=color)
            card["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
            card["frame"].config(highlightbackground=color)

        if hasattr(self, "software_new_table"):
            self.clear_table(self.software_new_table)
            for app in (m.get("new_software", []) or [])[:5000]:
                self.insert_table_row(self.software_new_table, [
                    app.get("displayName", "Unknown app"),
                    app.get("version", ""),
                    app.get("publisher", ""),
                    app.get("deviceCount", 0),
                ], tag="warn")
            self.clear_table(self.software_all_table)
            for app in (m.get("detected_apps", []) or [])[:20000]:
                self.insert_table_row(self.software_all_table, [
                    app.get("displayName", "Unknown app"),
                    app.get("version", ""),
                    app.get("publisher", ""),
                    app.get("deviceCount", 0),
                ], tag="info")

        sw_lines = [
            f"Software detection source: Microsoft Graph deviceManagement/detectedApps ({m.get('detected_apps_source', 'unknown')})",
            "Important: Graph detectedApps usually does not include install timestamp and can be throttled/paged by Microsoft.",
            "Newly observed means: app/version/publisher was not present in this dashboard's previous local baseline.",
            "",
            f"Detected apps returned/cached this run: {m.get('detected_app_count', 0)}",
            f"Newly observed apps: {m.get('new_software_count', 0)}",
            f"Graph detail: {m.get('detected_apps_error', '') or 'none'}",
            "429 means Microsoft Graph is throttling detectedApps. This is a real Microsoft Graph response, not simulated dashboard data.",
            "If detected apps is 0 with a 429, this run did not get usable detectedApps data and no usable local cache was available.",
            "If count is exactly 1000, Graph may be returning a page/window or cached sample. This is not necessarily broken.",
            "",
            "Newly observed software",
            "-" * 100,
        ]
        if not m.get("new_software"):
            sw_lines.append("No newly observed apps since the local baseline was created.")
        for app in (m.get("new_software", []) or [])[:150]:
            sw_lines.append(f"{app.get('displayName','Unknown app'):<45} | {app.get('version',''):<18} | {app.get('publisher',''):<28} | devices {app.get('deviceCount', 0)}")
        sw_lines += ["", "Detected software inventory sample", "-" * 100]
        if not m.get("detected_apps"):
            sw_lines.append("No detected app inventory returned. Check Graph DeviceManagementManagedDevices.Read.All / DeviceManagementApps.Read.All permissions if needed.")
        for app in (m.get("detected_apps", []) or [])[:250]:
            sw_lines.append(f"{app.get('displayName','Unknown app'):<45} | {app.get('version',''):<18} | {app.get('publisher',''):<28} | devices {app.get('deviceCount', 0)}")
        self.set_text_widget(self.software_text, "\n".join(sw_lines))


    def draw_spark(self):
        if not hasattr(self, "canvas"):
            return
        self.canvas.delete("all")
        w = max(10, self.canvas.winfo_width())
        h = max(10, self.canvas.winfo_height())
        self.canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline="")
        current = self.spark[-1] if self.spark else 0
        line_color = RED if current >= 100 else AMBER if current >= 25 else BLUE if current > 0 else GREEN
        self.canvas.create_text(24, 24, anchor="w", text="Alert telemetry", fill=TEXT, font=(self.font_display, 15, "bold"))
        self.canvas.create_text(24, 52, anchor="w", text="Live active unresolved alert trend from Defender, Graph Security, and UniFi", fill=MUTED, font=(self.font_ui, 10))
        self.canvas.create_text(w - 24, 24, anchor="e", text=f"Current active unresolved alerts {int(current)}", fill=line_color, font=(self.font_ui, 11, "bold"))
        if len(self.spark) < 2:
            return
        left, top, right, bottom = 32, 84, w - 40, h - 30
        max_value = max(max(self.spark), 10)
        scale_top = max(10, int(((max_value + 24) // 25) * 25))
        for y in range(0, scale_top + 1, max(1, scale_top // 4)):
            yy = bottom - (y / max(scale_top, 1)) * (bottom - top)
            self.canvas.create_line(left, yy, right, yy, fill="#202B44")
            self.canvas.create_text(right + 6, yy, anchor="w", text=str(y), fill="#526078", font=(self.font_ui, 8))
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
