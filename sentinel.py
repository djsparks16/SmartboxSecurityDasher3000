
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
        "microsoft": {"tenant_id": "", "client_id": "", "client_secret": "", "enabled": False},
        "unifi": {"base_url": "https://api.ui.com", "api_key": "", "site_id": "", "enabled": False},
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
        defender_alerts_url = "https://api.securitycenter.microsoft.com/api/alerts?$top=100"

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
            events.append({
                "severity": "medium",
                "title": "Microsoft Defender alert query failed",
                "detail": defender_alert_error[:180],
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

        graph_high = [
            a for a in graph_alerts
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]
        defender_high = [
            a for a in defender_alerts
            if str(a.get("severity", "")).lower() in ("high", "critical")
        ]

        # Defender signal feed first, then Graph security, then inventory.
        for a in defender_alerts[:6]:
            sev = str(a.get("severity", "medium")).lower()
            status = a.get("status") or a.get("classification") or "unknown"
            device = a.get("computerDnsName") or a.get("machineId") or "unknown device"
            events.append({
                "severity": "critical" if sev in ("high", "critical") else "medium" if sev == "medium" else "info",
                "title": a.get("title", "Microsoft Defender alert"),
                "detail": f"{device} | {status} | {a.get('category', 'Defender')}",
                "source": "Defender for Endpoint",
            })

        for a in graph_alerts[:5]:
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
                "detail": f"{len(defender_alerts)} Defender alert(s), {len(defender_high)} high/critical.",
                "source": "Defender for Endpoint",
            })

        total_alerts = len(graph_alerts) + len(defender_alerts)
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
            "alerts": total_alerts,
            "defender_alerts": len(defender_alerts),
            "graph_alerts": len(graph_alerts),
            "critical": total_critical,
            "events": events,
        }


class UniFiConnector:
    def __init__(self, cfg):
        self.cfg = cfg

    def enabled(self):
        c = self.cfg["unifi"]
        return c.get("enabled") and c.get("base_url") and c.get("api_key")

    def fetch(self):
        if not self.enabled():
            return None
        c = self.cfg["unifi"]
        base = c["base_url"].rstrip("/")
        headers = {"X-API-KEY": c["api_key"], "Accept": "application/json"}
        # The official UniFi API surface is expanding; keep endpoint configurable by version.
        path = "/proxy/network/integration/v1/sites"
        sites = Http.request("GET", base + path, headers=headers)
        items = sites.get("data") or sites.get("value") or sites.get("sites") or []
        return {
            "source": "UniFi",
            "live": True,
            "sites": len(items) if isinstance(items, list) else 1,
            "devices": 0,
            "wan_health": 0,
            "events": [{
                "severity": "info",
                "title": "UniFi controller reachable",
                "detail": f"{len(items) if isinstance(items, list) else 1} site object(s) returned",
                "source": "UniFi",
            }],
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

    def correlate(self, results, errors):
        if not results:
            return {
                "timestamp": now_iso(),
                "metrics": {
                    "devices": 0,
                    "noncompliant": 0,
                    "alerts": 0,
                    "defender_alerts": 0,
                    "graph_alerts": 0,
                    "critical": 0,
                    "wan_health": 0,
                    "windows": 0,
                    "ios": 0,
                    "macos": 0,
                    "android": 0,
                    "other_os": 0,
                    "risk": 0,
                },
                "events": [
                    {
                        "severity": "info",
                        "title": "Waiting for live connector data",
                        "detail": "Open Setup connectors, enable at least one connector, and save.",
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
        defender_alerts = sum(int(r.get("defender_alerts", 0)) for r in results)
        graph_alerts = sum(int(r.get("graph_alerts", 0)) for r in results)
        critical = sum(int(r.get("critical", 0)) for r in results)
        windows = sum(int(r.get("windows", 0)) for r in results)
        ios = sum(int(r.get("ios", 0)) for r in results)
        macos = sum(int(r.get("macos", 0)) for r in results)
        android = sum(int(r.get("android", 0)) for r in results)
        other_os = sum(int(r.get("other_os", 0)) for r in results)
        wan = [int(r.get("wan_health")) for r in results if r.get("wan_health") not in (None, 0)]
        wan_health = int(sum(wan) / len(wan)) if wan else 0
        wan_penalty = (100 - wan_health) * 1.2 if wan_health else 0
        risk = clamp(int((noncompliant / max(devices, 1)) * 42 + alerts * 1.8 + critical * 18 + wan_penalty), 0, 100)
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
                "alerts": alerts,
                "defender_alerts": defender_alerts,
                "graph_alerts": graph_alerts,
                "critical": critical,
                "wan_health": wan_health,
                "windows": windows,
                "ios": ios,
                "macos": macos,
                "android": android,
                "other_os": other_os,
                "risk": risk,
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
        self.card(cards, 0, 0, "Risk score", "risk", BLUE)
        self.card(cards, 0, 1, "Active alerts", "alerts", RED)
        self.card(cards, 0, 2, "Compliant gap", "noncompliant", AMBER)
        self.card(cards, 1, 0, "Managed devices", "devices", GREEN)
        self.card(cards, 1, 1, "Critical", "critical", PURPLE)
        self.card(cards, 1, 2, "WAN health", "wan_health", BLUE)

        self.platform_bar = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground="#22304C")
        self.platform_bar.pack(fill="x", pady=(8, 0))
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


        self.canvas = tk.Canvas(left, bg=PANEL, highlightthickness=0, height=250)
        self.canvas.pack(fill="both", expand=True, pady=(18, 0))
        self.spark = []

        tk.Label(right, text="Signal feed", bg=BG, fg=TEXT, font=("Segoe UI Variable Display", 18, "bold")).pack(anchor="w")
        self.feed = tk.Frame(right, bg=BG)
        self.feed.pack(fill="both", expand=True, pady=(10, 0))

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill="x", pady=(12, 0))
        tk.Label(footer, textvariable=self.status_var, bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
        tk.Label(footer, text="Real connector mode only. No simulated telemetry is generated.", bg=BG, fg="#526078", font=("Segoe UI", 9)).pack(side="right")

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
        val = safe_float(val, 0)
        if key == "risk":
            if val >= 75:
                return RED, "critical risk"
            if val >= 50:
                return AMBER, "elevated risk"
            if val >= 25:
                return BLUE, "watching"
            return GREEN, "healthy"
        if key == "alerts":
            if val >= 25:
                return RED, "heavy alert load"
            if val >= 10:
                return AMBER, "investigate"
            if val > 0:
                return BLUE, "active"
            return GREEN, "clear"
        if key == "noncompliant":
            if val >= 10:
                return RED, "needs action"
            if val > 0:
                return AMBER, "drift detected"
            return GREEN, "fully compliant"
        if key == "critical":
            if val > 0:
                return RED, "immediate attention"
            return GREEN, "none"
        if key == "wan_health":
            if val <= 0:
                return MUTED, "no network source"
            if val < 90:
                return RED, "unstable"
            if val < 95:
                return AMBER, "degraded"
            if val < 98:
                return BLUE, "good"
            return GREEN, "excellent"
        if key == "devices":
            if val <= 0:
                return AMBER, "no visibility"
            return GREEN, "visible"
        return BLUE, "live"

    def overall_state(self, metrics):
        risk = safe_float(metrics.get("risk", 0), 0)
        critical = safe_float(metrics.get("critical", 0), 0)
        noncompliant = safe_float(metrics.get("noncompliant", 0), 0)
        alerts = safe_float(metrics.get("alerts", 0), 0)
        if critical > 0 or risk >= 75:
            return "CRITICAL", RED
        if risk >= 50 or noncompliant >= 10 or alerts >= 25:
            return "ELEVATED", AMBER
        if risk >= 25 or alerts > 0 or noncompliant > 0:
            return "WATCH", BLUE
        return "HEALTHY", GREEN

    def open_setup(self):
        win = tk.Toplevel(self)
        win.title("Sentinel setup")
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
        ])
        add_tab("UniFi", "unifi", [
            ("Base URL", "base_url", False),
            ("API key", "api_key", True),
            ("Site ID optional", "site_id", False),
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
        for key, val in m.items():
            suffix = "%" if key in ("risk", "wan_health") else ""
            if key in self.metric_labels:
                color, hint = self.metric_style(key, val)
                self.metric_labels[key].config(text=f"{val}{suffix}", fg=color)
                self.metric_cards[key]["hint"].config(text=hint, fg=color if color != GREEN else "#8FD7B9")
                self.metric_cards[key]["frame"].config(highlightbackground=color)

        for key, label in self.platform_labels.items():
            label.config(text=str(m.get(key, 0)))

        for key, label in self.alert_breakdown_labels.items():
            label.config(text=str(m.get(key, 0)))

        state_text, state_color = self.overall_state(m)
        live = ", ".join(payload["sources"]["live"]) or "none"
        self.state_badge.config(text=state_text, fg=state_color)
        self.state_detail.config(text=f"Risk {m.get('risk', 0)}% • Devices {m.get('devices', 0)} • Defender {m.get('defender_alerts', 0)} • Graph {m.get('graph_alerts', 0)} • Win {m.get('windows', 0)} • iOS/iPadOS {m.get('ios', 0)} • Mac {m.get('macos', 0)}")
        self.live_badge.config(text=f"LIVE: {live.upper()}", fg=GREEN if live != "none" else MUTED)

        self.spark.append(m["risk"])
        self.spark = self.spark[-80:]
        self.draw_spark()

        for child in self.feed.winfo_children():
            child.destroy()

        sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sev_color = {"critical": RED, "high": RED, "medium": AMBER, "info": BLUE, "low": GREEN}
        sev_bg = {"critical": "#26111A", "high": "#26111A", "medium": "#241E11", "info": "#131C2D", "low": "#102019"}
        events = sorted(payload["events"][:10], key=lambda e: sev_priority.get(str(e.get("severity", "info")).lower(), 9))
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

        self.status_var.set(f"Updated {dt.datetime.now().strftime('%H:%M:%S')} | state: {state_text.lower()} | live: {live} | alerts: {m.get('alerts', 0)} | non-compliant: {m.get('noncompliant', 0)}")

    def draw_spark(self):
        self.canvas.delete("all")
        w = max(10, self.canvas.winfo_width())
        h = max(10, self.canvas.winfo_height())
        self.canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline="")
        current = self.spark[-1] if self.spark else 0
        line_color, state_text = self.metric_style("risk", current)
        self.canvas.create_text(24, 24, anchor="w", text="Risk telemetry", fill=TEXT, font=("Segoe UI Variable Display", 18, "bold"))
        self.canvas.create_text(24, 52, anchor="w", text="Correlation engine: endpoint compliance + network health + security alerts", fill=MUTED, font=("Segoe UI", 10))
        self.canvas.create_text(w - 24, 24, anchor="e", text=f"Current risk {int(current)}%", fill=line_color, font=("Segoe UI", 11, "bold"))
        if len(self.spark) < 2:
            return
        left, top, right, bottom = 32, 84, w - 40, h - 30
        for y in range(0, 101, 25):
            yy = bottom - (y / 100) * (bottom - top)
            self.canvas.create_line(left, yy, right, yy, fill="#202B44")
            self.canvas.create_text(right + 6, yy, anchor="w", text=str(y), fill="#526078", font=("Segoe UI", 8))
        pts = []
        for i, v in enumerate(self.spark):
            x = left + (i / max(1, len(self.spark) - 1)) * (right - left)
            y = bottom - (v / 100) * (bottom - top)
            pts.extend([x, y])
        self.canvas.create_line(*pts, fill=line_color, width=3, smooth=True)
        x, y = pts[-2], pts[-1]
        self.canvas.create_oval(x-6, y-6, x+6, y+6, fill=line_color, outline="")


def main():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    main()
