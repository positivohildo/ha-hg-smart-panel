#!/usr/bin/env python3
"""
HG Smart Home Panel - Local Security & Optimization Gateway
Intermediário local entre o tablet antigo (ZH960 KitKat) e o Home Assistant.

Recursos:
1. Isola credenciais: o token do Home Assistant reside apenas neste servidor.
2. Whitelist estrita de entidades autorizadas (luzes, câmeras, sensores).
3. Cache em memória de snapshots de câmeras e redimensionamento opcional.
4. Autenticação por token Bearer entre o tablet e este gateway.
5. Encaminhamento seguro de despertar físico do painel (/wake).
"""

import sys
import os
import json
import time
import hmac
import urllib.request
import urllib.error
import urllib.parse
import http.client
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import io
import threading
from datetime import datetime

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Handler HTTPS customizado para Home Assistant local com verificação estrita de TLS Let's Encrypt
class LocalHA_HTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # Conecta diretamente ao IP local 172.30.0.2 na porta 8123 para desempenho e resiliência LAN
        self.sock = self._create_connection(("172.30.0.2", 8123), self.timeout, self.source_address)
        # Aplica TLS estrito com SNI para beltramini.duckdns.org e validação completa da cadeia CA
        self.sock = self._context.wrap_socket(self.sock, server_hostname="beltramini.duckdns.org")

class LocalHA_HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(LocalHA_HTTPSConnection, req, context=self._context)

# Registra opener global com suporte TLS e CA confiável
ssl_context = ssl.create_default_context()
urllib.request.install_opener(urllib.request.build_opener(LocalHA_HTTPSHandler(context=ssl_context)))

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
CONFIG_EXAMPLE_PATH = os.path.join(os.path.dirname(__file__), "config.json.example")
LAYOUT_PATH = os.path.join(os.path.dirname(__file__), "panel_layout.json")
_LAST_CONFIG_MTIME = 0
_LAST_LAYOUT_MTIME = 0
CONFIG = {}
LAYOUT = {}
WHITELIST = set()
PANEL_KEY = ""
LUMIA_KEY = "hg-lumia-9a81cd68e4c4fc59592f8b88b8e25313"
HA_URL = ""
HA_TOKEN = ""
CACHE_SECONDS = 2
TABLET_URL = ""
TABLET_SECRET = ""

def check_and_reload_config():
    global _LAST_CONFIG_MTIME, _LAST_LAYOUT_MTIME, CONFIG, LAYOUT, WHITELIST, PANEL_KEY, LUMIA_KEY, HA_URL, HA_TOKEN, CACHE_SECONDS, TABLET_URL, TABLET_SECRET
    reloaded = False

    # 1. Suporte a Home Assistant Add-on nativo (Supervisor Token e Options)
    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if supervisor_token:
        HA_URL = "http://supervisor/core"
        HA_TOKEN = supervisor_token
        if not PANEL_KEY:
            PANEL_KEY = "hg-panel-7a41bc57d3b3fb49481f7a77a7e14202"

    options_path = "/data/options.json"
    if os.path.exists(options_path):
        try:
            with open(options_path, "r", encoding="utf-8") as f:
                opts = json.load(f)
                if opts.get("panel_api_key"):
                    PANEL_KEY = opts["panel_api_key"]
                if opts.get("lumia_api_key"):
                    LUMIA_KEY = opts["lumia_api_key"]
                if opts.get("cache_snapshot_seconds"):
                    CACHE_SECONDS = int(opts["cache_snapshot_seconds"])
        except Exception as e:
            print(f"[!] Erro ao ler /data/options.json: {e}")

    # 2. Arquivo de configuração config.json ou config.json.example (se existir)
    target = None
    if os.path.exists(CONFIG_PATH):
        target = CONFIG_PATH
    elif os.path.exists(CONFIG_EXAMPLE_PATH):
        target = CONFIG_EXAMPLE_PATH

    if target and os.path.exists(target):
        try:
            mtime = os.path.getmtime(target)
            if mtime != _LAST_CONFIG_MTIME:
                with open(target, "r", encoding="utf-8") as f:
                    CONFIG = json.load(f)
                _LAST_CONFIG_MTIME = mtime
                for ent in CONFIG.get("whitelist_entities", []):
                    WHITELIST.add(ent)
                if not PANEL_KEY and CONFIG.get("panel_api_key"):
                    PANEL_KEY = CONFIG.get("panel_api_key")
                if not supervisor_token and CONFIG.get("ha_url"):
                    HA_URL = CONFIG.get("ha_url", "").rstrip("/")
                    HA_TOKEN = CONFIG.get("ha_token", "")
                CACHE_SECONDS = CONFIG.get("cache_snapshot_seconds", CACHE_SECONDS)
                TABLET_URL = CONFIG.get("tablet_url", "")
                TABLET_SECRET = CONFIG.get("tablet_wake_secret", "")
                reloaded = True
        except Exception as e:
            print(f"[!] Erro ao ler {target}: {e}")

    # 3. Carregar Layout e preencher Whitelist
    if os.path.exists(LAYOUT_PATH):
        try:
            lmtime = os.path.getmtime(LAYOUT_PATH)
            if lmtime != _LAST_LAYOUT_MTIME:
                with open(LAYOUT_PATH, "r", encoding="utf-8") as f:
                    LAYOUT = json.load(f)
                _LAST_LAYOUT_MTIME = lmtime
                for r in LAYOUT.get("rooms", []):
                    for ent in r.get("entities", []):
                        WHITELIST.add(ent["entity_id"])
                for cam in LAYOUT.get("cameras", []):
                    WHITELIST.add(cam["entity_id"])
                if LAYOUT.get("motion_sensor"):
                    WHITELIST.add(LAYOUT["motion_sensor"])
                reloaded = True
        except Exception as e:
            print(f"[!] Erro ao ler {LAYOUT_PATH}: {e}")

    # Câmeras essenciais garantidas na whitelist
    default_cameras = [
        "camera.ds_7216hghi_k1_cvbs1620220509ccwrj72747326wcvu_1901",
        "camera.poste_vip5450_mediaprofile_channel1_substream1",
        "camera.poste_vip5450_mediaprofile_channel1_mainstream",
        "camera.ds_7216hghi_k1_cvbs1620220509ccwrj72747326wcvu_2301",
        "camera.ds_7216hghi_k1_cvbs1620220509ccwrj72747326wcvu_2001",
        "camera.poste",
        "camera.portao",
        "camera.frente",
        "camera.fundos"
    ]
    for cam in default_cameras:
        WHITELIST.add(cam)
    WHITELIST.add("scene.desligar_tudo")

    if reloaded:
        print(f"[*] Configuração carregada com sucesso. Whitelist: {len(WHITELIST)} entidades | HA Alvo: {HA_URL}")

check_and_reload_config()

# Cache de snapshots: entity_id -> (timestamp, bytes)
SNAPSHOT_CACHE = {}


# ---------------------------------------------------------------------------
# Temporizador da Airfryer (roda no gateway: continua mesmo se o tablet reiniciar)
# ---------------------------------------------------------------------------
AIRFRYER_ENTITY = "switch.modulo_zigbee_1"
AIRFRYER_MAX_MIN = 60
DATA_DIR = "/data" if os.path.isdir("/data") else os.path.dirname(os.path.abspath(__file__))
AIRFRYER_STATE_FILE = os.path.join(DATA_DIR, "airfryer_state.json")
_AF_LOCK = threading.Lock()
_AF = {
    "end": 0.0,
    "started_at": 0.0,
    "total": 0,
    "last_duration": 0,
    "switch_on": False,
    "cmd_at": 0.0,
    "timer": None,
}


def ha_call_service(domain, service, data):
    req = urllib.request.Request(
        f"{HA_URL}/api/services/{domain}/{service}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Authorization": f"Bearer {HA_TOKEN}", "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req, timeout=8) as resp:
        resp.read()


def _af_save():
    try:
        with open(AIRFRYER_STATE_FILE, "w") as f:
            json.dump({
                "end": _AF["end"],
                "started_at": _AF["started_at"],
                "total": _AF["total"],
                "last_duration": _AF["last_duration"],
            }, f)
    except Exception as e:
        print(f"[!] Falha ao salvar estado da airfryer: {e}")


def _af_alexa_announce():
    msg = "Atenção! O tempo da Airfryer terminou. A tomada foi desligada."
    attempts = (
        ("notify", "alexa_media_alexa_sala", {"message": msg, "data": {"type": "announce"}}),
        ("notify", "alexa_media", {"target": ["media_player.alexa_sala"], "message": msg, "data": {"type": "announce"}}),
        ("notify", "send_message", {"entity_id": "notify.alexa_sala_announce", "message": msg}),
    )
    for domain, svc, payload in attempts:
        try:
            ha_call_service(domain, svc, payload)
            print(f"[*] Alexa da Sala avisada com sucesso via {domain}.{svc}")
            return
        except Exception as e:
            print(f"[!] {domain}.{svc} falhou: {e}")


def _af_finish():
    with _AF_LOCK:
        if _AF["end"] <= 0:
            return
        now = time.time()
        dur = int(now - _AF["started_at"]) if _AF["started_at"] > 0 else int(_AF["total"])
        _AF["last_duration"] = max(1, dur)
        _AF["end"] = 0.0
        _AF["started_at"] = 0.0
        _AF["switch_on"] = False
        _AF["cmd_at"] = now
        _AF["timer"] = None
        _af_save()
    print(f"[*] Tempo da airfryer terminou ({dur}s): desligando tomada e avisando Alexa da Sala")
    try:
        ha_call_service("switch", "turn_off", {"entity_id": AIRFRYER_ENTITY})
    except Exception as e:
        print(f"[!] ERRO ao desligar airfryer: {e} (nova tentativa em 3s)")
        time.sleep(3)
        try:
            ha_call_service("switch", "turn_off", {"entity_id": AIRFRYER_ENTITY})
        except Exception as e2:
            print(f"[!] ERRO ao desligar airfryer (2a tentativa): {e2}")
    _af_alexa_announce()


def _af_schedule(seconds):
    t = threading.Timer(max(0.1, seconds), _af_finish)
    t.daemon = True
    _AF["timer"] = t
    t.start()


def airfryer_start(minutes):
    minutes = int(minutes)
    if minutes < 1 or minutes > AIRFRYER_MAX_MIN:
        raise ValueError(f"minutos deve estar entre 1 e {AIRFRYER_MAX_MIN}")
    ha_call_service("switch", "turn_on", {"entity_id": AIRFRYER_ENTITY})
    now = time.time()
    with _AF_LOCK:
        if _AF["timer"]:
            _AF["timer"].cancel()
        if not _AF["switch_on"] or _AF["started_at"] <= 0:
            _AF["started_at"] = now
        _AF["switch_on"] = True
        _AF["cmd_at"] = now
        _AF["total"] = minutes * 60
        _AF["end"] = now + minutes * 60
        _af_save()
        _af_schedule(minutes * 60)


def airfryer_add(minutes):
    now = time.time()
    with _AF_LOCK:
        if _AF["end"] <= 0:
            raise ValueError("airfryer não está com timer ativo")
        new_end = _AF["end"] + int(minutes) * 60
        if new_end - now > AIRFRYER_MAX_MIN * 60:
            raise ValueError(f"máximo de {AIRFRYER_MAX_MIN} min")
        if new_end <= now + 5:
            new_end = now + 60
        _AF["end"] = new_end
        _AF["total"] = max(60, _AF["total"] + int(minutes) * 60)
        if _AF["timer"]:
            _AF["timer"].cancel()
        _af_save()
        _af_schedule(new_end - now)


def airfryer_stop():
    now = time.time()
    with _AF_LOCK:
        if _AF["timer"]:
            _AF["timer"].cancel()
        _AF["timer"] = None
        if _AF["started_at"] > 0:
            _AF["last_duration"] = max(1, int(now - _AF["started_at"]))
        _AF["end"] = 0.0
        _AF["started_at"] = 0.0
        _AF["switch_on"] = False
        _AF["cmd_at"] = now
        _af_save()
    ha_call_service("switch", "turn_off", {"entity_id": AIRFRYER_ENTITY})


def _af_sync_from_ha_item(item):
    """Sincroniza estado real da tomada no HA (tempo ligada e desligamento manual externo)."""
    is_on = (item.get("state") == "on")
    ha_changed_ts = 0.0
    lc = item.get("last_changed")
    if lc:
        try:
            ha_changed_ts = datetime.fromisoformat(lc.replace("Z", "+00:00")).timestamp()
        except Exception:
            ha_changed_ts = 0.0
    now = time.time()
    with _AF_LOCK:
        grace = (now - _AF["cmd_at"]) < 6.0
        if is_on:
            _AF["switch_on"] = True
            if _AF["started_at"] <= 0:
                _AF["started_at"] = ha_changed_ts if ha_changed_ts > 0 else now
                _af_save()
        else:
            if not grace:
                if _AF["switch_on"] and _AF["started_at"] > 0:
                    _AF["last_duration"] = max(1, int(now - _AF["started_at"]))
                _AF["switch_on"] = False
                _AF["started_at"] = 0.0
                if _AF["end"] > 0:
                    if _AF["timer"]:
                        _AF["timer"].cancel()
                    _AF["timer"] = None
                    _AF["end"] = 0.0
                    print("[*] Airfryer desligada manualmente fora do timer: temporizador cancelado")
                _af_save()


def airfryer_status():
    now = time.time()
    with _AF_LOCK:
        rem = int(round(_AF["end"] - now)) if _AF["end"] > 0 else 0
        active = rem > 0
        sw_on = bool(_AF["switch_on"] or active)
        elapsed = int(now - _AF["started_at"]) if (sw_on and _AF["started_at"] > 0) else 0
        return {
            "active": active,
            "switch_on": sw_on,
            "remaining_seconds": max(0, rem),
            "elapsed_seconds": max(0, elapsed),
            "total_seconds": _AF["total"],
            "last_duration_seconds": _AF.get("last_duration", 0),
            "max_minutes": AIRFRYER_MAX_MIN,
        }


def airfryer_restore():
    try:
        with open(AIRFRYER_STATE_FILE) as f:
            st = json.load(f)
        _AF["last_duration"] = int(st.get("last_duration", 0))
        end = float(st.get("end", 0))
        if end > 0:
            _AF["end"] = end
            _AF["started_at"] = float(st.get("started_at", time.time()))
            _AF["total"] = int(st.get("total", 0))
            _AF["switch_on"] = True
            _af_schedule(end - time.time())
            print(f"[*] Timer da airfryer restaurado ({int(end - time.time())}s restantes)")
    except Exception:
        pass


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class GatewayRequestHandler(BaseHTTPRequestHandler):
    server_version = "HG-Gateway/0.2.0"

    def log_message(self, format, *args):
        # Log limpo sem credenciais
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def is_authenticated(self):
        if not PANEL_KEY and not LUMIA_KEY:
            return True
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header[7:].strip()
        if PANEL_KEY and hmac.compare_digest(token, PANEL_KEY):
            return True
        if LUMIA_KEY and hmac.compare_digest(token, LUMIA_KEY):
            return True
        return False

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        check_and_reload_config()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Health check público
        if path == "/health":
            self.send_json(200, {
                "status": "healthy",
                "version": "0.2.0",
                "pil_available": HAS_PIL,
                "whitelist_count": len(WHITELIST),
                "ha_configured": bool(HA_TOKEN and not HA_TOKEN.startswith("INSIRA_"))
            })
            return

        # Validação de token Bearer para endpoints da API
        if not self.is_authenticated():
            self.send_json(401, {"error": "Unauthorized", "message": "Chave de painel inválida ou ausente"})
            return

        if path == "/api/panel/airfryer":
            self.send_json(200, airfryer_status())
            return

        # Layout dos Cômodos e Câmeras
        if path == "/api/panel/layout":
            self.send_json(200, LAYOUT)
            return

        # Estados simplificados
        if path == "/api/panel/states":
            self.handle_states()
            return

        # Snapshot de Câmera
        if path == "/api/panel/camera/snapshot":
            entity_id = query.get("entity_id", [""])[0]
            is_thumb = query.get("thumb", ["0"])[0] == "1" or query.get("width", ["640"])[0] == "320"
            self.handle_camera_snapshot(entity_id, is_thumb)
            return

        self.send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        check_and_reload_config()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if not self.is_authenticated():
            self.send_json(401, {"error": "Unauthorized", "message": "Chave de painel inválida ou ausente"})
            return

        if path.startswith("/api/panel/airfryer/"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
                action = path.rsplit("/", 1)[1]
                if action == "start":
                    airfryer_start(body.get("minutes", 0))
                elif action == "add":
                    airfryer_add(body.get("minutes", 0))
                elif action == "stop":
                    airfryer_stop()
                else:
                    self.send_json(404, {"error": "Not Found"})
                    return
                self.send_json(200, airfryer_status())
            except ValueError as e:
                self.send_json(400, {"error": "BadRequest", "details": str(e)})
            except Exception as e:
                self.send_json(502, {"error": "HA_Error", "details": str(e)})
            return

        if path == "/api/panel/toggle":
            self.handle_toggle()
            return

        if path == "/api/panel/wake":
            self.handle_wake()
            return

        self.send_json(404, {"error": "Not Found", "path": path})

    def handle_states(self):
        if not HA_TOKEN or HA_TOKEN.startswith("INSIRA_"):
            fake_entities = [
                {"entity_id": "light.sala_test_light_35", "state": "on", "name": "Luz Sala", "room": "Sala", "favorite": True},
                {"entity_id": "light.cozinha_2", "state": "off", "name": "Luz Cozinha", "room": "Cozinha", "favorite": True},
                {"entity_id": "light.modulo_sotao_l4", "state": "off", "name": "Luz Sótão", "room": "Sótão", "favorite": True},
                {"entity_id": "light.luzes_frente", "state": "on", "name": "Luzes Frente", "room": "Área Externa", "favorite": True},
                {"entity_id": "binary_sensor.presenca_sala", "state": "off", "name": "Presença Sala", "room": "Sala", "favorite": False}
            ]
            self.send_json(200, {"entities": fake_entities, "mock": True})
            return

        req = urllib.request.Request(
            f"{HA_URL}/api/states",
            headers={"Authorization": f"Bearer {HA_TOKEN}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            
            # Mapeamento rápido de entidades para sala e favorito
            meta = {}
            for r in LAYOUT.get("rooms", []):
                rname = r.get("name", "Geral")
                rid = r.get("id", "")
                for ent in r.get("entities", []):
                    meta[ent["entity_id"]] = {
                        "room": rname,
                        "room_id": rid,
                        "name": ent.get("name"),
                        "favorite": ent.get("favorite", False)
                    }

            filtered = []
            for item in data:
                eid = item.get("entity_id")
                if eid == AIRFRYER_ENTITY:
                    _af_sync_from_ha_item(item)
                if eid in WHITELIST:
                    attrs = item.get("attributes", {})
                    m = meta.get(eid, {})
                    friendly = m.get("name") or attrs.get("friendly_name", eid)
                    filtered.append({
                        "entity_id": eid,
                        "state": item.get("state"),
                        "name": friendly,
                        "room": m.get("room", "Sem Ambiente"),
                        "room_id": m.get("room_id", "sem_ambiente"),
                        "favorite": m.get("favorite", False),
                        "unit_of_measurement": attrs.get("unit_of_measurement", ""),
                        "temperature": attrs.get("temperature"),
                        "current_temperature": attrs.get("current_temperature"),
                        "current_position": attrs.get("current_position"),
                        "hvac_modes": attrs.get("hvac_modes"),
                        "hvac_action": attrs.get("hvac_action")
                    })
            self.send_json(200, {"entities": filtered, "airfryer": airfryer_status()})
        except Exception as e:
            self.send_json(502, {"error": "HA_Error", "details": str(e)})

    def handle_toggle(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            entity_id = body.get("entity_id", "")
        except Exception:
            self.send_json(400, {"error": "Invalid JSON body"})
            return

        if entity_id not in WHITELIST:
            self.send_json(403, {"error": "Forbidden", "message": f"Entidade '{entity_id}' não autorizada na whitelist"})
            return

        if not HA_TOKEN or HA_TOKEN.startswith("INSIRA_"):
            # Resposta simulada
            self.send_json(200, {"status": "ok", "entity_id": entity_id, "mock": True})
            return

        domain = "light"
        service = "toggle"
        service_data = {"entity_id": entity_id}

        if entity_id.startswith("light."):
            action = body.get("action", "toggle")
            if action in ["turn_on", "turn_off", "toggle"]:
                service = action
        elif entity_id.startswith("switch."):
            domain = "switch"
            action = body.get("action", "toggle")
            service = action if action in ["turn_on", "turn_off"] else "toggle"
        elif entity_id.startswith("cover."):
            domain = "cover"
            action = body.get("action", "toggle")
            if action in ["open_cover", "open"]:
                service = "open_cover"
            elif action in ["close_cover", "close"]:
                service = "close_cover"
            elif action in ["stop_cover", "stop"]:
                service = "stop_cover"
            elif action in ["set_cover_position", "set_position"]:
                service = "set_cover_position"
                if "position" in body:
                    service_data["position"] = int(body["position"])
            else:
                service = "toggle"
        elif entity_id.startswith("lock."):
            domain = "lock"
            action = body.get("action", "")
            if action in ["lock", "unlock", "open"]:
                service = action
            else:
                current_st = body.get("current_state", "")
                service = "lock" if current_st == "unlocked" else "unlock"
        elif entity_id.startswith("button."):
            domain = "button"
            service = "press"
        elif entity_id.startswith("climate."):
            domain = "climate"
            action = body.get("action", "toggle")
            if action == "set_temperature":
                service = "set_temperature"
                if "temperature" in body:
                    service_data["temperature"] = float(body["temperature"])
            elif action == "set_hvac_mode":
                service = "set_hvac_mode"
                if "hvac_mode" in body:
                    service_data["hvac_mode"] = str(body["hvac_mode"])
            elif action == "turn_off":
                service = "set_hvac_mode"
                service_data["hvac_mode"] = "off"
            elif action == "turn_on":
                service = "set_hvac_mode"
                service_data["hvac_mode"] = body.get("hvac_mode", "cool")
            else:
                current_st = body.get("current_state", "off")
                service = "set_hvac_mode"
                service_data["hvac_mode"] = "off" if (current_st != "off" and current_st != "unavailable") else "cool"
        elif entity_id.startswith("scene."):
            domain = "scene"
            service = "turn_on"
        elif entity_id.startswith("script."):
            domain = "script"
            service = "turn_on"

        url = f"{HA_URL}/api/services/{domain}/{service}"
        req_data = json.dumps(service_data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "Authorization": f"Bearer {HA_TOKEN}",
                "Content-Type": "application/json"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp_data = resp.read()
            self.send_json(200, {"status": "ok", "entity_id": entity_id})
        except Exception as e:
            self.send_json(502, {"error": "HA_Error", "details": str(e)})

    def handle_camera_snapshot(self, entity_id, is_thumb=False):
        if not entity_id or entity_id not in WHITELIST:
            self.send_json(403, {"error": "Forbidden", "message": "Câmera não autorizada"})
            return

        cache_key = entity_id + (":thumb" if is_thumb else ":main")
        now = time.time()
        cached = SNAPSHOT_CACHE.get(cache_key)
        if cached and (now - cached[0] < CACHE_SECONDS):
            self.send_image(cached[1])
            return

        if not HA_TOKEN or HA_TOKEN.startswith("INSIRA_"):
            self.send_mock_image(entity_id)
            return

        url = f"{HA_URL}/api/camera_proxy/{entity_id}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {HA_TOKEN}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw_bytes = resp.read()

            final_bytes = raw_bytes
            if HAS_PIL and len(raw_bytes) > 0:
                try:
                    img = Image.open(io.BytesIO(raw_bytes))
                    target_width = 320 if is_thumb else 640
                    quality = 70 if is_thumb else 75
                    if img.width > target_width:
                        h = int(img.height * (target_width / img.width))
                        img = img.resize((target_width, h), Image.BILINEAR)
                        out = io.BytesIO()
                        img.convert("RGB").save(out, format="JPEG", quality=quality, optimize=True)
                        final_bytes = out.getvalue()
                except Exception as ex:
                    print(f"[!] Erro ao otimizar imagem: {ex}")
                    final_bytes = raw_bytes

            SNAPSHOT_CACHE[cache_key] = (now, final_bytes)
            self.send_image(final_bytes)
        except Exception as e:
            self.send_json(502, {"error": "Camera_Error", "details": str(e)})

    def send_image(self, img_bytes):
        self.send_response(200)
        self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(img_bytes)))
        self.send_header("Cache-Control", f"max-age={CACHE_SECONDS}")
        self.end_headers()
        self.wfile.write(img_bytes)

    def send_mock_image(self, entity_id):
        # 1x1 ou padrão cinza para modo mock
        # JPEG mínimo 1x1 cinza escuro
        dummy_jpeg = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
            0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
            0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
            0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20,
            0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
            0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
            0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F,
            0x00, 0xBF, 0x80, 0xFF, 0xD9
        ])
        self.send_image(dummy_jpeg)

    def handle_wake(self):
        if not TABLET_URL:
            self.send_json(400, {"error": "tablet_url não configurada"})
            return

        req = urllib.request.Request(
            TABLET_URL,
            headers={"X-HG-Wake-Secret": TABLET_SECRET},
            data=b""
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
            self.send_json(200, {"status": "ok", "tablet_response": body})
        except urllib.error.HTTPError as e:
            self.send_json(e.code, {"error": "Tablet_Error", "status": e.code, "msg": str(e)})
        except Exception as e:
            self.send_json(502, {"error": "Tablet_Unreachable", "details": str(e)})

def run_gateway():
    airfryer_restore()
    host = CONFIG.get("gateway_host", "0.0.0.0")
    port = CONFIG.get("gateway_port", 8090)
    server = ThreadedHTTPServer((host, port), GatewayRequestHandler)
    print("=" * 60)
    print("   HG Smart Home Panel - Security & Optimization Gateway")
    print("=" * 60)
    print(f"[*] Escutando em: http://{host}:{port}")
    print(f"[*] Home Assistant Alvo: {HA_URL}")
    print(f"[*] Tablet Wake Alvo: {TABLET_URL}")
    print(f"[*] Entidades na Whitelist: {len(WHITELIST)}")
    print(f"[*] Pillow ativo: {HAS_PIL}")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Encerrando gateway...")
        server.server_close()

if __name__ == "__main__":
    run_gateway()
