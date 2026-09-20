import os
import sys
import json
import time
import sqlite3
import random
import threading

import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import socket
import soc_pipeline_mgr as pipeline_mgr
import retraining

# Paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(ROOT_DIR, "data", "nids.db")
STATIC_DIR = os.path.join(ROOT_DIR, "dist")
LOG_FILE = os.path.join(ROOT_DIR, "data", "pipeline.log")

MODELS_DIR = os.path.join(ROOT_DIR, "detection-service", "models")


def build_filter_conditions(params):
    """
    Build a SQL WHERE clause and argument list from dashboard filter params.

    Returns:
        (where_clause: str, where_args: list)
    """
    conditions = []
    args = []

    # time_range
    time_range = params.get("time_range")
    if time_range and time_range != "all":
        now = time.time()
        if time_range == "15m":
            cutoff = now - 15 * 60
        elif time_range == "1h":
            cutoff = now - 3600
        elif time_range == "24h":
            cutoff = now - 86400
        elif time_range == "7d":
            cutoff = now - 7 * 86400
        else:
            cutoff = None
        if cutoff is not None:
            conditions.append("f.created_at >= ?")
            args.append(cutoff)

    # src_ip
    src_ip = params.get("src_ip")
    if src_ip:
        conditions.append("f.src_ip LIKE ?")
        args.append(f"%{src_ip}%")

    # dst_ip
    dst_ip = params.get("dst_ip")
    if dst_ip:
        conditions.append("f.dst_ip LIKE ?")
        args.append(f"%{dst_ip}%")

    # category
    category = params.get("category")
    if category == "threats":
        conditions.append("d.is_malicious = 1")
    elif category == "benign":
        conditions.append("(d.is_malicious IS NULL OR d.is_malicious = 0)")

    interface = params.get("interface")
    if interface and interface != "all":
        conditions.append("f.interface = ?")
        args.append(interface)

    where_clause = " AND ".join(conditions) if conditions else "1=1"
    return where_clause, args
def get_model_info():
    """
    Lightweight status endpoint for the System Management tab: reports
    whether model artifacts exist and their basic metadata, WITHOUT loading
    the actual LightGBM model/scaler into memory on every request (that is
    expensive and is already done once by main.py's own process).
    """
    def _file_info(path):
        if not os.path.exists(path):
            return {"exists": False}
        stat = os.stat(path)
        return {
            "exists": True,
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
        }

    file_map = {
        "lightgbm_nids_model.pkl": os.path.join(MODELS_DIR, "lightgbm_nids_model.pkl"),
        "lightgbm_nids_model.txt": os.path.join(MODELS_DIR, "lightgbm_nids_model.txt"),
        "standard_scaler.pkl": os.path.join(MODELS_DIR, "standard_scaler.pkl"),
        "label_mapping.json": os.path.join(MODELS_DIR, "label_mapping.json"),
        "features_spec.json": os.path.join(MODELS_DIR, "features_spec.json"),
    }

    details = {name: _file_info(path) for name, path in file_map.items()}

    # The dashboard's Model Files card reads `models` as a flat array of
    # display strings (see dashboard.html: `models.models?.length` /
    # `models.models.map(...)`). Returning only the detailed per-file object
    # below (as an earlier version of this endpoint did) left that array
    # missing, so the card always showed "No model files found." even when
    # every artifact was present and loaded fine by main.py.
    models_list = [
        f"{name} ({info['size_bytes']:,} bytes)"
        for name, info in details.items()
        if info.get("exists")
    ]

    info = {
        "models": models_list,
        "models_dir": MODELS_DIR,
        "details": details,
    }

    label_mapping_path = os.path.join(MODELS_DIR, "label_mapping.json")
    if os.path.exists(label_mapping_path):
        try:
            with open(label_mapping_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                info["num_classes"] = len(data.get("id_to_label", {}))
        except Exception:
            info["num_classes"] = None

    features_spec_path = os.path.join(MODELS_DIR, "features_spec.json")
    if os.path.exists(features_spec_path):
        try:
            with open(features_spec_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                info["num_features"] = len(data.get("feature_names", []))
        except Exception:
            info["num_features"] = None

    return info

def get_logs_by_file(limit=200):
    """
    Per-file log tails for the dashboard's log viewer, keyed by the real
    log filename (not the flat/merged shapes that /api/pipeline/logs and
    /api/system/logs/all already return and that other consumers may rely
    on -- this is a new, separate helper so those two are left untouched).
    """
    files = {
        "pipeline_manager.log": pipeline_mgr.LOG_FILE_PIPELINE,
        "flow_capture.log": pipeline_mgr.LOG_FILE_CAPTURE,
        "buffer_writer.log": pipeline_mgr.LOG_FILE_BUFFER,
        "main_processor.log": pipeline_mgr.LOG_FILE_MAIN,
    }
    return {name: pipeline_mgr.get_logs(limit, log_file=path) for name, path in files.items()}

SEVERITY_MAP = {
    "SSH-BruteForce": "LOW",
    "DoS Slowloris": "MEDIUM",
    "Botnet Ares": "HIGH",
    "DoS GoldenEye": "HIGH",
    "DoS Hulk": "HIGH",
    "DDoS-LOIC-UDP": "CRITICAL",
    "DDoS-LOIC-HTTP": "CRITICAL",
    "DDoS-HOIC": "CRITICAL"
}

FEATURE_NAMES = [
    "Bwd IAT Mean", "Bwd IAT Min", "Bwd IAT Std", "Bwd IAT Total",
    "Bwd PSH Flags", "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "CWR Flag Count", "Down/Up Ratio", "ECE Flag Count", "FIN Flag Count",
    "Flow Bytes/s", "Flow Duration", "Flow IAT Max", "Flow IAT Mean",
    "Flow IAT Std", "Flow Packets/s", "Fwd Avg Bulk Rate", "Fwd IAT Max",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Total", "Fwd PSH Flags",
    "Fwd Packet Length Max", "Fwd Packet Length Mean", "Fwd RST Flags",
    "Fwd Seg Size Min", "Init Bwd Win Bytes", "Init Fwd Win Bytes",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "RST Flag Count", "SYN Flag Count", "Subflow Fwd Packets",
    "Total Backward Packets", "Total Fwd Packets", "Total TCP Flow Time"
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_stats(params=None):
    params = params or {}
    if not os.path.exists(DB_PATH):
        return {"total_flows": 0, "benign_flows": 0, "total_attacks": 0, "security_alerts": 0, "attack_distribution": {}}

    where_clause, where_args = build_filter_conditions(params)

    with get_db() as conn:
        c = conn.cursor()
        c.execute(f"""
            SELECT COUNT(*) AS total_flows
            FROM flows f
            LEFT JOIN detections d ON f.flow_id = d.flow_id
            WHERE {where_clause}
        """, where_args)
        total_flows = c.fetchone()["total_flows"]

        c.execute(f"""
            SELECT COUNT(*) AS total_attacks
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.is_malicious = 1 AND {where_clause}
        """, where_args)
        total_attacks = c.fetchone()["total_attacks"]

        c.execute(f"""
            SELECT d.attack_type, COUNT(*) as count
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.is_malicious = 1 AND {where_clause}
            GROUP BY d.attack_type
            ORDER BY count DESC
        """, where_args)
        attack_distribution = {row["attack_type"]: row["count"] for row in c.fetchall()}

        c.execute(f"""
            SELECT COUNT(*) AS alert_count
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.is_malicious = 1 AND {where_clause}
        """, where_args)
        alerts = c.fetchone()["alert_count"]

        return {
            "total_flows": total_flows,
            "benign_flows": total_flows - total_attacks,
            "total_attacks": total_attacks,
            "security_alerts": alerts,
            "attack_distribution": attack_distribution
        }


def get_alerts(limit=50, offset=0, params=None):
    params = params or {}
    if not os.path.exists(DB_PATH):
        return []
    where_clause, where_args = build_filter_conditions(params)
    with get_db() as conn:
        c = conn.cursor()
        c.execute(f"""
            SELECT f.flow_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol,
                   f.interface,
                   d.attack_type, d.confidence, d.severity, d.inserted_at AS detected_at,
                   f.flow_pkts_s
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.is_malicious = 1 AND {where_clause}
            ORDER BY d.inserted_at DESC
            LIMIT ? OFFSET ?
        """, where_args + [limit, offset])
        return [dict(r) for r in c.fetchall()]

def get_flows(limit=50, offset=0, params=None):
    params = params or {}
    if not os.path.exists(DB_PATH):
        return {"flows": [], "total": 0}
    where_clause, where_args = build_filter_conditions(params)
    with get_db() as conn:
        c = conn.cursor()
        c.execute(f"""
            SELECT COUNT(*) AS total
            FROM flows f
            LEFT JOIN detections d ON f.flow_id = d.flow_id
            WHERE {where_clause}
        """, where_args)
        total = c.fetchone()["total"]

        c.execute(f"""
            SELECT
                f.id, f.flow_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol,
                f.duration_us, f.total_fwd_pkts, f.total_bwd_pkts, f.flow_bytes_s, f.flow_pkts_s,
                f.features_json, f.interface,
                d.is_malicious, d.attack_type, d.confidence, d.severity, d.probabilities_json,
                f.created_at
            FROM flows f
            LEFT JOIN detections d ON f.flow_id = d.flow_id
            WHERE {where_clause}
            ORDER BY f.id DESC
            LIMIT ? OFFSET ?
        """, where_args + [limit, offset])
        rows = []
        for r in c.fetchall():
            item = dict(r)
            if item.get("features_json"):
                try: item["features"] = json.loads(item["features_json"])
                except Exception: item["features"] = {}
            if item.get("probabilities_json"):
                try: item["probabilities"] = json.loads(item["probabilities_json"])
                except Exception: item["probabilities"] = {}
            rows.append(item)
        return {"flows": rows, "total": total}

def simulate_flow(attack_type="DDoS-HOIC"):
    src = f"{random.randint(45, 198)}.{random.randint(10, 240)}.{random.randint(1, 250)}.{random.randint(2, 254)}"
    dst = "10.0.0.1"
    dst_port = 22 if "SSH" in attack_type else 80
    src_port = random.randint(32000, 64000)

    features = {f: round(random.uniform(0.0, 5.0), 2) for f in FEATURE_NAMES}

    if attack_type == "DDoS-HOIC":
        features["Flow Packets/s"] = round(random.uniform(35000.0, 95000.0), 2)
        features["Flow Bytes/s"] = round(random.uniform(2500000.0, 6000000.0), 2)
        features["Total Fwd Packets"] = random.randint(4500, 15000)
        conf = round(random.uniform(0.97, 0.998), 4)
    elif attack_type == "SSH-BruteForce":
        dst_port = 22
        features["Total Fwd Packets"] = random.randint(90, 320)
        features["Flow Packets/s"] = round(random.uniform(650.0, 3200.0), 2)
        conf = round(random.uniform(0.91, 0.975), 4)
    else:
        features["Flow Packets/s"] = round(random.uniform(15.0, 650.0), 2)
        conf = round(random.uniform(0.92, 0.99), 4)

    is_malicious = 0 if attack_type == "Benign" else 1
    severity = SEVERITY_MAP.get(attack_type, "INFO")
    flow_id = f"{src}:{src_port}-{dst}:{dst_port}-6"
    now_us = int(time.time() * 1000000)

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO flows (
                flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                start_time_us, end_time_us, duration_us, total_fwd_pkts, total_bwd_pkts,
                flow_bytes_s, flow_pkts_s, features_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            flow_id, src, dst, src_port, dst_port, 6,
            now_us - 15000, now_us, 15000, int(features.get("Total Fwd Packets", 10)),
            10, float(features.get("Flow Bytes/s", 1000.0)), float(features.get("Flow Packets/s", 100.0)),
            json.dumps(features)
        ))
        cur.execute("""
            INSERT INTO detections (
                flow_id, is_malicious, attack_type, class_id, confidence, severity, probabilities_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (
            flow_id, is_malicious, attack_type, 1 if is_malicious else 0, conf, severity,
            json.dumps({attack_type: conf, "Benign" if is_malicious else "DDoS-HOIC": round(1.0 - conf, 4)})
        ))
        conn.commit()

    return {
        "flow_id": flow_id, "src_ip": src, "dst_ip": dst,
        "src_port": src_port, "dst_port": dst_port,
        "attack_type": attack_type, "is_malicious": bool(is_malicious),
        "confidence": conf, "severity": severity, "features": features
    }

class NIDSServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # The browser tab closed / navigated away / a periodic polling
            # request was cancelled mid-response, so the socket is already
            # gone. Not a server error -- swallow it instead of letting it
            # crash the request-handling thread with a traceback.
            pass

    def parse_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            raw = self.rfile.read(length).decode("utf-8")
            try: return json.loads(raw)
            except Exception: return {}
        return {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/health":
            return self.send_json({"status": "healthy", "engine": "Python Standard Library (Pure)", "db_exists": os.path.exists(DB_PATH)})
        elif path == "/api/stats":
            params = {k: v[0] if v else None for k, v in query.items()}
            return self.send_json(get_stats(params))
        elif path == "/api/alerts":
            limit = int(query.get("limit", [50])[0])
            offset = int(query.get("offset", [0])[0])
            params = {k: v[0] if v else None for k, v in query.items()}
            alerts = get_alerts(limit, offset, params)
            return self.send_json({"alerts": alerts})
        elif path == "/api/flows":
            limit = int(query.get("limit", [60])[0])
            offset = int(query.get("offset", [0])[0])
            params = {k: v[0] if v else None for k, v in query.items()}
            result = get_flows(limit, offset, params)
            return self.send_json(result)
        elif path == "/api/interfaces":
            return self.send_json({"interfaces": get_interfaces()})
        elif path == "/api/pipeline/status":
            status = pipeline_mgr.get_status()  
            return self.send_json(status)
        elif path == "/api/pipeline/logs":
            logs = pipeline_mgr.get_logs(60)    # <-- استفاده از تابع واقعی
            return self.send_json({"logs": logs})
        elif path == "/api/system/processes":
            state = pipeline_mgr._read_pid_state() or {}
            main_pid = state.get("main_pid")
            buffer_pid = state.get("buffer_pid")
            return self.send_json({
                "processes": [
                    {
                        "name": "main.py (detection service)",
                        "pid": main_pid,
                        "alive": pipeline_mgr._pid_alive(main_pid),
                    },
                    {
                        "name": "flow-capture.exe | buffer_writer.py",
                        "pid": buffer_pid,
                        "alive": pipeline_mgr._pid_alive(buffer_pid),
                    },
                ]
            })
        elif path == "/api/system/models":
            return self.send_json(get_model_info())
        elif path == "/api/system/logs/all":
            limit = int(query.get("limit", [200])[0])
            logs = pipeline_mgr.get_combined_logs(limit)
            return self.send_json({"logs": logs})
        elif path == "/api/system/logs/by-file":
            limit = int(query.get("limit", [200])[0])
            return self.send_json({"logs": get_logs_by_file(limit)})
        elif path == "/api/retraining/status":
            return self.send_json(retraining.get_retraining_status())
        elif path == "/api/retraining/data-stats":
            return self.send_json(retraining.get_training_data_stats())
        elif path == "/api/retraining/models":
            return self.send_json({"models": retraining.list_models()})

        # Favicon handling
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # Static SPA routing fallback
        if not path.startswith("/api/"):
            dist_index = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(dist_index):
                file_path = os.path.join(STATIC_DIR, path.lstrip("/"))
                if not os.path.exists(file_path) or os.path.isdir(file_path):
                    self.path = "/index.html"
                return super().do_GET()
            
            # Fallback to standalone embedded dashboard if dist is not compiled
            fallback_html = os.path.join(ROOT_DIR, "detection-service", "src", "dashboard.html")
            if os.path.exists(fallback_html):
                with open(fallback_html, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self.parse_body()

        if path == "/api/simulate":
            atype = body.get("attack_type", "DDoS-HOIC")
            res = simulate_flow(atype)
            return self.send_json({"success": True, "result": res})
        elif path == "/api/pipeline/start":
            iface = body.get("interface")

            if not iface:
                return self.send_json(
                    {"status": "error", "error": "No interface selected"},
                    400
                )
            valid_devices = {
                item.get("device")
                for item in get_interfaces()
                if item.get("device")
            }

            if iface not in valid_devices:
                return self.send_json(
                    {
                        "status": "error",
                        "error": "Invalid or unavailable capture interface"
                    },
                    400
                )

            result = pipeline_mgr.start_pipeline(iface)
            return self.send_json(result)
        elif path == "/api/pipeline/stop":
            result = pipeline_mgr.stop_pipeline()       
            return self.send_json(result)
        elif path == "/api/system/kill":
            pid = body.get("pid")
            if not pid:
                return self.send_json({"status": "error", "error": "No pid provided"}, 400)
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                return self.send_json({"status": "error", "error": "Invalid pid"}, 400)

            # Only ever kill a PID that this pipeline actually launched
            # (main_pid or buffer_pid from PID_FILE) -- never an arbitrary
            # PID sent by the browser. This is a safety boundary since the
            # dashboard passes whatever the /api/system/processes list
            # showed, which itself only ever lists those two PIDs.
            state = pipeline_mgr._read_pid_state() or {}
            allowed_pids = {state.get("main_pid"), state.get("buffer_pid")}
            if pid not in allowed_pids:
                return self.send_json(
                    {"status": "error", "error": "PID is not a managed pipeline process"},
                    400
                )

            pipeline_mgr._kill_pid_tree(pid, f"manual-kill-{pid}")
            return self.send_json({"status": "killed", "pid": pid})
        elif path == "/api/system/shutdown":
            # Stop the capture/buffer/main pipeline synchronously first (if
            # it is running), so nothing is left orphaned once this process
            # exits.
            pipeline_mgr.stop_pipeline()
            self.send_json({"status": "shutting_down"})

            def _exit_soon():
                time.sleep(0.3)  # let the response above actually flush
                os._exit(0)

            threading.Thread(target=_exit_soon, daemon=True).start()
            return
        elif path == "/api/retraining/start":
            limit = int(body.get("sample_limit", 10000))
            test_size = float(body.get("test_size", 0.2))
            threshold = float(body.get("label_threshold", 0.8))
            force = bool(body.get("force", False))
            model_name = body.get("model_name", "")
            result = retraining.start_retraining(limit, test_size, threshold, force, model_name)
            return self.send_json(result)
        elif path == "/api/retraining/switch":
            version = body.get("version")
            if not version:
                return self.send_json({"status": "error", "error": "Missing version"}, 400)
            result = retraining.set_active_model(version)
            return self.send_json(result)
        elif path == "/api/retraining/stop":
            result = retraining.stop_retraining()
            return self.send_json(result)
        
        self.send_error(404, "Not Found")




def get_interfaces():
    """
    Enumerate Windows network interfaces using Scapy.

    Dashboard:
        - label       -> description (preferred) / friendly fallback

    Backend:
        - index       -> Windows interface index
        - friendly    -> Windows friendly adapter name
        - description -> adapter description
        - guid        -> Windows adapter GUID
        - device      -> real Npcap/libpcap network_name
        - mac         -> MAC address
        - ips         -> IPv4/IPv6 addresses

    IMPORTANT:
        'description' is for display only.
        'device' is the value passed to flow-capture.exe -i.
    """

    interfaces = []

    try:
        from scapy.all import conf
        from scapy.arch.windows import get_windows_if_list

        # Windows adapter information
        windows_ifaces = get_windows_if_list()

        # Scapy's interface table contains the actual libpcap/Npcap
        # network_name when Npcap/libpcap is available.
        try:
            scapy_ifaces = conf.ifaces
        except Exception:
            scapy_ifaces = {}

        # Build a GUID -> real Npcap device mapping.
        #
        # Example:
        #   {GUID} -> \\Device\\NPF_{GUID}
        pcap_devices = {}

        try:
            for _, dev in scapy_ifaces.items():
                guid = getattr(dev, "guid", None)
                network_name = getattr(dev, "network_name", None)

                if guid and network_name:
                    pcap_devices[str(guid).lower()] = network_name
        except Exception:
            pass

        # Also inspect Scapy's libpcap cache when available.
        try:
            cache = getattr(conf, "cache_pcapiflist", {}) or {}

            for network_name in cache.keys():
                network_name = str(network_name)

                if "{" in network_name and "}" in network_name:
                    guid_part = network_name[
                        network_name.find("{"):
                        network_name.find("}") + 1
                    ]

                    pcap_devices[guid_part.lower()] = network_name
        except Exception:
            pass

        # Names that normally indicate virtual/filter/non-physical
        # adapters which are not useful as the primary NIDS capture NIC.
        virtual_keywords = (
            "loopback",
            "npcap loopback",
            "hyper-v",
            "vmware",
            "virtualbox",
            "wintun",
            "wireguard",
            "tap-windows",
            "docker",
            "vethernet",
            "wan miniport",
        )

        for iface in windows_ifaces:
            friendly = str(iface.get("name") or "").strip()
            description = str(iface.get("description") or "").strip()
            guid = str(iface.get("guid") or "").strip()
            index = iface.get("index")

            mac = str(iface.get("mac") or "").strip()

            ips = iface.get("ips") or []
            if not isinstance(ips, list):
                ips = [str(ips)]

            # Skip interfaces without useful Windows identity.
            if not friendly and not description:
                continue

            # Find the real Npcap/libpcap device.
            device = None

            if guid:
                device = pcap_devices.get(guid.lower())

            # Some Scapy versions may expose the network name directly.
            if not device:
                try:
                    for _, dev in scapy_ifaces.items():
                        dev_guid = str(
                            getattr(dev, "guid", "") or ""
                        ).lower()

                        if guid and dev_guid == guid.lower():
                            device = getattr(
                                dev,
                                "network_name",
                                None
                            )
                            if device:
                                break
                except Exception:
                    pass

            # If Scapy/libpcap gave us no capture device,
            # do NOT invent one here.
            #
            # The C engine needs a real Npcap device.
            if not device:
                continue

            search_text = f"{friendly} {description}".lower()

            # Ignore obvious virtual/filter adapters.
            if any(keyword in search_text for keyword in virtual_keywords):
                continue

            # Prefer description for dashboard display.
            label = description or friendly or f"Interface {index}"

            interfaces.append({
                "id": index,
                "index": index,
                "label": label,

                # Human-readable Windows names
                "friendly": friendly,
                "description": description,

                # Windows identity
                "guid": guid,

                # IMPORTANT:
                # This is the value that must reach pcap_open_live().
                "device": device,

                "mac": mac,
                "ips": ips,
            })

        # Sort by Windows interface index.
        interfaces.sort(
            key=lambda x: (
                x["index"] is None,
                x["index"] if x["index"] is not None else 999999
            )
        )

        return interfaces

    except ImportError as e:
        print(f"[interfaces ERROR] Scapy is not available: {e}")

    except Exception as e:
        print(f"[interfaces ERROR] Failed to enumerate interfaces: {e}")

    return []


def run_server(port=3000):
    print("=" * 60)
    print(f"🚀 NIDS NetSentinel SOC Server running on http://127.0.0.1:{port}")
    print("✅ Built entirely with Python Standard Library (No FastAPI / Node required)")
    print("=" * 60)
    server = ThreadingHTTPServer(("0.0.0.0", port), NIDSServerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    run_server(port)