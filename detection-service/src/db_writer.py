"""
NIDSDatabaseWriter - SQLite-backed crash-safe queue between buffer_writer.py
and main.py, plus the results sink used by main.py.
"""
import os
import sqlite3
import time
import json
from typing import List, Dict, Any, Optional

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_DB_PATH = os.path.join(DATA_DIR, "nids.db")
CLAIM_LEASE_SECONDS = 60.0

class NIDSDatabaseWriter:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")

    # ------------------------------------------------------------------
    # Producer side (buffer_writer.py)
    # ------------------------------------------------------------------
    def write_raw_batch(self, json_lines: List[str]):
        if not json_lines:
            return
        now = time.time()
        rows = [(line, "pending", now, None) for line in json_lines]
        with self._conn:
            self._conn.executemany(
                "INSERT INTO raw_flows (flow_json, status, received_at, claimed_at) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )

    # ------------------------------------------------------------------
    # Consumer side (main.py, --buffer mode)
    # ------------------------------------------------------------------
    def _reclaim_stale_claims(self):
        cutoff = time.time() - CLAIM_LEASE_SECONDS
        with self._conn:
            self._conn.execute(
                "UPDATE raw_flows SET status = 'pending', claimed_at = NULL "
                "WHERE status = 'processing' AND claimed_at < ?",
                (cutoff,),
            )

    def get_pending_raw_flows(self, limit: int = 500) -> List[Dict[str, Any]]:
        self._reclaim_stale_claims()
        now = time.time()
        claimed_rows: List[Dict[str, Any]] = []
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE;")
            try:
                cur = self._conn.execute(
                    "SELECT id, flow_json FROM raw_flows "
                    "WHERE status = 'pending' ORDER BY id LIMIT ?",
                    (limit,),
                )
                candidates = cur.fetchall()
                if not candidates:
                    self._conn.execute("COMMIT;")
                    return []
                ids = [row[0] for row in candidates]
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"UPDATE raw_flows SET status = 'processing', claimed_at = ? "
                    f"WHERE id IN ({placeholders})",
                    [now] + ids,
                )
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

        for row_id, flow_json in candidates:
            try:
                flow = json.loads(flow_json)
            except json.JSONDecodeError:
                self.mark_raw_processed([row_id])
                continue
            flow["_buffer_id"] = row_id
            claimed_rows.append(flow)
        return claimed_rows

    def mark_raw_processed(self, buffer_ids: List[int]):
        if not buffer_ids:
            return
        placeholders = ",".join("?" for _ in buffer_ids)
        with self._conn:
            self._conn.execute(
                f"UPDATE raw_flows SET status = 'processed' WHERE id IN ({placeholders})",
                buffer_ids,
            )

    # ------------------------------------------------------------------
    # Results sink (modified to include interface)
    # ------------------------------------------------------------------
    def insert_batch(self, results: List[Dict[str, Any]]):
        if not results:
            return
        now = time.time()
        with self._conn:
            for r in results:
                flow = r.get("flow", r)
                det = r.get("detection", {})

                features = flow.get("features", {})
                norm_map = {self._normalize_key(k): v for k, v in features.items()}

                duration_us = float(norm_map.get(self._normalize_key("Flow Duration"), 0))
                total_fwd = int(norm_map.get(self._normalize_key("Total Fwd Packets"), 0))
                total_bwd = int(norm_map.get(self._normalize_key("Total Backward Packets"), 0))
                flow_bytes_s = float(norm_map.get(self._normalize_key("Flow Bytes/s"), 0.0))
                flow_pkts_s = float(norm_map.get(self._normalize_key("Flow Packets/s"), 0.0))

                # extract interface from flow dict
                interface = flow.get("interface") or flow.get("net_interface") or None

                self._conn.execute("""
                    INSERT OR IGNORE INTO flows (
                        flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                        start_time_us, end_time_us, duration_us,
                        total_fwd_pkts, total_bwd_pkts, flow_bytes_s, flow_pkts_s,
                        features_json, interface
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get("flow_id"), flow.get("src_ip"), flow.get("dst_ip"),
                    flow.get("src_port"), flow.get("dst_port"), flow.get("protocol"),
                    flow.get("start_time_us"), flow.get("end_time_us"),
                    duration_us, total_fwd, total_bwd, flow_bytes_s, flow_pkts_s,
                    json.dumps(features),
                    interface
                ))

                self._conn.execute("""
                    INSERT OR REPLACE INTO detections (
                        flow_id, is_malicious, attack_type, class_id,
                        confidence, severity, probabilities_json, inserted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flow.get("flow_id"),
                    1 if det.get("is_malicious") else 0,
                    det.get("attack_type"), det.get("class_id"),
                    det.get("confidence"), det.get("severity"),
                    json.dumps(det.get("probabilities", {})),
                    now
                ))

    def init_database(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_flows (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_json    TEXT    NOT NULL,
                status       TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'processing', 'processed')),
                received_at  REAL    NOT NULL,
                claimed_at   REAL
            );
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_raw_flows_status_id
            ON raw_flows(status, id);
        """)

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT UNIQUE,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol INTEGER,
                start_time_us INTEGER,
                end_time_us INTEGER,
                duration_us INTEGER,
                total_fwd_pkts INTEGER,
                total_bwd_pkts INTEGER,
                flow_bytes_s REAL,
                flow_pkts_s REAL,
                features_json TEXT,
                interface TEXT,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT UNIQUE,
                is_malicious INTEGER,
                attack_type TEXT,
                class_id INTEGER,
                confidence REAL,
                severity TEXT,
                probabilities_json TEXT,
                inserted_at REAL
            );
        """)
        self._conn.execute("""
            CREATE VIEW IF NOT EXISTS v_security_alerts AS
            SELECT f.flow_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol,
                f.interface,
                d.attack_type, d.confidence, d.severity, d.inserted_at AS detected_at,
                f.flow_pkts_s
            FROM flows f
            JOIN detections d ON f.flow_id = d.flow_id
            WHERE d.is_malicious = 1
            ORDER BY d.inserted_at DESC;
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_flow_id ON flows(flow_id);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_flow_id ON detections(flow_id);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_malicious ON detections(is_malicious);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_inserted ON detections(inserted_at);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_flows_status ON raw_flows(status);")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_interface ON flows(interface);")

    def close(self):
        self._conn.close()

    def _normalize_key(self, k: str) -> str:
        return k.lower().replace(" ", "").replace("_", "").replace("/", "").replace("-", "")