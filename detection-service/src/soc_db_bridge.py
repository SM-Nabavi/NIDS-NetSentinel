import sys
import os
import json
import sqlite3

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "nids.db"))

def get_db(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def get_stats(db_path=DEFAULT_DB_PATH):
    if not os.path.exists(db_path):
        return {
            "total_flows": 0,
            "benign_flows": 0,
            "total_attacks": 0,
            "security_alerts": 0,
            "attack_distribution": {}
        }
    with get_db(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) AS total_flows FROM flows;")
        total_flows = c.fetchone()["total_flows"]
        c.execute("SELECT COUNT(*) AS total_attacks FROM detections WHERE is_malicious = 1;")
        total_attacks = c.fetchone()["total_attacks"]
        c.execute("""
            SELECT attack_type, COUNT(*) as count 
            FROM detections 
            GROUP BY attack_type 
            ORDER BY count DESC;
        """)
        attack_distribution = {row["attack_type"]: row["count"] for row in c.fetchall()}
        c.execute("SELECT COUNT(*) AS alert_count FROM v_security_alerts;")
        alerts = c.fetchone()["alert_count"]

        return {
            "total_flows": total_flows,
            "benign_flows": total_flows - total_attacks,
            "total_attacks": total_attacks,
            "security_alerts": alerts,
            "attack_distribution": attack_distribution
        }

def get_alerts(limit=50, db_path=DEFAULT_DB_PATH):
    if not os.path.exists(db_path):
        return []
    with get_db(db_path) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM v_security_alerts LIMIT ?;", (limit,))
        return [dict(r) for r in c.fetchall()]

def get_flows(limit=50, db_path=DEFAULT_DB_PATH):
    if not os.path.exists(db_path):
        return []
    with get_db(db_path) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT 
                f.id, f.flow_id, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol,
                f.duration_us, f.total_fwd_pkts, f.total_bwd_pkts, f.flow_bytes_s, f.flow_pkts_s,
                f.features_json,
                d.is_malicious, d.attack_type, d.confidence, d.severity, d.probabilities_json,
                f.created_at
            FROM flows f
            LEFT JOIN detections d ON f.flow_id = d.flow_id
            ORDER BY f.id DESC
            LIMIT ?;
        """, (limit,))
        rows = []
        for r in c.fetchall():
            item = dict(r)
            if item.get("features_json"):
                try:
                    item["features"] = json.loads(item["features_json"])
                except Exception:
                    item["features"] = {}
            if item.get("probabilities_json"):
                try:
                    item["probabilities"] = json.loads(item["probabilities_json"])
                except Exception:
                    item["probabilities"] = {}
            rows.append(item)
        return rows

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "stats"
    if action == "stats":
        print(json.dumps(get_stats()))
    elif action == "alerts":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        print(json.dumps(get_alerts(limit)))
    elif action == "flows":
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        print(json.dumps(get_flows(limit)))
