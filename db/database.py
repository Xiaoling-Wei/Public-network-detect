import sqlite3
import json
import os
from datetime import datetime


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "history.db")


class Database:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT,
                bssid TEXT,
                gateway_ip TEXT,
                gateway_mac TEXT,
                scan_time TEXT,
                score REAL,
                risk_level TEXT,
                results_json TEXT,
                ai_analysis TEXT,
                ai_recommendations TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        self.conn.commit()

    def save_scan(self, scan_data: dict) -> int:
        cur = self.conn.execute("""
            INSERT INTO scan_history
              (ssid, bssid, gateway_ip, gateway_mac, scan_time, score, risk_level,
               results_json, ai_analysis, ai_recommendations)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_data.get("ssid", "Unknown"),
            scan_data.get("bssid", ""),
            scan_data.get("gateway_ip", ""),
            scan_data.get("gateway_mac", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_data.get("score", 0),
            scan_data.get("risk_level", "未知"),
            json.dumps(scan_data.get("results", {}), ensure_ascii=False),
            scan_data.get("ai_analysis", ""),
            json.dumps(scan_data.get("ai_recommendations", []), ensure_ascii=False),
        ))
        self.conn.commit()
        return cur.lastrowid

    def get_history(self, limit: int = 50) -> list:
        rows = self.conn.execute(
            "SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["results"] = json.loads(d.pop("results_json", "{}"))
            d["ai_recommendations"] = json.loads(d.get("ai_recommendations", "[]"))
            result.append(d)
        return result

    def get_scan(self, scan_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scan_history WHERE id=?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["results"] = json.loads(d.pop("results_json", "{}"))
        d["ai_recommendations"] = json.loads(d.get("ai_recommendations", "[]"))
        return d

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, value)
        )
        self.conn.commit()

    def delete_scan(self, scan_id: int):
        self.conn.execute("DELETE FROM scan_history WHERE id=?", (scan_id,))
        self.conn.commit()

    def clear_history(self):
        self.conn.execute("DELETE FROM scan_history")
        self.conn.commit()

    def close(self):
        self.conn.close()
