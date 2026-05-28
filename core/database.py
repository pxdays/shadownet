"""ShadowNet - Database Layer (SQLite)"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from threading import Lock

class Database:
    """Thread-safe SQLite database for scan results"""
    
    def __init__(self, db_path=None):
        from .config import Config
        self.db_path = db_path or Config.DB_PATH
        self.lock = Lock()
        self._init_db()
    
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn
    
    def _init_db(self):
        """Create tables if they don't exist"""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_scan TEXT,
                    total_scans INTEGER DEFAULT 0,
                    notes TEXT
                );
                
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    completed_at TEXT,
                    findings_count INTEGER DEFAULT 0,
                    summary TEXT,
                    FOREIGN KEY(target_id) REFERENCES targets(id)
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    severity TEXT DEFAULT 'info',
                    title TEXT NOT NULL,
                    description TEXT,
                    detail TEXT,
                    remediation TEXT,
                    cve_id TEXT,
                    cvss REAL,
                    raw_data TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );
                
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
            """)
    
    def add_target(self, target):
        """Register or get a target"""
        with self.lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO targets (target, first_seen) VALUES (?, ?)",
                    (target, datetime.now().isoformat())
                )
                row = conn.execute("SELECT id FROM targets WHERE target = ?", (target,)).fetchone()
                return row['id']
    
    def start_scan(self, target_id, module):
        """Record a new scan"""
        with self.lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "INSERT INTO scans (target_id, module, status, started_at) VALUES (?, ?, 'running', ?)",
                    (target_id, module, datetime.now().isoformat())
                )
                conn.execute(
                    "UPDATE targets SET last_scan = ?, total_scans = total_scans + 1 WHERE id = ?",
                    (datetime.now().isoformat(), target_id)
                )
                return cur.lastrowid
    
    def complete_scan(self, scan_id, findings_count=0, summary=""):
        """Mark scan as complete"""
        with self.lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE scans SET status = 'complete', completed_at = ?, findings_count = ?, summary = ? WHERE id = ?",
                    (datetime.now().isoformat(), findings_count, summary, scan_id)
                )
    
    def add_finding(self, scan_id, severity, title, description="", detail="", remediation="", cve_id="", cvss=0.0, raw_data=None):
        """Add a finding"""
        with self.lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    """INSERT INTO findings 
                    (scan_id, severity, title, description, detail, remediation, cve_id, cvss, raw_data) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, severity, title, description, detail, remediation, cve_id, cvss, 
                     json.dumps(raw_data) if raw_data else None)
                )
                return cur.lastrowid
    
    def get_target(self, target):
        """Get target info"""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM targets WHERE target = ?", (target,)).fetchone()
            return dict(row) if row else None
    
    def get_scans(self, target_id=None, limit=20):
        """Get recent scans"""
        with self._get_conn() as conn:
            if target_id:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE target_id = ? ORDER BY started_at DESC LIMIT ?",
                    (target_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
    
    def get_findings(self, scan_id=None, severity=None, limit=100):
        """Get findings with optional filters"""
        with self._get_conn() as conn:
            query = "SELECT f.*, t.target FROM findings f JOIN scans s ON f.scan_id = s.id JOIN targets t ON s.target_id = t.id"
            params = []
            conditions = []
            
            if scan_id:
                conditions.append("f.scan_id = ?")
                params.append(scan_id)
            if severity:
                conditions.append("f.severity = ?")
                params.append(severity)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY f.created_at DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
    
    def get_stats(self):
        """Get summary statistics"""
        with self._get_conn() as conn:
            stats = {}
            stats['total_targets'] = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            stats['total_scans'] = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            stats['total_findings'] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            stats['critical'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
            stats['high'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0]
            stats['medium'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='medium'").fetchone()[0]
            stats['low'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='low'").fetchone()[0]
            stats['info'] = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='info'").fetchone()[0]
            return stats

