"""ShadowNet - HTML Report Generator"""
import os
import json
import base64
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    """Generates professional HTML pentest reports"""
    
    def __init__(self, target, findings, db=None):
        self.target = target
        self.findings = findings
        self.db = db
    
    def generate(self):
        """Generate a full HTML report"""
        hostname = self.target['hostname']
        safe_name = hostname.replace('://', '_').replace('/', '_').replace(':', '_')
        
        from .config import Config
        out_dir = Config.OUTPUT_DIR / safe_name
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # Count by severity
        sev_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in self.findings:
            sev_count[f.get('severity', 'info')] = sev_count.get(f.get('severity', 'info'), 0) + 1
        
        # Calculate risk score
        risk_score = min(10, (
            sev_count['critical'] * 9 +
            sev_count['high'] * 7 +
            sev_count['medium'] * 4 +
            sev_count['low'] * 1
        ) / max(1, len(self.findings)) * 2)
        risk_score = round(risk_score, 1)
        
        if risk_score >= 7:
            risk_level = "Critical"
            risk_color = "#ef4444"
        elif risk_score >= 4:
            risk_level = "High"
            risk_color = "#f97316"
        elif risk_score >= 2:
            risk_level = "Medium"
            risk_color = "#eab308"
        else:
            risk_level = "Low"
            risk_color = "#22c55e"
        
        # Build findings HTML
        findings_html = ""
        for i, f in enumerate(self.findings):
            sev = f.get('severity', 'info')
            sev_colors = {
                'critical': ('#ef4444', '#fef2f2'),
                'high': ('#f97316', '#fff7ed'),
                'medium': ('#eab308', '#fefce8'),
                'low': ('#3b82f6', '#eff6ff'),
                'info': ('#6b7280', '#f9fafb'),
            }
            color, bg = sev_colors.get(sev, ('#6b7280', '#f9fafb'))
            
            findings_html += f'''
            <div class="finding" style="border-left: 4px solid {color}; background: {bg};">
                <div class="finding-header">
                    <span class="severity" style="background: {color};">{sev.upper()}</span>
                    <h3>{f.get('title', 'Unknown')}</h3>
                    {f'<span class="cve">CVE: {f["cve_id"]}</span>' if f.get('cve_id') else ''}
                    {f'<span class="cvss">CVSS: {f["cvss"]}</span>' if f.get('cvss') else ''}
                </div>
                <div class="finding-body">
                    <p>{f.get('description', '')}</p>
                    {f'<pre>{f["detail"]}</pre>' if f.get('detail') else ''}
                    {f'<div class="remediation"><strong>Remediation:</strong> {f["remediation"]}</div>' if f.get('remediation') else ''}
                </div>
            </div>
            '''
        
        # Stats cards
        stats_cards = ""
        for sev, label in [('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Info')]:
            color = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6', 'info': '#6b7280'}[sev]
            stats_cards += f'''
            <div class="stat-card" style="border-bottom: 3px solid {color};">
                <div class="stat-num" style="color: {color};">{sev_count[sev]}</div>
                <div class="stat-label">{label}</div>
            </div>
            '''
        
        # Get timeline from DB
        timeline_rows = ""
        if self.db:
            stats = self.db.get_stats()
            scans = self.db.get_scans()
            for s in scans[:10]:
                timeline_rows += f'''
                <tr>
                    <td>{s.get('started_at', '')[:19]}</td>
                    <td>{s.get('module', '')}</td>
                    <td>{s.get('findings_count', 0)}</td>
                    <td>{s.get('status', '')}</td>
                </tr>
                '''
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowNet Report — {hostname}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0e17; color: #e2e8f0; line-height: 1.6; }}
.container {{ max-width: 1000px; margin: 0 auto; padding: 40px 24px; }}

.header {{ text-align: center; padding: 60px 0 40px; }}
.header h1 {{ font-size: 2.5em; background: linear-gradient(135deg, #ef4444, #f97316); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.header .hostname {{ color: #94a3b8; font-size: 1.2em; margin-top: 8px; }}
.header .date {{ color: #64748b; font-size: 0.85em; }}

.risk-badge {{ display: inline-flex; align-items: center; gap: 12px; margin-top: 20px; padding: 16px 32px; border-radius: 12px; background: #1e293b; border: 1px solid #334155; }}
.risk-badge .score {{ font-size: 2em; font-weight: 800; color: {risk_color}; }}
.risk-badge .level {{ font-size: 1em; font-weight: 600; color: {risk_color}; }}
.risk-badge .label {{ font-size: 0.75em; color: #64748b; }}

.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 30px 0; }}
.stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; text-align: center; }}
.stat-num {{ font-size: 2em; font-weight: 800; }}
.stat-label {{ font-size: 0.75em; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }}

table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th {{ text-align: left; padding: 12px 16px; background: #1e293b; font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
td {{ padding: 10px 16px; border-bottom: 1px solid #1e293b; font-size: 0.85em; }}

.section {{ margin: 40px 0; }}
.section h2 {{ font-size: 1.3em; color: #f1f5f9; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #334155; }}

.finding {{ border-radius: 8px; padding: 16px 20px; margin: 12px 0; }}
.finding-header {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 8px; }}
.finding-header h3 {{ font-size: 0.95em; color: #f1f5f9; flex: 1; }}
.severity {{ padding: 2px 8px; border-radius: 4px; font-size: 0.65em; font-weight: 700; color: #fff; letter-spacing: 0.05em; }}
.cve {{ font-family: monospace; font-size: 0.75em; color: #94a3b8; }}
.cvss {{ font-family: monospace; font-size: 0.75em; color: #94a3b8; }}
.finding-body p {{ font-size: 0.82em; color: #94a3b8; margin-bottom: 8px; }}
.finding-body pre {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-size: 0.75em; overflow-x: auto; color: #e2e8f0; margin: 8px 0; }}
.remediation {{ background: #0f172a; border-left: 3px solid #22c55e; padding: 8px 12px; border-radius: 4px; font-size: 0.82em; color: #94a3b8; }}

.footer {{ text-align: center; padding: 40px 0; color: #475569; font-size: 0.75em; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>ShadowNet Audit Report</h1>
        <div class="hostname">🔍 {hostname}</div>
        <div class="date">{datetime.now().strftime('%d %B %Y, %H:%M')}</div>
        <div class="risk-badge">
            <div>
                <div class="label">Risk Score</div>
                <div class="score">{risk_score}</div>
            </div>
            <div style="width:1px;height:40px;background:#334155;"></div>
            <div>
                <div class="label">Severity</div>
                <div class="level">{risk_level}</div>
            </div>
            <div style="width:1px;height:40px;background:#334155;"></div>
            <div>
                <div class="label">Findings</div>
                <div class="score">{len(self.findings)}</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Summary</h2>
        <div class="stats">{stats_cards}</div>
    </div>
    
    <div class="section">
        <h2>📄 Target Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Hostname</td><td>{hostname}</td></tr>
            <tr><td>Protocol</td><td>{self.target.get('protocol', 'http')}</td></tr>
            <tr><td>Port</td><td>{self.target.get('port', 80)}</td></tr>
            <tr><td>Type</td><td>{'IP' if any(c.isdigit() for c in hostname.split('.')[0]) else 'Domain'}</td></tr>
            <tr><td>Scan Date</td><td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>⚠️ Findings ({len(self.findings)})</h2>
        {findings_html if findings_html else '<p style="color: #64748b;">No findings to display.</p>'}
    </div>
    
    <div class="section">
        <h2>📋 Scan History</h2>
        <table>
            <tr><th>Date</th><th>Module</th><th>Findings</th><th>Status</th></tr>
            {timeline_rows if timeline_rows else '<tr><td colspan="4" style="text-align:center;color:#64748b;">No scan history</td></tr>'}
        </table>
    </div>
    
    <div class="footer">
        Generated by <strong>ShadowNet</strong> — Autonomous Red Team Engine<br>
        Built by pxdays · For authorized testing only
    </div>
</div>
</body>
</html>'''
        
        filepath = out_dir / f"report-{hostname}.html"
        with open(filepath, 'w') as f:
            f.write(html)
        
        return filepath

