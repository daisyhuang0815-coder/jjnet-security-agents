import json
import urllib.request

incident_payload = {
    'rawAlert': '''[Palo Alto Threat Prevention & Cortex XDR Alert]
Log ID: PA-LOG-20260916-89421
Event Name: Palo Alto Threat Prevention: Suspicious Inbound Exploit & Web Shell Execution
PA Severity: Critical
PA Action: reset-both / block-url
Rule: SecRule-Inbound-DMZ-Protect
App-ID: web-browsing / ssl / powershell
Src: 185.220.101.5:54322 (Zone: untrust-external, Geo: Netherlands / Tor Exit Node)
Dst: 192.168.20.105:443 (Zone: trust-dmz, Host: WS-FIN-088.corp.jjnet.tw, User: daisy.wang@jjnet.com.tw)
Hit Count: 14 次連續探測
Time Range: 2026-09-16T22:14:10Z - 2026-09-16T22:16:01Z
Primary Evidence: POST /wp-content/plugins/formidable/classes/api.php with base64 encoded payload & CVE-2022-45806 exploit pattern.
File Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Host Status: Host isolated automatically by Cortex XDR agent at 22:16:01Z.'''
}

req = urllib.request.Request('http://127.0.0.1:8787/api/incident', data=json.dumps(incident_payload).encode(), headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())['data']

incId = data.get('incidentId', 'INC-2026-0042')
custName = data.get('customerName', 'JJNET Demo Customer')
title = data.get('title', 'Security Incident Report')
sev = data.get('severity', 'High')
detTime = data.get('detectionTime', '2026-09-16 22:14 UTC')
ver = data.get('reportVersion', '1.0')
execSummary = data.get('executiveSummary') or data.get('summary') or ''

md = f'''MANAGED DETECTION & RESPONSE
# SECURITY INCIDENT REPORT
## 事件應變與調查報告

| Incident ID | {incId} |
| Customer | {custName} |
| Report Title | {title} |
| Severity | {sev} |
| Detection Time | {detTime} |
| Report Version | {ver} |

---

## 01 Executive Summary

{execSummary}

## 02 Classification and Scope

| Classification | Value |
| :--- | :--- |
'''
for c in data.get('classification', []):
    md += f"| {c['label']} | {c['value']} |\n"

md += '''
## 03 Affected Assets

| Asset | Business / Security Context |
| :--- | :--- |
'''
for a in data.get('affectedAssets', []):
    md += f"| {a['name']} | {a['context']} |\n"

md += '''
## 04 MITRE ATT&CK Mapping

| Technique ID | Technique Name |
| :--- | :--- |
'''
for m in data.get('mitreTechniques', []):
    md += f"| {m['id']} | {m['name']} |\n"

md += '''
## 05 Evidence

| Time | Source | Observation |
| :--- | :--- | :--- |
'''
for e in data.get('evidence', []):
    md += f"| {e['time']} | {e['source']} | {e['observation']} |\n"

md += '''
## 06 Incident Timeline

| Time | Event |
| :--- | :--- |
'''
for t in data.get('timeline', []):
    md += f"| {t['time']} | {t['event']} |\n"

md += '''
## 07 Response Actions

| # | Action | Status |
| :--- | :--- | :--- |
'''
for a in data.get('responseActions', []):
    md += f"| {a['number']} | {a['action']} | {a['status']} |\n"

md += '''
## 08 Recommendations

| Priority | Recommendation |
| :--- | :--- |
'''
for r in data.get('recommendations', []):
    md += f"| {r['priority']} | {r['recommendation']} |\n"

md += '''
## 09 Unresolved Items / Pending Confirmation

| # | Item | Required Evidence |
| :--- | :--- | :--- |
'''
for u in data.get('unresolvedItems', []):
    md += f"| {u['number']} | {u['item']} | {u['evidence']} |\n"

md += '''
## 10 Revision History

| Version | Date | Author | Change |
| :--- | :--- | :--- | :--- |
'''
for rv in data.get('revisionHistory', []):
    md += f"| {rv['version']} | {rv['date']} | {rv['author']} | {rv['change']} |\n"

appr = data.get('reviewApproval', {})
md += f'''
## 11 Review and Approval

| Label | Value | Label | Value |
| :--- | :--- | :--- | :--- |
| Prepared by | {appr.get('preparedBy')} | Prepared at | {appr.get('preparedAt')} |
| Reviewed by | {appr.get('reviewedBy')} | Reviewed at | {appr.get('reviewedAt')} |
| Approval status | {appr.get('approvalStatus')} | Signature / record | {appr.get('approvalRecord')} |
'''

out_path = 'INC-20260916-89421.md'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(md)

print('Markdown file generated successfully! Total lines:', len(md.splitlines()))
