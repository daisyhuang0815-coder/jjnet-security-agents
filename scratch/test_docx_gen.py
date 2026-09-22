import io
import os
import re
import zipfile

def escape_xml(val):
    s = str(val if val is not None else '')
    return (s.replace('&', '&amp;')
             .replace('<', '&lt;')
             .replace('>', '&gt;')
             .replace('"', '&quot;')
             .replace("'", '&apos;'))

def replace_token(xml, token, value):
    return xml.replace('{{' + token + '}}', escape_xml(value))

def expand_table_row(xml, marker_token, rows):
    pattern = re.compile(r'<w:tr\b[\s\S]*?</w:tr>')
    all_rows = pattern.findall(xml)
    template_row = None
    for r in all_rows:
        if ('{{' + marker_token + '}}') in r:
            template_row = r
            break
    if not template_row:
        raise ValueError(f'Template row not found for {marker_token}')
    
    expanded = []
    for rdata in rows:
        row_str = template_row
        for k, v in rdata.items():
            row_str = replace_token(row_str, k, v)
        row_str = re.sub(r'\{\{[A-Z0-9_]+\}\}', '', row_str)
        expanded.append(row_str)
    
    return xml.replace(template_row, ''.join(expanded), 1)

def render_incident_docx(template_path, report):
    with zipfile.ZipFile(template_path, 'r') as zin:
        doc_xml = zin.read('word/document.xml').decode('utf-8')

    values = {
        'INCIDENT_ID': report.get('incidentId', 'INC-PENDING'),
        'CUSTOMER_NAME': report.get('customerName', 'JJNET Enterprise Customer'),
        'TITLE': report.get('title', 'Security Incident Report'),
        'SEVERITY': report.get('severity', 'High'),
        'DETECTION_TIME': report.get('detectionTime', '2026-09-16 22:14:10 UTC'),
        'REPORT_VERSION': report.get('reportVersion', '1.0'),
        'EXECUTIVE_SUMMARY': report.get('executiveSummary', ''),
        'PREPARED_BY': report.get('preparedBy', 'SOC Analyst'),
        'PREPARED_AT': report.get('preparedAt', '2026-09-16T22:30:00Z'),
        'REVIEWED_BY': report.get('reviewedBy', 'Vincent (資深資安顧問 / SOC 主管)'),
        'REVIEWED_AT': report.get('reviewedAt', '2026-09-16T22:45:00Z'),
        'APPROVAL_STATUS': report.get('approvalStatus', 'Approved'),
        'APPROVAL_RECORD': report.get('approvalRecord', 'APR-2026-0042'),
    }
    for k, v in values.items():
        doc_xml = replace_token(doc_xml, k, v)

    # 02 Classification and Scope
    classification_rows = []
    for item in report.get('classification', []):
        if isinstance(item, dict):
            classification_rows.append({'CLASSIFICATION_LABEL': item.get('label', ''), 'CLASSIFICATION_VALUE': item.get('value', '')})
        else:
            sep = ':' if ':' in str(item) else ('|' if '|' in str(item) else '')
            if sep:
                parts = str(item).split(sep, 1)
                classification_rows.append({'CLASSIFICATION_LABEL': parts[0].strip(), 'CLASSIFICATION_VALUE': parts[1].strip()})
            else:
                classification_rows.append({'CLASSIFICATION_LABEL': 'Classification', 'CLASSIFICATION_VALUE': str(item)})
    if classification_rows:
        doc_xml = expand_table_row(doc_xml, 'CLASSIFICATION_LABEL', classification_rows)

    # 03 Affected Assets
    asset_rows = []
    for item in report.get('affectedAssets', []):
        if isinstance(item, dict):
            asset_rows.append({'ASSET_NAME': item.get('name', ''), 'ASSET_CONTEXT': item.get('context', '')})
        else:
            sep = '|' if '|' in str(item) else (':' if ':' in str(item) else '')
            if sep:
                parts = str(item).split(sep, 1)
                asset_rows.append({'ASSET_NAME': parts[0].strip(), 'ASSET_CONTEXT': parts[1].strip()})
            else:
                asset_rows.append({'ASSET_NAME': str(item), 'ASSET_CONTEXT': 'Corporate Asset'})
    if asset_rows:
        doc_xml = expand_table_row(doc_xml, 'ASSET_NAME', asset_rows)

    # 04 MITRE ATT&CK Mapping
    mitre_rows = []
    for item in report.get('mitreTechniques', []):
        if isinstance(item, dict):
            mitre_rows.append({'MITRE_ID': item.get('id', ''), 'MITRE_NAME': item.get('name', '')})
        else:
            m = re.search(r'(T\d+(?:\.\d+)?)\s*(?:\(([^)]+)\)|:\s*(.+)|-\s*(.+))?', str(item))
            if m:
                mid = m.group(1)
                mname = m.group(2) or m.group(3) or m.group(4) or 'Technique'
                mitre_rows.append({'MITRE_ID': mid, 'MITRE_NAME': mname.strip()})
            else:
                mitre_rows.append({'MITRE_ID': 'T1059', 'MITRE_NAME': str(item)})
    if mitre_rows:
        doc_xml = expand_table_row(doc_xml, 'MITRE_ID', mitre_rows)

    # 05 Evidence
    evidence_rows = []
    for item in report.get('evidence', []):
        if isinstance(item, dict):
            evidence_rows.append({
                'EVIDENCE_TIME': item.get('time', ''),
                'EVIDENCE_SOURCE': item.get('source', ''),
                'EVIDENCE_OBSERVATION': item.get('observation', '')
            })
        else:
            evidence_rows.append({
                'EVIDENCE_TIME': 'Detected',
                'EVIDENCE_SOURCE': 'SOC Telemetry',
                'EVIDENCE_OBSERVATION': str(item)
            })
    if evidence_rows:
        doc_xml = expand_table_row(doc_xml, 'EVIDENCE_TIME', evidence_rows)

    # 06 Timeline
    timeline_rows = []
    for item in report.get('timeline', []):
        if isinstance(item, dict):
            timeline_rows.append({'TIMELINE_TIME': item.get('time', item.get('timestamp', '')), 'TIMELINE_EVENT': item.get('event', '')})
        else:
            timeline_rows.append({'TIMELINE_TIME': 'N/A', 'TIMELINE_EVENT': str(item)})
    if timeline_rows:
        doc_xml = expand_table_row(doc_xml, 'TIMELINE_TIME', timeline_rows)

    # 07 Response Actions
    action_rows = []
    for idx, item in enumerate(report.get('responseActions', [])):
        if isinstance(item, dict):
            action_rows.append({
                'ACTION_NUMBER': str(idx + 1),
                'ACTION_TEXT': item.get('action', item.get('text', '')),
                'ACTION_STATUS': item.get('status', 'Completed / in progress')
            })
        else:
            action_rows.append({
                'ACTION_NUMBER': str(idx + 1),
                'ACTION_TEXT': str(item),
                'ACTION_STATUS': 'Completed / in progress'
            })
    if action_rows:
        doc_xml = expand_table_row(doc_xml, 'ACTION_NUMBER', action_rows)

    # 08 Recommendations
    rec_rows = []
    for idx, item in enumerate(report.get('recommendations', [])):
        prio = 'P1' if idx == 0 else ('P2' if idx < 3 else 'P3')
        if isinstance(item, dict):
            rec_rows.append({
                'RECOMMENDATION_PRIORITY': item.get('priority', prio),
                'RECOMMENDATION_TEXT': item.get('recommendation', item.get('text', ''))
            })
        else:
            rec_rows.append({
                'RECOMMENDATION_PRIORITY': prio,
                'RECOMMENDATION_TEXT': str(item)
            })
    if rec_rows:
        doc_xml = expand_table_row(doc_xml, 'RECOMMENDATION_PRIORITY', rec_rows)

    # 09 Unresolved Items
    unresolved_rows = []
    unresolved_list = report.get('unresolvedItems', [])
    if not unresolved_list:
        unresolved_list = ['Confirm whether the credential was reused on AD/DC Domain Controllers', 'External destination ownership verification']
    for idx, item in enumerate(unresolved_list):
        if isinstance(item, dict):
            unresolved_rows.append({
                'UNRESOLVED_NUMBER': str(idx + 1),
                'UNRESOLVED_ITEM': item.get('item', ''),
                'UNRESOLVED_EVIDENCE': item.get('evidence', 'Pending confirmation')
            })
        else:
            unresolved_rows.append({
                'UNRESOLVED_NUMBER': str(idx + 1),
                'UNRESOLVED_ITEM': str(item),
                'UNRESOLVED_EVIDENCE': 'Pending confirmation'
            })
    if unresolved_rows:
        doc_xml = expand_table_row(doc_xml, 'UNRESOLVED_NUMBER', unresolved_rows)

    # 10 Revision History
    rev_rows = [{
        'REVISION_VERSION': report.get('reportVersion', '1.0'),
        'REVISION_DATE': report.get('preparedAt', '2026-09-16T22:30:00Z'),
        'REVISION_AUTHOR': report.get('preparedBy', 'SOC Analyst'),
        'REVISION_CHANGE': 'Initial incident report'
    }]
    doc_xml = expand_table_row(doc_xml, 'REVISION_VERSION', rev_rows)

    # Clean leftover tokens
    doc_xml = re.sub(r'\{\{[A-Z0-9_]+\}\}', '', doc_xml)

    out_buf = io.BytesIO()
    with zipfile.ZipFile(template_path, 'r') as zin, zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == 'word/document.xml':
                zout.writestr(item, doc_xml.encode('utf-8'))
            else:
                zout.writestr(item, zin.read(item.filename))
    return out_buf.getvalue()

if __name__ == '__main__':
    tpl = r'C:\Users\Elodie\jjnet-security-agents\templates\JJNET_Incident_Report_Template.docx'
    test_report = {
        'incidentId': 'INC-2026-0042',
        'customerName': 'JJNET Demo Customer',
        'title': 'Suspicious Inbound Exploit & Web Shell Execution',
        'severity': 'Critical',
        'detectionTime': '2026-09-16 22:14:10 UTC',
        'reportVersion': '1.0',
        'executiveSummary': 'Palo Alto 防火牆與 Cortex XDR 偵測到外部惡意 IP 針對內部 DMZ 發動漏洞利用攻擊。主機已自動隔離，無橫向擴散跡象。',
        'classification': ['Category: Exploit', 'Status: Contained', 'Confidence: High'],
        'affectedAssets': ['WS-FIN-088.corp.jjnet.tw | Finance workstation (daisy.wang@jjnet.com.tw)'],
        'mitreTechniques': [
            {'id': 'T1059.001', 'name': 'Command and Scripting Interpreter: PowerShell'},
            {'id': 'T1055', 'name': 'Process Injection'},
            {'id': 'T1003.001', 'name': 'OS Credential Dumping: LSASS Memory'}
        ],
        'evidence': [
            {'time': '22:14:10', 'source': 'Palo Alto Firewall', 'observation': 'POST /wp-content/plugins/formidable/classes/api.php exploit pattern.'},
            {'time': '22:15:30', 'source': 'Cortex XDR', 'observation': 'WINWORD.EXE spawned obfuscated powershell.exe.'},
            {'time': '22:15:45', 'source': 'Network Telemetry', 'observation': 'Outbound beacon to 185.220.101.5 blocked.'},
            {'time': '22:16:01', 'source': 'EDR Agent', 'observation': 'Host WS-FIN-088 isolated.'}
        ],
        'timeline': [
            {'time': '22:14:10', 'event': 'Detection triggered.'},
            {'time': '22:15:30', 'event': 'PowerShell execution detected.'},
            {'time': '22:15:45', 'event': 'External C2 connection blocked.'},
            {'time': '22:16:01', 'event': 'Endpoint isolated.'}
        ],
        'responseActions': [
            '維持受害主機 WS-FIN-088 之 EDR 隔離狀態',
            '重設 daisy.wang@jjnet.com.tw 網域密碼',
            '邊界防火牆阻斷惡意 IP 185.220.101.5'
        ],
        'recommendations': [
            '套用原廠針對 CVE-2022-45806 發布之安全修補更新',
            '全域 GPO 強制停用未經簽署之 Office 巨集自動執行',
            '啟用 Windows 虛擬化安全性 (VBS) 與 Credential Guard'
        ],
        'unresolvedItems': [
            '確認 AD/DC 是否存在憑證二次利用異常日誌',
            '外部 C2 威脅組織身分對齊'
        ],
        'preparedBy': 'SOC Lead Analyst',
        'preparedAt': '2026-09-16T22:30:00Z',
        'reviewedBy': 'Vincent (資深資安顧問 / SOC 主管)',
        'reviewedAt': '2026-09-16T22:45:00Z',
        'approvalStatus': 'Approved',
        'approvalRecord': 'APR-2026-0042'
    }
    bytes_data = render_incident_docx(tpl, test_report)
    out_file = r'C:\Users\Elodie\jjnet-security-agents\scratch\rendered_test.docx'
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'wb') as f:
        f.write(bytes_data)
    print(f'Done! Output written to {out_file}, size: {len(bytes_data)} bytes')
