# JJNET 資安智能運籌中心 - 四大資安 Agent 整合交付平台

本專案專為 **JJNET 資安智能運籌中心 (JJNET Cyber SOC)** 量身打造，全系統核心 AI 模型全面搭載 **Google Gemma 4 28B (gemma-4-28b-it)**，嚴格對齊專案規格簡報與企業範本標準。架構遵循 **「前三個任務為 100% 地端自主運行 AI Agent（機敏資料不出門、日誌零外洩），任務四採用前端 ＋ RAG 知識庫出題與主管簽核閉環」** 的核心原則。

---

## 🌟 系統整體架構與四大任務定位

```
                                ┌──────────────────────────────────────────────┐
                                │     JJNET Cyber SOC 統一維運操作平台 (Web)    │
                                └──────────────────────┬───────────────────────┘
                                                       │ (http://localhost:8787)
         ┌─────────────────────────────────────────────┴─────────────────────────────────────────────┐
         ▼                                             ▼                                             ▼
┌─────────────────────────────────┐           ┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│ 任務一：資安事件調查 Agent      │           │ 任務二：資安顧問助理 Agent      │           │ 任務三：Cortex 月報生成 Agent   │
│ (100% 地端離線·資料不出門)       │           │ (100% 地端離線·資料不出門)       │           │ (100% 地端離線·資料不出門)       │
├─────────────────────────────────┤           ├─────────────────────────────────┤           ├─────────────────────────────────┤
│ • 8 階段工作流自主執行          │           │ • 專業技術問答與知識檢索        │           │ • SOC 運籌指標即時計算 (SLA)    │
│ • 組成 Incident Data Pack       │           │ • CVE 脈絡補充與處置策略        │           │ • 異常趨勢與模式挖掘 (Anomaly)  │
│ • 人審閘道覆核機制 (Checklist)  │           │ • 法規合規 (ISO 27001/NIST)     │           │ • 跨月趨勢對比與 Top 10 事件    │
│ • 11 節標準 Word/PDF/MD/Email   │           │ • 嚴格防幻覺與低信心度補件指引  │           │ • 企業級 5 頁式標準月報規格     │
│ • JJNET 官方雙盾牌浮水印全內嵌  │           │ • 顧問審核並回存新 Q&A          │           │ • JJNET 浮水印與高階主管摘要    │
└─────────────────────────────────┘           └─────────────────────────────────┘           └─────────────────────────────────┘
                                                       │
                                                       ▼
                                      ┌─────────────────────────────────┐
                                      │ 任務四：資安新人訓練與主管簽核   │
                                      │ (前端 + 本地 RAG 向量知識庫)    │
                                      ├─────────────────────────────────┤
                                      │ 1. 課本匯入：章節分段與建立索引 │
                                      │ 2. 前端 RAG：精準檢索與模擬出題 │
                                      │ 3. 講師定稿：線上修訂與鎖定發布 │
                                      │ 4. 新人研讀：情境測驗與錯題考核 │
                                      │ 5. 主管簽核：加蓋官方資安專用章 │
                                      │    (去除假名，支援真實姓名簽章) │
                                      └─────────────────────────────────┘
```

---

## 📋 四大 Agent 詳細功能規格清單

### 任務一：資安事件調查 Agent (Incident Investigation Agent)
- **核心定位**：接收 Palo Alto NGFW 與 Cortex XDR 原始調查日誌，自動抽取 IOC、關聯 CVE 脈絡，組成統一資料脈絡層（Incident Data Pack），並由地端模型生成具備 11 節完整架構的正式事件調查報告。
- **後端端點**：`POST /api/incident`、`POST /api/incident/export-docx`
- **11 節標準輸出結構**：
  1. `00` 封面標頭與 6 行 2 欄元資料表（雙色深海藍 `#0B2239` 與湖水綠 `#087E8B`）
  2. `01` Executive Summary（事件綜整與殘餘風險）
  3. `02` Classification and Scope（分類、狀態、信心度）
  4. `03` Affected Assets（受影響主機、帳號與防火牆邊界資產）
  5. `04` MITRE ATT&CK Mapping（戰術與技術矩陣對應）
  6. `05` Evidence（Palo Alto / Cortex XDR 觀測跡證）
  7. `06` Incident Timeline（事件進程時序表）
  8. `07` Response Actions（圍堵處置作為與完成狀態）
  9. `08` Recommendations（優先處置等級 P1/P2/P3 與修補加固）
  10. `09` Unresolved Items / Pending Confirmation（待追蹤事項與佐證需求）
  11. `10` Revision History（版本歷程修訂表）
  12. `11` Review and Approval（編製者、審核顧問與簽章紀錄）
- **官方背景浮水印**：Word (.docx) 頁首與網頁列印/PDF 均已完整置中嵌入 **JJNET 官方雙盾牌浮水印**。
- **五大多元輸出管道**：Word (.docx)、Markdown (.md)、PDF/列印、Email 緊急通報函、ITSM/Jira 工單。

### 任務二：資安顧問助理 Agent (Security Consultant Agent)
- **核心定位**：協助資安顧問快速且精準回答客戶資安技術、產品配置與合規問題，**並完整支援「讀取任務一/月報檔案進行深度事件解釋與建議處置方針」**。
- **報告讀入模式 (Report Ingestion Mode)**：
  - 支援讀入任務一產出之 Word (`.docx`)、Markdown (`.md`)、JSON (`.json`) 或原始日誌檔。
  - **自動解析攻擊鏈與根因**：邊界 Web 漏洞利用 ➜ 混淆 PowerShell 執行 ➜ svchost.exe 記憶體代碼注入 (Process Hollowing) ➜ 境外 C2 外聯。
  - **受害資產衝擊評估**：針對財務端點 (WS-FIN-088) 與主管帳號特權角色評估潛在金流憑證與資料外洩風險。
  - **四階段處置處方 (Playbook)**：0~2 小時緊急隔離與憑證撤銷、2~8 小時記憶體鑑識、24 小時邊界封鎖與補丁、72 小時法規通報結案。
  - **中長期加固與法規時限**：Windows Credential Guard、PowerShell 限制語言模式、微隔離，以及《資通安全管理法》1 小時內通報、《個資法》罰則警示。
- **後端端點**：`POST /api/consultant`、`GET /api/incident/latest-report`
- **防幻覺機制**：知識庫不足時自動將信心度標記為 `Low`，嚴禁憑空捏造，並自動列出需向客戶索取的補件事項。
- **輸出包含**：技術解答、可信度評級、引用來源（ISO 27001 / NIST / SOP-SEC-004 條款）、分階段處置步驟、潛在業務風險、追蹤問題。

### 任務三：Cortex 月報生成 Agent (Cortex Monthly Report Agent)
- **核心定位**：彙整全月份資安監控數據與告警事件，自動核算營運 SLA，挖掘異常攻擊趨勢，產出標準 5 頁式月報。
- **後端端點**：`POST /api/monthly-report`
- **指標分析**：告警總量、自動化阻擋率、MTTA（平均確認時間）、MTTR（平均處置時間）、每週威脅趨勢。
- **報表內容**：高階主管摘要、Top 10 重大事件分佈、深度處置細節與下階段資安加固策略。

### 任務四：資安新人訓練與主管簽核系統 (Training RAG & Sign-off)
- **核心定位**：以「前端＋RAG 知識庫」架構，讓資安教材出題、研讀、測驗與主管簽章形成完整閉環。
- **系統入口**：`http://localhost:8787/training.html`
- **五階段流水線**：
  1. `階段 1`：課本教材匯入與語義切片建立。
  2. `階段 2`：基於教材依據進行前端 RAG 出題（嚴禁幻覺，題目包含答案解析）。
  3. `階段 3`：教官線上覆核、修改考題並鎖定定稿（生成唯一版本號）。
  4. `階段 4`：新進學員研讀學習、在線測驗互動與成績錯題收錄。
  5. `階段 5`：**主管覆核簽章與結訓證書**：
     - 已徹底去除任何捏造之假名，預設加蓋官方 **「資安專用章」**。
     - 支援主管輸入真實姓名動態簽核，亦可留空維持單位官方章。
     - 具備防偽浮水印與專屬 A4/Letter 列印與 PDF 匯出格式。

---

## 🗂️ 專案檔案清單說明

```
jjnet-security-agents/
├── server.py                               # 核心後端主伺服器 (REST API、地端微調 AI 路由、OOXML DOCX 引擎)
├── templates/
│   ├── JJNET_Incident_Report_Template.docx # 官方 Word 標準範本 (含內嵌 JJNET 盾牌浮水印與 11 節標記)
│   └── jjnet-watermark.jpg                 # 官方雙盾牌浮水印圖片 (520x462)
├── public/                                 # 前端完整靜態資源
│   ├── index.html                          # SOC 統一控制台 (任務 1~3 主入口，含跳轉任務 4 導航)
│   ├── app.js                              # 前端業務邏輯 (多 Agent 切換、人審閘道、DOCX/MD/PDF 匯出)
│   ├── styles.css                          # SOC 科技風樣式表 (含 11 節正式範本排版與 @media print 浮水印)
│   ├── training.html                       # 任務四獨立系統：新人培訓、前端 RAG 出題與主管簽核證書
│   ├── training.js                         # 任務四前端 RAG 檢索引擎、定稿審核與真實姓名簽核邏輯
│   ├── training.css                        # 培訓系統專用樣式 (含結訓證書視覺化與數位資安印信)
│   └── jjnet-watermark.jpg                 # 提供網頁與列印引用之浮水印資源
├── INC-20260916-89421.md                   # 任務一實體驗證：11 節標準格式事件報告範例檔
├── work_incident_output.docx               # 任務一實體驗證：最新動態產生之標準 Word 報告 (含浮水印)
├── wrangler.toml                           # Cloudflare Worker 配置備用檔
├── .env.example                            # 環境變數範本 (可配置地端 Sovereign 或外部 API)
└── README.md                               # 本專案完整說明與交付文件
```

---

## 🚀 雙軌運作模式：純終端機 CLI 自主 Agent vs. Web 視覺化看板

本專案支援 **「純終端機命令列 (Pure CLI Autonomous Mode)」** 與 **「Web 視覺化運籌看板」** 雙軌運行架構，展現 100% 地端自主 Agent 之技術深度：

### 模式一：終端機純 CLI 自主 Agent 模式 (推薦展示！)
**完全不需開啟瀏覽器**，Agent 直接於本機終端機自主調用工具、完成推演並直接將 Word / Markdown 報告產出於磁碟 `outputs/` 目錄：

1. **互動式終端控制台 (Interactive Menu)**：
   ```powershell
   python agent_cli.py
   # 或在 Windows 直接點擊執行：run_agent_cli.bat
   ```
   可依數字選單快速選擇任務 1、2、3，終端機將即時顯示思考鏈與工具調用進度。

2. **直接執行特定任務 (Command-line Arguments)**：
   - **任務一：調查指定日誌檔並自動產出 11 節 Word (含浮水印) / MD / JSON**：
     ```powershell
     python agent_cli.py --task incident --demo
     # 指定自身日誌檔：python agent_cli.py --task incident --log C:\path\to\alert.log
     ```
   - **任務二：顧問技術問答或讀取任務一/月報檔案解讀**：
     ```powershell
     # 模式 A：讀取任務一 Word/MD 報告並進行深度攻擊鏈與處置分析
     python agent_cli.py --task consultant --file outputs/PA-20260916-89421.docx

     # 模式 B：手動輸入技術或法規諮詢問題
     python agent_cli.py --task consultant --query "同仁點擊外部勒索信件，該如何通報與處置？"
     ```
   - **任務三：Cortex 月報指標核算**：
     ```powershell
     python agent_cli.py --task monthly --month 2026-09
     ```

3. **目錄常駐自主監控模式 (Autonomous Watcher Daemon)**：
   ```powershell
   python agent_cli.py --watch
   # 或在 Windows 直接點擊執行：run_autonomous_watcher.bat
   ```
   Agent 將常駐背景監聽 `incoming_logs/` 資料夾。任何新進 Palo Alto / Cortex 日誌一放入，Agent 即**自主喚醒**、執行 8 階段調查，並自動產出 Word 報告至 `outputs/`，隨後將原日誌歸檔至 `processed/`！

---

### 模式二：Web 視覺化運籌看板與任務四新人訓系統

1. **啟動本機 Web 伺服器**：
   ```powershell
   python server.py
   # 或在 Windows 直接點擊執行：run_web_server.bat
   ```
   > 服務將預設監聽於 `http://localhost:8787`。

2. **存取與展示**：
   - **主維運平台（任務 1 ~ 任務 3）**：
     開啟瀏覽器：[http://localhost:8787](http://localhost:8787)
     - 點選「載入範例資料」➜「🚀 啟動 Agent 分析」，觀察 8 階段工作流與統一資料層。
     - 人審閘道核准後，點擊「📄 下載 Word (.docx) 報告」檢驗正中央 JJNET 官方盾牌浮水印。
   - **資安新人訓練與主管簽核（任務 4）**：
     開啟瀏覽器：[http://localhost:8787/training.html](http://localhost:8787/training.html)
     - 體驗 5 階段閉環（課本匯入 ➜ 前端 RAG 出題 ➜ 定稿 ➜ 測驗 ➜ 主管簽核發證）。
     - 驗證印信章無任何假名，支援真實姓名簽章並一鍵列印證書。

---

## 🔒 資料安全性與合規承諾
- **100% 地端自主運行**：任務一至任務三核心日誌完全在地端解析，不經過任何外部網路傳輸，滿足金融與政府機敏單位之去識別化與合規稽核規範。
- **無任何預設假名**：主管簽核、資安報告與印信完全去除假名污染，確保交付產出具備企業正式採納之真實性與法律效力。
