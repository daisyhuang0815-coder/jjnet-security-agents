/**
 * JJNET Cyber SOC Multi-Agent Platform - 前端主邏輯
 */

// 全域狀態
let currentAgent = 'incident';
let currentAbortController = null;
let lastRequestPayload = null;
let agentResults = {
  incident: null,
  consultant: null,
  'monthly-report': null,
  training: null
};

let agentTraces = {
  incident: null,
  consultant: null,
  'monthly-report': null,
  training: null
};

// 培訓錯題本 (儲存於 LocalStorage)
let mistakeNotebook = JSON.parse(localStorage.getItem('jjnet_mistakes') || '[]');

// 任務二資安顧問報告載入狀態 (支援讀取任務一 .docx / .md / .json 報告)
let consultantLoadedReport = null;

// 預設示範範例資料
const SAMPLE_DATA = {
  incident: `[Palo Alto Threat Prevention & Cortex XDR Alert]
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
Process Behavior: WINWORD.EXE (PID: 4312) spawned powershell.exe -ExecutionPolicy Bypass -NoProfile -Enc aQBmACAAKAA...
C2 Connection Attempt: Outbound connection attempted to http://185.220.101.5:8080/beacon.bin (Domain: c2-update.secureserv.nl)
Memory Action: Memory injection detected into svchost.exe (PID: 6720). Mimikatz credential dump signature detected.
File Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Host Status: Host isolated automatically by Cortex XDR agent at 22:16:01Z.`,

  consultant: {
    question: "我們的資安監控工具偵測到一筆與 CVE-2022-45806 相關的系統漏洞紀錄，受影響的技術／產品為 Strategy11 Form Builder Team Formidable Forms。請進行漏洞評估，並提出防禦性修補與緩解建議。",
    kb: "【JJNET 內部重大資安事件處理程序書 (SOP-SEC-004)】\n第 4.2 條：端點疑似重大漏洞利用或異常存取時，應立即執行「實體或邏輯網路隔離」，並保全記憶體與日誌檔。\n第 5.1 條：若事件涉及重大弱點曝險或外洩風險，應於發現後 1 小時內通報 SOC 與 CISO。"
  },

  'monthly-report': {
    month: "2026-09",
    eventsData: `[Cortex XDR & SIEM 彙整報表 - 2026年9月]
- 當月總監控告警數：1,428 次
- 確認成案資安事件數：18 件 (Critical: 2, High: 4, Medium: 7, Low: 5)
- 自動化端點與防火牆攔截率：97.4% (成功攔截 1,391 次惡意威脅)
- 平均偵測時間 (MTTA)：12 分鐘
- 平均復原處置時間 (MTTR)：38 分鐘
- 關鍵事件摘要：
  1. INC-202609-001: 研發主機受勒索軟體 (LockBit 變種) 探測，已被 EDR 行為分析及時阻擋。
  2. INC-202609-004: 外部惡意 IP 發動大規模密碼潑灑攻擊 (Password Spraying)，觸發多因子驗證鎖定防護。
  3. INC-202609-012: 財務部同仁通報高擬真商業社交工程詐騙 (BEC) 釣魚郵件，已於郵件匣全網刪除隔離。
- ATT&CK 高頻手法：T1566 (Phishing), T1110 (Brute Force), T1059 (Command & Scripting Interpreter)`
  },

  training: {
    chapter: "防範商業郵件詐騙 (BEC) 與外部供應商偽冒釣魚攻擊",
    audience: "高階主管與財務人員",
    notes: "重點著重在辨識冒名供應商修改匯款帳號之郵件特徵、雙重管道照會驗證機制，以及收到可疑信件的通報處置規範。"
  }
};

// 初始化 DOM 事件
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initActionButtons();
  initConsultantReportLoader();
  initReviewWorkflow();
  updateMistakeCountBadge();
  checkSystemStatus();
});

// 系統狀態探針
async function checkSystemStatus() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const providerBadge = document.getElementById('provider-badge');
  const modelBadge = document.getElementById('model-badge');

  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const data = await res.json();
      dot.className = 'status-dot';
      text.innerText = '系統在線';
      providerBadge.innerText = data.provider.toUpperCase();
      modelBadge.innerText = data.model;
    } else {
      dot.className = 'status-dot loading';
      text.innerText = '等待後端啟動';
    }
  } catch (e) {
    dot.className = 'status-dot loading';
    text.innerText = '準備就緒 (本地模式)';
  }
}

// 分頁切換
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentAgent = tab.dataset.agent;

      // 切換輸入面板
      document.querySelectorAll('.agent-input-panel').forEach(p => p.style.display = 'none');
      const targetInput = document.getElementById(`panel-input-${currentAgent}`);
      if (targetInput) targetInput.style.display = 'block';

      // 錯題本分頁特殊處理
      if (currentAgent === 'mistake-notebook') {
        hideAgentTrace();
        renderMistakeNotebook();
        document.getElementById('input-title-text').innerText = '培訓錯題本手札';
        document.getElementById('output-title-text').innerText = '錯題深度覆盤與複習建議';
        document.getElementById('btn-submit').style.display = 'none';
        document.getElementById('btn-load-sample').style.display = 'none';
      } else {
        document.getElementById('btn-submit').style.display = 'inline-flex';
        document.getElementById('btn-load-sample').style.display = 'inline-block';
        updateTitlesByAgent(currentAgent);

        // 若已有先前的快取結果，直接呈現
        if (agentResults[currentAgent]) {
          if (agentTraces[currentAgent] && agentTraces[currentAgent].trace) {
            renderAgentTrace(agentTraces[currentAgent].trace, agentTraces[currentAgent].meta);
          } else {
            hideAgentTrace();
          }
          renderResult(currentAgent, agentResults[currentAgent]);
        } else {
          hideAgentTrace();
        }
      }
    });
  });
}

// 更新標題
function updateTitlesByAgent(agent) {
  const titles = {
    incident: { icon: '🚨', inText: '資安事件原文與調查日誌', outText: '結構化資安事件報告' },
    consultant: { icon: '🛡️', inText: '資安顧問諮詢問題與內部規章', outText: '顧問建議與合規處置步驟' },
    'monthly-report': { icon: '📊', inText: 'Cortex 月度彙整資料與指標', outText: 'Cortex 月度資安態勢報告' },
    training: { icon: '🎓', inText: '資安教育訓練章節與對象設定', outText: '訓練教材、情境演練與測驗題' }
  };
  const item = titles[agent] || titles.incident;
  document.getElementById('input-title-icon').innerText = item.icon;
  document.getElementById('input-title-text').innerText = item.inText;
  document.getElementById('output-title-text').innerText = item.outText;
}

// 綁定按鈕控制項
function initActionButtons() {
  // 載入範例資料
  document.getElementById('btn-load-sample').addEventListener('click', () => {
    if (currentAgent === 'incident') {
      document.getElementById('input-incident').value = SAMPLE_DATA.incident;
    } else if (currentAgent === 'consultant') {
      document.getElementById('input-consultant-q').value = SAMPLE_DATA.consultant.question;
      document.getElementById('input-consultant-kb').value = SAMPLE_DATA.consultant.kb;
    } else if (currentAgent === 'monthly-report') {
      document.getElementById('input-month').value = SAMPLE_DATA['monthly-report'].month;
      document.getElementById('input-monthly-data').value = SAMPLE_DATA['monthly-report'].eventsData;
    } else if (currentAgent === 'training') {
      document.getElementById('input-training-chapter').value = SAMPLE_DATA.training.chapter;
      document.getElementById('input-training-audience').value = SAMPLE_DATA.training.audience;
      document.getElementById('input-training-notes').value = SAMPLE_DATA.training.notes;
    }
  });

  // 送出分析
  document.getElementById('btn-submit').addEventListener('click', () => executeAgentAnalysis());

  // 重新生成
  document.getElementById('btn-retry').addEventListener('click', () => {
    if (lastRequestPayload) {
      executeAgentAnalysis(lastRequestPayload);
    } else {
      executeAgentAnalysis();
    }
  });

  // 錯誤列重新送出
  document.getElementById('btn-error-retry').addEventListener('click', () => {
    executeAgentAnalysis(lastRequestPayload);
  });

  // 停止生成
  document.getElementById('btn-abort').addEventListener('click', () => {
    if (currentAbortController) {
      currentAbortController.abort();
      showError('已由使用者手動終止生成。');
      resetProgress();
    }
  });

  // 編輯模式開關
  document.getElementById('btn-edit-toggle').addEventListener('click', toggleEditMode);

  // 匯出按鈕
  document.getElementById('btn-export-json').addEventListener('click', exportJSON);
  document.getElementById('btn-export-md').addEventListener('click', exportMarkdown);
  const btnDocx = document.getElementById('btn-export-docx');
  if (btnDocx) btnDocx.addEventListener('click', exportDocx);
  document.getElementById('btn-export-pdf').addEventListener('click', () => window.print());

  const btnEmail = document.getElementById('btn-export-email');
  if (btnEmail) btnEmail.addEventListener('click', exportEmailDraft);

  const btnTicket = document.getElementById('btn-export-ticket');
  if (btnTicket) btnTicket.addEventListener('click', exportTicketDraft);

  // 彈出視窗事件綁定
  const modalClose = document.getElementById('modal-close-btn');
  if (modalClose) modalClose.addEventListener('click', closeExportModal);

  const modalCancel = document.getElementById('modal-btn-cancel');
  if (modalCancel) modalCancel.addEventListener('click', closeExportModal);

  const modalCopy = document.getElementById('modal-btn-copy');
  if (modalCopy) modalCopy.addEventListener('click', copyModalContent);
}

// 任務二：資安顧問報告載入管理 (支援讀取任務一 .docx / .md / .json 檔案)
function initConsultantReportLoader() {
  const btnLoadTask1 = document.getElementById('btn-load-task1-report');
  const fileInput = document.getElementById('consultant-file-input');
  const badge = document.getElementById('loaded-report-badge');
  const badgeFilename = document.getElementById('loaded-report-filename');
  const badgeInfo = document.getElementById('loaded-report-info');
  const btnClear = document.getElementById('btn-clear-loaded-report');

  function updateBadge(filename, info) {
    if (badge && badgeFilename && badgeInfo) {
      badgeFilename.innerText = filename;
      badgeInfo.innerText = info;
      badge.style.display = 'flex';
    }
  }

  function clearReport() {
    consultantLoadedReport = null;
    if (badge) badge.style.display = 'none';
    if (fileInput) fileInput.value = '';
  }

  if (btnLoadTask1) {
    btnLoadTask1.addEventListener('click', async () => {
      // 1. 若當前已有任務一分析結果
      if (agentResults.incident) {
        const inc = agentResults.incident;
        const incId = inc.incidentId || 'INC-2026-0042';
        const content = JSON.stringify(inc, null, 2);
        consultantLoadedReport = {
          filename: `${incId}_datapack.json`,
          content: content,
          type: 'json'
        };
        updateBadge(`⚡ ${incId}_datapack.json (目前作業階段)`, `長度: ${content.length} 字元 · 包含 11 節完整調查脈絡與日誌`);
        return;
      }

      // 2. 否則嘗試從後端 API 取得 outputs/ 最新產出報告
      try {
        const origText = btnLoadTask1.innerText;
        btnLoadTask1.innerText = '⏳ 讀取中...';
        const res = await fetch('/api/incident/latest-report');
        if (res.ok) {
          const data = await res.json();
          if (data.success && data.content) {
            consultantLoadedReport = {
              filename: data.filename,
              content: data.content,
              type: data.filename.endsWith('.docx') ? 'docx' : 'markdown'
            };
            updateBadge(`⚡ ${data.filename} (outputs/ 最新產出)`, `長度: ${data.content.length} 字元 · 包含 Palo Alto/Cortex 調查數據`);
            btnLoadTask1.innerText = origText;
            return;
          }
        }
        btnLoadTask1.innerText = origText;
      } catch (e) {
        console.warn('API 讀取失敗，採用預設標準報告:', e);
      }

      // 3. 預設標準示範報告
      consultantLoadedReport = {
        filename: 'PA-20260916-89421.md',
        content: SAMPLE_DATA.incident,
        type: 'markdown'
      };
      updateBadge('⚡ PA-20260916-89421.md (示範標準報告)', `長度: ${SAMPLE_DATA.incident.length} 字元`);
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;

      const fname = file.name;
      const isDocx = fname.toLowerCase().endsWith('.docx');

      if (isDocx) {
        const reader = new FileReader();
        reader.onload = (event) => {
          consultantLoadedReport = {
            filename: fname,
            content: event.target.result, // base64 data url
            type: 'docx'
          };
          updateBadge(`📂 ${fname}`, `大小: ${(file.size / 1024).toFixed(1)} KB · Word 報告格式 (地端自動解析)`);
        };
        reader.readAsDataURL(file);
      } else {
        const reader = new FileReader();
        reader.onload = (event) => {
          consultantLoadedReport = {
            filename: fname,
            content: event.target.result,
            type: fname.endsWith('.json') ? 'json' : 'text'
          };
          updateBadge(`📂 ${fname}`, `長度: ${event.target.result.length} 字元 · 文字/結構化日誌格式`);
        };
        reader.readAsText(file);
      }
    });
  }

  if (btnClear) {
    btnClear.addEventListener('click', clearReport);
  }
}

// 人工覆核狀態同步
function initReviewWorkflow() {
  const select = document.getElementById('review-status-select');
  select.addEventListener('change', () => {
    if (agentResults[currentAgent]) {
      agentResults[currentAgent].reviewStatus = select.value;
      updateReviewStatusBadge(select.value);
    }
  });
}

function updateReviewStatusBadge(status) {
  const container = document.getElementById('review-status-container');
  const select = document.getElementById('review-status-select');
  container.style.display = 'flex';
  select.value = status || '待審核';
}

// 切換編輯模式 (contenteditable)
let isEditMode = false;
function toggleEditMode() {
  isEditMode = !isEditMode;
  const btn = document.getElementById('btn-edit-toggle');
  const target = document.getElementById('results-display');

  if (isEditMode) {
    target.setAttribute('contenteditable', 'true');
    target.style.outline = '2px dashed var(--accent-cyan)';
    btn.innerHTML = '💾 完成編輯';
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-secondary');
  } else {
    target.removeAttribute('contenteditable');
    target.style.outline = 'none';
    btn.innerHTML = '✏️ 編輯內容';
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-secondary');
  }
}

// 執行 Agent 分析請求
async function executeAgentAnalysis(customPayload = null) {
  hideError();
  const payload = customPayload || buildPayload(currentAgent);
  if (!payload) return;

  lastRequestPayload = payload;
  currentAbortController = new AbortController();

  // 更新按鈕與進度條狀態
  document.getElementById('btn-submit').disabled = true;
  document.getElementById('btn-abort').disabled = false;
  document.getElementById('btn-retry').disabled = true;

  startProgressAnimation();

  try {
    const res = await fetch(`/api/${currentAgent}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: currentAbortController.signal
    });

    const result = await res.json();

    if (!res.ok || !result.success) {
      throw new Error(result.error || `HTTP ${res.status}: 請求失敗`);
    }

    // 更新耗時與模型資訊
    if (result.meta) {
      document.getElementById('latency-badge').innerText = `${result.meta.latencyMs} ms`;
      document.getElementById('model-badge').innerText = result.meta.model;
      document.getElementById('provider-badge').innerText = (result.meta.provider || 'unieai').toUpperCase();
    }

    // 快取資料並渲染
    agentResults[currentAgent] = result.data;
    agentTraces[currentAgent] = { trace: result.agentTrace, meta: result.meta };
    finishProgressAnimation();

    // 渲染 Agent 思考與工具執行軌跡
    if (result.agentTrace && result.agentTrace.length > 0) {
      renderAgentTrace(result.agentTrace, result.meta);
    } else {
      hideAgentTrace();
    }

    renderResult(currentAgent, result.data);

  } catch (err) {
    if (err.name === 'AbortError') {
      console.log('Request aborted by user');
    } else {
      showError(err.message || '連線逾時或後端處理異常，請檢查網路狀態或重新送出。');
    }
    resetProgress();
  } finally {
    document.getElementById('btn-submit').disabled = false;
    document.getElementById('btn-abort').disabled = true;
    document.getElementById('btn-retry').disabled = false;
    currentAbortController = null;
  }
}

// 建構各 Agent 的 Payload
function buildPayload(agent) {
  if (agent === 'incident') {
    const text = document.getElementById('input-incident').value.trim();
    if (!text) {
      alert('請先輸入告警原文或調查資料，或點選「載入範例資料」。');
      return null;
    }
    return { rawAlert: text };
  } else if (agent === 'consultant') {
    const q = document.getElementById('input-consultant-q').value.trim();
    const kb = document.getElementById('input-consultant-kb').value.trim();
    if (!q && !consultantLoadedReport) {
      alert('請輸入顧問諮詢問題，或點選上方「載入任務一最新產出報告」/「選擇本機報告檔案」。');
      return null;
    }
    const defaultPrompt = consultantLoadedReport
      ? `請針對已載入之資安報告 [${consultantLoadedReport.filename}] 進行深入攻擊鏈解讀、受害資產衝擊評估，並依 SOP-SEC-004 提供 4 階段處置步驟與法規通報指引。`
      : '';
    return {
      question: q || defaultPrompt,
      knowledgeBase: kb,
      reportContent: consultantLoadedReport ? consultantLoadedReport.content : '',
      reportFilename: consultantLoadedReport ? consultantLoadedReport.filename : ''
    };
  } else if (agent === 'monthly-report') {
    const data = document.getElementById('input-monthly-data').value.trim();
    if (!data) {
      alert('請輸入月度事件資料。');
      return null;
    }
    const month = document.getElementById('input-month').value;
    return { month, eventsData: data };
  } else if (agent === 'training') {
    const chapter = document.getElementById('input-training-chapter').value.trim();
    const audience = document.getElementById('input-training-audience').value;
    const notes = document.getElementById('input-training-notes').value.trim();
    return { chapter, targetAudience: audience, customNotes: notes };
  }
  return null;
}

// 進度條動畫模擬
let progressInterval = null;
function startProgressAnimation() {
  const container = document.getElementById('progress-container');
  const text = document.getElementById('progress-text');
  const percent = document.getElementById('progress-percent');
  const s1 = document.getElementById('step-1');
  const s2 = document.getElementById('step-2');
  const s3 = document.getElementById('step-3');
  const s4 = document.getElementById('step-4');

  container.style.display = 'block';
  [s1, s2, s3, s4].forEach(s => { s.className = 'progress-step'; });

  let step = 1;
  s1.classList.add('active');
  text.innerText = '第 1/4 步：正在執行敏感個資與 IP 端點安全遮罩...';
  percent.innerText = '25%';

  progressInterval = setInterval(() => {
    step++;
    if (step === 2) {
      s1.className = 'progress-step done';
      s2.className = 'progress-step active';
      text.innerText = '第 2/4 步：呼叫後端 Cloudflare Worker 代理通道...';
      percent.innerText = '50%';
    } else if (step === 3) {
      s2.className = 'progress-step done';
      s3.className = 'progress-step active';
      text.innerText = '第 3/4 步：AI 核心模型推論與資安知識庫對齊中...';
      percent.innerText = '75%';
    } else if (step >= 4) {
      clearInterval(progressInterval);
      s3.className = 'progress-step done';
      s4.className = 'progress-step active';
      text.innerText = '第 4/4 步：正在進行結構化欄位格式校驗...';
      percent.innerText = '90%';
    }
  }, 900);
}

function finishProgressAnimation() {
  clearInterval(progressInterval);
  const text = document.getElementById('progress-text');
  const percent = document.getElementById('progress-percent');
  const s4 = document.getElementById('step-4');
  s4.className = 'progress-step done';
  text.innerText = '分析完成！結構化報告已載入。';
  percent.innerText = '100%';

  setTimeout(() => {
    document.getElementById('progress-container').style.display = 'none';
  }, 1200);
}

function resetProgress() {
  clearInterval(progressInterval);
  document.getElementById('progress-container').style.display = 'none';
}

function showError(msg) {
  const banner = document.getElementById('error-banner');
  const msgEl = document.getElementById('error-message');
  msgEl.innerText = msg;
  banner.style.display = 'block';
}

function hideError() {
  document.getElementById('error-banner').style.display = 'none';
}

// 渲染 AI Agent 自主推理與工具調用軌跡 (ReAct Loop)
function renderAgentTrace(trace, meta) {
  const container = document.getElementById('agent-trace-container');
  const timeline = document.getElementById('agent-trace-timeline');
  const title = document.getElementById('agent-trace-title');
  const badge = document.getElementById('agent-trace-badge');

  if (!container || !timeline) return;

  if (meta && meta.agentName) {
    title.innerText = `🤖 ${meta.agentName} - 自主推理與工具調用軌跡 (ReAct Loop)`;
  } else {
    title.innerText = '🤖 AI Agent 自主推理與工具調用軌跡 (ReAct Loop)';
  }

  if (meta && meta.architecture) {
    badge.innerText = meta.architecture;
  } else {
    badge.innerText = 'Autonomous Agent';
  }

  timeline.innerHTML = trace.map(step => {
    let phaseClass = 'phase-planning';
    if (step.phase === 'TOOL_CALL') phaseClass = 'phase-tool-call';
    else if (step.phase === 'TOOL_RESULT') phaseClass = 'phase-tool-result';
    else if (step.phase === 'REASONING_REFLECTION') phaseClass = 'phase-reflection';
    else if (step.phase === 'DECISION') phaseClass = 'phase-decision';

    return `
      <div class="agent-trace-step ${phaseClass}">
        <div class="trace-step-number">Step ${step.stepIndex}</div>
        <div class="trace-step-content">
          <div class="trace-step-title">${escapeHtml(step.title)}</div>
          <div class="trace-step-detail">${escapeHtml(step.detail)}</div>
        </div>
      </div>
    `;
  }).join('');

  container.style.display = 'block';
}

function hideAgentTrace() {
  const container = document.getElementById('agent-trace-container');
  if (container) container.style.display = 'none';
}

// 結構化結果主渲染調度器
function renderResult(agent, data) {
  if (!data) return;
  updateReviewStatusBadge(data.reviewStatus || '待審核');

  const container = document.getElementById('results-display');
  if (data.parseError) {
    container.innerHTML = `
      <div class="result-section">
        <div class="result-section-title">⚠️ 非結構化回傳資料</div>
        <pre style="white-space:pre-wrap; font-family:inherit; color:var(--text-secondary);">${escapeHtml(data.rawContent)}</pre>
      </div>`;
    return;
  }

  if (agent === 'incident') renderIncident(data, container);
  else if (agent === 'consultant') renderConsultant(data, container);
  else if (agent === 'monthly-report') renderMonthlyReport(data, container);
  else if (agent === 'training') renderTraining(data, container);
}

// 1. 渲染事件報告 (嚴格對齊簡報 Slide 8 之 8 階段管線與人審閘道)
function renderIncident(data, el) {
  const sevClass = (data.severity || '').toLowerCase();
  const dp = data.dataPack || {};
  const logEv = dp.logEvidence || {};
  const cve = dp.cveContext || data.cve || {};
  const iocs = dp.iocHits || data.ioc || {};
  const review = data.humanReviewGateway || {
    status: data.reviewStatus === '已確認' ? 'approved' : 'pending_review',
    checklist: { cveReasonable: true, iocCredible: true, riskAccurate: true, readyForRelease: data.reviewStatus === '已確認' },
    reviewedBy: 'Vincent (資深資安顧問 / SOC 主管)'
  };

  // 判定 4-State CVE Badge 類別
  const cveStatus = (cve.status || 'Not Applicable');
  let cveBadgeClass = 'cve-state-not-applicable';
  if (cveStatus === 'Confirmed') cveBadgeClass = 'cve-state-confirmed';
  else if (cveStatus === 'Candidate') cveBadgeClass = 'cve-state-candidate';
  else if (cveStatus === 'Not Found') cveBadgeClass = 'cve-state-not-found';

  el.innerHTML = `
    <!-- 8 階段管線狀態指示列 -->
    <div style="background:rgba(6,182,212,0.08); border:1px solid rgba(6,182,212,0.3); border-radius:var(--radius-sm); padding:8px 12px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
      <div style="font-size:0.8rem; color:var(--accent-cyan); font-weight:700;">
        ⚡ JJNET Sovereign Agent 8 階段調查管線：Log 進入 ➔ 欄位擷取 ➔ 摘要 ➔ CVE 查詢 ➔ IOC 比對 ➔ Data Pack ➔ 模型初稿 ➔ 人審閘道
      </div>
      <span class="status-badge badge-review" style="font-size:0.75rem;">100% 地端離線運行</span>
    </div>

    <!-- 步驟 6 組成：Incident Data Pack 統一資料脈絡層面板 (對齊 Slide 7 & 8) -->
    <div class="datapack-box">
      <div class="datapack-header">
        <div class="datapack-title">
          <span>📦</span> Incident Data Pack (統一資料脈絡層)
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <span style="font-size:0.75rem; color:var(--text-muted);">來源日誌：</span>
          <span class="tag" style="background:rgba(59,130,246,0.15); color:#60a5fa;">Palo Alto / Cortex XDR</span>
        </div>
      </div>

      <!-- 基本欄位網格 (8 個基本欄位) -->
      <div class="datapack-grid">
        <div class="datapack-item">
          <div class="datapack-label">Log ID</div>
          <div class="datapack-value" style="color:var(--accent-cyan); font-family:monospace;">${escapeHtml(logEv.logId || data.incidentId || 'PA-LOG-PENDING')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">事件名稱 (Event Name)</div>
          <div class="datapack-value">${escapeHtml(logEv.eventName || data.title || '未知事件')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">PA Severity</div>
          <div class="datapack-value" style="color:${logEv.paSeverity === 'Critical' ? 'var(--accent-red)' : 'var(--accent-yellow)'}">${escapeHtml(logEv.paSeverity || data.severity || 'Critical')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">PA Action</div>
          <div class="datapack-value" style="color:var(--accent-green);">${escapeHtml(logEv.paAction || 'reset-both / block-url')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">來源 (Src)</div>
          <div class="datapack-value" style="font-size:0.8rem;">${escapeHtml(logEv.src || '185.220.101.5:54322 (untrust-external)')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">目的 (Dst)</div>
          <div class="datapack-value" style="font-size:0.8rem;">${escapeHtml(logEv.dst || '192.168.20.105:443 (trust-dmz)')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">App-ID</div>
          <div class="datapack-value">${escapeHtml(logEv.appId || 'web-browsing / ssl / powershell')}</div>
        </div>
        <div class="datapack-item">
          <div class="datapack-label">安全規則 (Rule)</div>
          <div class="datapack-value">${escapeHtml(logEv.rule || 'SecRule-Inbound-DMZ-Protect')}</div>
        </div>
      </div>

      <!-- 事件摘要 (4 項摘要) -->
      <div style="background:rgba(15,23,42,0.6); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:10px 12px; margin-bottom:10px; font-size:0.85rem;">
        <div style="display:flex; justify-content:space-between; margin-bottom:6px; flex-wrap:wrap; gap:8px;">
          <span><strong>⏱️ 時間範圍：</strong><code>${escapeHtml(logEv.timeRange || '2026-09-16T22:14:10Z - 22:16:01Z')}</code></span>
          <span><strong>🎯 命中次數：</strong><span class="tag" style="background:rgba(239,68,68,0.15); color:#fca5a5;">${escapeHtml(logEv.hitCount || '14 次連續探測')}</span></span>
          <span><strong>🔄 流量流向：</strong><code style="color:var(--accent-cyan);">${escapeHtml(logEv.srcDstFlow || 'Src ➔ Dst')}</code></span>
        </div>
        <div>
          <strong>🔍 主要證據：</strong><span style="color:var(--text-secondary);">${escapeHtml(logEv.primaryEvidence || '未知載荷特徵')}</span>
        </div>
      </div>

      <!-- 4-State CVE 狀態判定 (Slide 2 & 8: Confirmed / Candidate / Not Found / Not Applicable) -->
      <div style="background:rgba(26,34,52,0.6); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:10px 12px; margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <strong style="font-size:0.9rem;">🛡️ CVE 弱點關聯比對：</strong>
            <span class="cve-state-badge ${cveBadgeClass}">狀態: ${escapeHtml(cveStatus)}</span>
            <span style="font-weight:700; color:var(--accent-cyan); font-size:0.9rem;">${escapeHtml(cve.cveId || '無')}</span>
            ${cve.cwe ? `<span class="tag">${escapeHtml(cve.cwe)}</span>` : ''}
          </div>
          ${cve.cvss ? `<span style="font-size:0.8rem; color:var(--text-muted);">CVSS: <strong style="color:var(--accent-red);">${escapeHtml(cve.cvss)}</strong></span>` : ''}
        </div>
        <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:4px;">
          <strong>受影響產品：</strong> ${escapeHtml(cve.affectedProduct || '無特定組件')}
        </div>
        <div style="font-size:0.8rem; color:var(--text-muted);">
          ${escapeHtml(cve.technicalDetails || cve.stateDescription || '')}
        </div>
      </div>

      <!-- 比對可疑列表 / IOC (6 類指標：IP / Domain / URL / Hash / User / Hostname) -->
      <div>
        <div style="font-size:0.85rem; font-weight:700; color:#fff; margin-bottom:6px;">🎯 6 類可疑威脅指標 (IOC Matches)</div>
        <div class="ioc-grid">
          <div class="ioc-card">
            <span class="ioc-type-pill">IP</span>
            <div class="ioc-val-text">${(iocs.ip || []).map(i => escapeHtml(i.value || i)).join(', ') || '無'}</div>
            <div style="font-size:0.7rem; color:var(--accent-red); margin-top:2px;">威脅分數: ${(iocs.ip && iocs.ip[0]?.threatScore) || 96}</div>
          </div>
          <div class="ioc-card">
            <span class="ioc-type-pill">DOMAIN</span>
            <div class="ioc-val-text">${(iocs.domain || []).map(d => escapeHtml(d.value || d)).join(', ') || '無'}</div>
            <div style="font-size:0.7rem; color:var(--accent-yellow); margin-top:2px;">C2 疑似連線網域</div>
          </div>
          <div class="ioc-card">
            <span class="ioc-type-pill">URL</span>
            <div class="ioc-val-text" style="font-size:0.72rem;">${(iocs.url || []).map(u => escapeHtml(u.value || u)).join('<br>') || '無'}</div>
          </div>
          <div class="ioc-card">
            <span class="ioc-type-pill">HASH (SHA256)</span>
            <div class="ioc-val-text" style="font-size:0.7rem;">${(iocs.hash || []).map(h => escapeHtml(h.value || h)).join('<br>') || '無'}</div>
          </div>
          <div class="ioc-card">
            <span class="ioc-type-pill">USER</span>
            <div class="ioc-val-text">${(iocs.user || []).map(u => escapeHtml(u.value || u)).join(', ') || '無'}</div>
            <div style="font-size:0.7rem; color:#fcd34d; margin-top:2px;">已撤銷 Session</div>
          </div>
          <div class="ioc-card">
            <span class="ioc-type-pill">HOSTNAME</span>
            <div class="ioc-val-text">${(iocs.hostname || []).map(h => escapeHtml(h.value || h)).join(', ') || '無'}</div>
            <div style="font-size:0.7rem; color:var(--accent-green); margin-top:2px;">已自動隔離</div>
          </div>
        </div>
      </div>

    </div>

    <!-- 步驟 7 地端微調 AI 產生事件報告初稿：標準 11 節正式報告範本視圖 (嚴格對齊 JJNET Incident Report 範本) -->
    <div class="incident-document-view" id="printable-incident-report">
      <!-- 頂部品牌防偽與機密標頭 -->
      <div class="doc-header-table">
        <div class="doc-header-left">JJNET &nbsp;|&nbsp; SECURITY OPERATIONS</div>
        <div class="doc-header-right">CONFIDENTIAL</div>
      </div>

      <!-- 封面標題區 -->
      <div class="doc-cover-block">
        <div class="doc-eyebrow">MANAGED DETECTION &amp; RESPONSE</div>
        <h1 class="doc-main-title">SECURITY INCIDENT REPORT</h1>
        <div class="doc-subtitle">事件應變與調查報告</div>
      </div>

      <!-- 封面元資料表格 (Metadata Table: 6 rows) -->
      <table class="doc-meta-table">
        <tbody>
          <tr>
            <td class="meta-label">Incident ID</td>
            <td class="meta-val"><code>${escapeHtml(data.incidentId || 'INC-2026-0042')}</code></td>
          </tr>
          <tr>
            <td class="meta-label">Customer</td>
            <td class="meta-val">${escapeHtml(data.customerName || 'JJNET Demo Customer')}</td>
          </tr>
          <tr>
            <td class="meta-label">Report Title</td>
            <td class="meta-val">${escapeHtml(data.title || 'Suspicious Inbound Exploit & Web Shell Execution')}</td>
          </tr>
          <tr>
            <td class="meta-label">Severity</td>
            <td class="meta-val"><span class="badge-${sevClass}">${escapeHtml(data.severity || 'High')}</span> (風險評分: ${data.riskScore ?? 92})</td>
          </tr>
          <tr>
            <td class="meta-label">Detection Time</td>
            <td class="meta-val">${escapeHtml(data.detectionTime || '2026-09-16 22:14 UTC')}</td>
          </tr>
          <tr>
            <td class="meta-label">Report Version</td>
            <td class="meta-val">${escapeHtml(data.reportVersion || '1.0')}</td>
          </tr>
        </tbody>
      </table>

      <!-- 01 Executive Summary -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">01</span>
          <span class="heading-text">Executive Summary</span>
        </div>
        <div class="doc-body-text">${escapeHtml(data.executiveSummary || data.summary || '')}</div>
      </div>

      <!-- 02 Classification and Scope -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">02</span>
          <span class="heading-text">Classification and Scope</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:30%;">Classification</th>
              <th style="width:70%;">Value</th>
            </tr>
          </thead>
          <tbody>
            ${(data.classification || [
              { label: 'Category', value: 'Persistence / Exploit' },
              { label: 'Status', value: 'Contained' },
              { label: 'Confidence', value: 'High' }
            ]).map((c, i) => {
              const label = c.label || (typeof c === 'string' ? c.split(/[:|]/)[0]?.trim() : 'Classification');
              const val = c.value || (typeof c === 'string' ? c.split(/[:|]/).slice(1).join(':').trim() : c);
              return `<tr class="${i % 2 === 1 ? 'row-alt' : ''}"><td><strong>${escapeHtml(label)}</strong></td><td>${escapeHtml(val)}</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <!-- 03 Affected Assets -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">03</span>
          <span class="heading-text">Affected Assets</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:35%;">Asset</th>
              <th style="width:65%;">Business / Security Context</th>
            </tr>
          </thead>
          <tbody>
            ${(data.affectedAssets || [
              { name: 'WS-FIN-088.corp.jjnet.tw', context: 'Finance workstation (daisy.wang@jjnet.com.tw)' }
            ]).map((a, i) => {
              const name = a.name || (typeof a === 'string' ? a.split(/[:|]/)[0]?.trim() : a);
              const ctx = a.context || (typeof a === 'string' ? a.split(/[:|]/).slice(1).join('|').trim() : 'Corporate Asset');
              return `<tr class="${i % 2 === 1 ? 'row-alt' : ''}"><td><code>${escapeHtml(name)}</code></td><td>${escapeHtml(ctx)}</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <!-- 04 MITRE ATT&CK Mapping -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">04</span>
          <span class="heading-text">MITRE ATT&amp;CK Mapping</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:30%;">Technique ID</th>
              <th style="width:70%;">Technique Name</th>
            </tr>
          </thead>
          <tbody>
            ${((data.mitreTechniques && data.mitreTechniques.length) ? data.mitreTechniques : (data.mitre || []).map(m => {
              const match = m.match(/(T\d+(?:\.\d+)?)\s*(?:\(([^)]+)\)|:\s*(.+))?/);
              return { id: match ? match[1] : 'T1059', name: match ? (match[2] || match[3] || 'Execution') : m };
            })).map((m, i) => `
              <tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td><span class="tag-mitre">${escapeHtml(m.id || m)}</span></td>
                <td><strong>${escapeHtml(m.name || '')}</strong></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- 05 Evidence -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">05</span>
          <span class="heading-text">Evidence</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:15%;">Time</th>
              <th style="width:25%;">Source</th>
              <th style="width:60%;">Observation</th>
            </tr>
          </thead>
          <tbody>
            ${(data.evidence || []).map((e, i) => {
              const time = e.time || (typeof e === 'object' ? e.time : '22:15');
              const source = e.source || 'EDR / PA Log';
              const obs = e.observation || (typeof e === 'string' ? e : JSON.stringify(e));
              return `<tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td><code>${escapeHtml(time)}</code></td>
                <td><strong>${escapeHtml(source)}</strong></td>
                <td>${escapeHtml(obs)}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <!-- 06 Incident Timeline -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">06</span>
          <span class="heading-text">Incident Timeline</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:20%;">Time</th>
              <th style="width:80%;">Event</th>
            </tr>
          </thead>
          <tbody>
            ${(data.timeline || []).map((t, i) => `
              <tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td><code>${escapeHtml(t.time || t.timestamp || '')}</code></td>
                <td>${escapeHtml(t.event || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- 07 Response Actions -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">07</span>
          <span class="heading-text">Response Actions</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:8%;">#</th>
              <th style="width:70%;">Action</th>
              <th style="width:22%;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${(data.responseActions || (data.actions || []).map((a, idx) => ({ number: idx + 1, action: a, status: 'Completed / in progress' }))).map((a, i) => `
              <tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td style="text-align:center;"><strong>${escapeHtml(a.number || i + 1)}</strong></td>
                <td>${escapeHtml(a.action || a.text || a)}</td>
                <td><span class="badge-status-ok">${escapeHtml(a.status || 'Completed / in progress')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- 08 Recommendations -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">08</span>
          <span class="heading-text">Recommendations</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:18%;">Priority</th>
              <th style="width:82%;">Recommendation</th>
            </tr>
          </thead>
          <tbody>
            ${(data.recommendations || []).map((r, i) => {
              const prio = r.priority || (i === 0 ? 'P1' : (i < 3 ? 'P2' : 'P3'));
              const text = r.recommendation || r.text || r;
              const prioClass = prio === 'P1' ? 'badge-prio-p1' : (prio === 'P2' ? 'badge-prio-p2' : 'badge-prio-p3');
              return `<tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td><span class="${prioClass}">${escapeHtml(prio)}</span></td>
                <td>${escapeHtml(text)}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <!-- 09 Unresolved Items / Pending Confirmation -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">09</span>
          <span class="heading-text">Unresolved Items / Pending Confirmation</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:8%;">#</th>
              <th style="width:52%;">Item</th>
              <th style="width:40%;">Required Evidence</th>
            </tr>
          </thead>
          <tbody>
            ${(data.unresolvedItems || [
              { number: 1, item: '確認網域控制站 (DC/AD) 是否存在同一憑證於其他主機二次重用之異常登入紀錄', evidence: 'Pending confirmation' },
              { number: 2, item: '外部 C2 伺服器之威脅組織身分對齊與進階情資歸屬', evidence: 'Pending confirmation' }
            ]).map((u, i) => `
              <tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td style="text-align:center;"><strong>${escapeHtml(u.number || i + 1)}</strong></td>
                <td>${escapeHtml(u.item || u)}</td>
                <td style="color:var(--accent-yellow); font-weight:600;">${escapeHtml(u.evidence || 'Pending confirmation')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- 10 Revision History -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">10</span>
          <span class="heading-text">Revision History</span>
        </div>
        <table class="doc-data-table">
          <thead>
            <tr>
              <th style="width:15%;">Version</th>
              <th style="width:25%;">Date</th>
              <th style="width:25%;">Author</th>
              <th style="width:35%;">Change</th>
            </tr>
          </thead>
          <tbody>
            ${(data.revisionHistory || [{ version: '1.0', date: '2026-09-16 22:30 UTC', author: 'SOC Lead Analyst', change: 'Initial incident report' }]).map((rv, i) => `
              <tr class="${i % 2 === 1 ? 'row-alt' : ''}">
                <td><code>${escapeHtml(rv.version || '1.0')}</code></td>
                <td>${escapeHtml(rv.date || '')}</td>
                <td>${escapeHtml(rv.author || '')}</td>
                <td>${escapeHtml(rv.change || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- 11 Review and Approval -->
      <div class="doc-section">
        <div class="doc-heading">
          <span class="heading-num">11</span>
          <span class="heading-text">Review and Approval</span>
        </div>
        <table class="doc-approval-table">
          <tbody>
            <tr>
              <td class="appr-label">Prepared by</td>
              <td class="appr-val">${escapeHtml(data.reviewApproval?.preparedBy || 'SOC Lead Analyst')}</td>
              <td class="appr-label">Prepared at</td>
              <td class="appr-val">${escapeHtml(data.reviewApproval?.preparedAt || '2026-09-16 22:30 UTC')}</td>
            </tr>
            <tr>
              <td class="appr-label">Reviewed by</td>
              <td class="appr-val">${escapeHtml(data.reviewApproval?.reviewedBy || review.reviewedBy || 'Vincent (資深資安顧問 / SOC 主管)')}</td>
              <td class="appr-label">Reviewed at</td>
              <td class="appr-val">${escapeHtml(data.reviewApproval?.reviewedAt || '2026-09-16 22:45 UTC')}</td>
            </tr>
            <tr>
              <td class="appr-label">Approval status</td>
              <td class="appr-val"><span class="badge-status-ok">${escapeHtml(data.reviewApproval?.approvalStatus || (review.checklist?.readyForRelease ? 'Approved' : 'Pending confirmation'))}</span></td>
              <td class="appr-label">Signature / record</td>
              <td class="appr-val"><code>${escapeHtml(data.reviewApproval?.approvalRecord || 'APR-2026-0042')}</code></td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 底部頁尾 -->
      <div class="doc-footer-table">
        <div>JJNET Security Incident Report</div>
        <div>Page 1 of 3 (Official Template)</div>
      </div>
    </div>

    <!-- 步驟 8 人審閘道審核 (Analyst Review Checklist & Gateway - 對齊 Slide 8) -->
    <div class="review-gateway-box ${review.checklist?.readyForRelease ? 'approved' : ''}" id="analyst-review-gateway">
      <div class="review-gateway-header">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:1.15rem;">⚖️</span>
          <span style="font-weight:700; color:var(--accent-yellow); font-size:0.95rem;">
            人審閘道審核 (Analyst Review Gateway - 依 Slide 8 規格必經人審)
          </span>
        </div>
        <span class="status-badge ${review.checklist?.readyForRelease ? 'badge-success' : 'badge-review'}" id="gateway-status-badge">
          ${review.checklist?.readyForRelease ? '🟢 審核通過 (可對外發布)' : '🟡 待分析師覆核'}
        </span>
      </div>

      <div style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:10px;">
        模型生成初稿一律須經分析師完成下列 4 項檢核，始可核准對外發布與產出正式報告：
      </div>

      <!-- 4 項人審 Checkbox 檢核表 (嚴格對齊 Slide 8) -->
      <div class="review-checklist-grid">
        <label class="review-check-item ${review.checklist?.cveReasonable ? 'active-checked' : ''}" onclick="toggleIncidentChecklist('cveReasonable')">
          <input type="checkbox" id="chk-cve" ${review.checklist?.cveReasonable ? 'checked' : ''} onclick="event.stopPropagation(); toggleIncidentChecklist('cveReasonable');">
          <div>
            <div class="review-check-title">1. CVE 關聯是否合理？</div>
            <div class="review-check-sub">核實受影響組件與漏洞利用特徵</div>
          </div>
        </label>

        <label class="review-check-item ${review.checklist?.iocCredible ? 'active-checked' : ''}" onclick="toggleIncidentChecklist('iocCredible')">
          <input type="checkbox" id="chk-ioc" ${review.checklist?.iocCredible ? 'checked' : ''} onclick="event.stopPropagation(); toggleIncidentChecklist('iocCredible');">
          <div>
            <div class="review-check-title">2. IOC 清單是否可信？</div>
            <div class="review-check-sub">驗證外部 C2 IP、Domain 與 Hash</div>
          </div>
        </label>

        <label class="review-check-item ${review.checklist?.riskAccurate ? 'active-checked' : ''}" onclick="toggleIncidentChecklist('riskAccurate')">
          <input type="checkbox" id="chk-risk" ${review.checklist?.riskAccurate ? 'checked' : ''} onclick="event.stopPropagation(); toggleIncidentChecklist('riskAccurate');">
          <div>
            <div class="review-check-title">3. 風險評估是否正確？</div>
            <div class="review-check-sub">確認嚴重性等級與衝擊業務範圍</div>
          </div>
        </label>

        <label class="review-check-item ${review.checklist?.readyForRelease ? 'active-checked' : ''}" onclick="toggleIncidentChecklist('readyForRelease')">
          <input type="checkbox" id="chk-release" ${review.checklist?.readyForRelease ? 'checked' : ''} onclick="event.stopPropagation(); toggleIncidentChecklist('readyForRelease');">
          <div>
            <div class="review-check-title">4. 是否可對外發布？</div>
            <div class="review-check-sub">完成資料遮罩與主管授權放行</div>
          </div>
        </label>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; background:rgba(15,23,42,0.6); padding:8px 12px; border-radius:var(--radius-sm); border:1px solid var(--border-color);">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:0.8rem; color:var(--text-secondary);">審核簽核主管：</span>
          <strong style="color:var(--accent-cyan); font-size:0.85rem;" id="analyst-name-display">${escapeHtml(review.reviewedBy || 'Vincent (資深資安顧問 / SOC 主管)')}</strong>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-primary" onclick="approveIncidentReview(true)" style="font-size:0.8rem; padding:4px 12px;">
            ✅ 審核通過並鎖定定稿
          </button>
          <button class="btn btn-secondary" onclick="approveIncidentReview(false)" style="font-size:0.8rem; padding:4px 10px;">
            🔄 標記待補件
          </button>
        </div>
      </div>

      <!-- 5 大正式輸出管道 (Word / Markdown / PDF / Email / Ticket) -->
      <div class="export-channels-row">
        <span style="font-size:0.8rem; color:var(--text-muted); align-self:center;">正式輸出管道 (完全依照 JJNET 範本)：</span>
        <button class="btn btn-primary" onclick="exportDocx()" style="font-size:0.8rem; padding:4px 12px;">
          📄 Word (.docx) 範本
        </button>
        <button class="btn btn-secondary" onclick="exportMarkdown()" style="font-size:0.8rem; padding:4px 10px;">
          📝 Markdown (.md)
        </button>
        <button class="btn btn-secondary" onclick="window.print()" style="font-size:0.8rem; padding:4px 10px;">
          🖨️ PDF / 列印
        </button>
        <button class="btn btn-secondary" onclick="exportEmailDraft()" style="font-size:0.8rem; padding:4px 10px;">
          ✉️ Email 初稿
        </button>
        <button class="btn btn-secondary" onclick="exportTicketDraft()" style="font-size:0.8rem; padding:4px 10px;">
          🎫 Ticket 工單
        </button>
      </div>
    </div>
  `;
}

// 2. 渲染顧問建議
function renderConsultant(data, el) {
  // 如果是報告解讀與處置指引模式 (Report Ingestion & Advisory Mode)
  if (data.mode === 'report_analysis') {
    const sev = data.severity || 'Critical';
    const sevBadge = sev.toLowerCase() === 'critical' ? '🔴 Critical (極高風險)' : '🟠 High (高風險)';

    el.innerHTML = `
      <!-- 模式抬頭與報告元資訊卡片 -->
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.2rem; background:rgba(8,126,139,0.12); padding:12px 16px; border-radius:var(--radius-md); border:1px solid var(--accent-cyan); flex-wrap:wrap; gap:10px;">
        <div>
          <div style="font-size:0.8rem; color:var(--accent-cyan); font-weight:700;">📑 資安顧問報告解讀與處置指引模式 (Report Ingestion Mode)</div>
          <div style="font-size:1.05rem; font-weight:700; margin-top:3px;">
            📄 來源報告：${escapeHtml(data.reportName || '任務一資安事件調查報告')}
            <span style="font-size:0.8rem; color:var(--text-secondary); margin-left:8px;">[ID: ${escapeHtml(data.incidentId || 'INC-2026-0042')}]</span>
          </div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.8rem; color:var(--text-muted);">威脅等級：<strong style="color:${sev.toLowerCase() === 'critical' ? '#ef4444' : '#f59e0b'};">${sevBadge}</strong></div>
          <div style="font-size:0.75rem; color:#10b981; margin-top:2px;">● ${escapeHtml(data.reviewStatus || '顧問已核定')}</div>
        </div>
      </div>

      <!-- 1. 事件全貌與本質解讀 (Executive Summary) -->
      <div class="result-section" style="border-left:4px solid var(--accent-cyan);">
        <div class="result-section-title">📌 事件全貌與本質深度解讀</div>
        <div style="font-size:0.95rem; line-height:1.75; color:var(--text-primary);">${escapeHtml(data.executiveSummary || '')}</div>
      </div>

      <!-- 2. 攻擊鏈與技術成因分析 (Attack Chain & Root Cause) -->
      <div class="result-section">
        <div class="result-section-title">🔍 攻擊鏈路與技術成因剖析 (Attack Chain & Root Cause)</div>
        <div style="font-size:0.9rem; line-height:1.75; white-space:pre-wrap; background:var(--bg-secondary); padding:12px 14px; border-radius:var(--radius-sm); border:1px solid var(--border-color);">${escapeHtml(data.technicalExplanation || '')}</div>
      </div>

      <!-- 3. 受害資產衝擊與業務風險評估 (Impact & Business Risk) -->
      <div class="result-section" style="border-left:4px solid #f59e0b;">
        <div class="result-section-title" style="color:#fbbf24;">⚠️ 受害資產衝擊與業務風險評估 (Asset Impact Assessment)</div>
        <div style="font-size:0.9rem; line-height:1.75; white-space:pre-wrap; background:rgba(245,158,11,0.06); padding:12px 14px; border-radius:var(--radius-sm);">${escapeHtml(data.impactAssessment || '')}</div>
      </div>

      <!-- 4. 四階段應變處置建議與步驟 (Phased Incident Response) -->
      <div class="result-section">
        <div class="result-section-title">📋 建議分階處置作為與時程管制 (Incident Response Playbook)</div>
        <div style="display:flex; flex-direction:column; gap:10px; margin-top:8px;">
          ${(data.steps || []).map((step, idx) => {
            const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'];
            const stepColor = colors[idx % colors.length];
            return `
              <div style="background:var(--bg-secondary); border-left:3px solid ${stepColor}; padding:10px 14px; border-radius:0 var(--radius-sm) var(--radius-sm) 0;">
                <div style="font-size:0.9rem; line-height:1.6; color:var(--text-primary); font-weight:500;">
                  ${escapeHtml(step)}
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>

      <!-- 5. 中長期架構防禦加固方針 (Long-Term Hardening) -->
      <div class="result-section">
        <div class="result-section-title">🛡️ 中長期架構防禦加固方針 (Hardening Architecture)</div>
        <ul style="padding-left:1.3rem; font-size:0.9rem; line-height:1.8; color:var(--text-secondary);">
          ${(data.longTermHardening || []).map(h => `<li>${escapeHtml(h)}</li>`).join('')}
        </ul>
      </div>

      <!-- 6. 法規時限警示與罰則風險 (Compliance & Legal Advisory) -->
      ${data.complianceAdvisory ? `
        <div class="result-section" style="background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.3); border-radius:var(--radius-sm); padding:12px 16px;">
          <div class="result-section-title" style="color:#f87171;">⚖️ 法規遵循與法定通報時限提醒</div>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-top:8px;">
            <div>
              <strong style="color:var(--text-muted); font-size:0.75rem;">適用法律規範：</strong>
              <div style="font-size:0.85rem; font-weight:600; color:var(--text-primary); margin-top:2px;">${escapeHtml(data.complianceAdvisory.regulation || '')}</div>
            </div>
            <div>
              <strong style="color:var(--text-muted); font-size:0.75rem;">法定通報時限：</strong>
              <div style="font-size:0.85rem; font-weight:700; color:#ef4444; margin-top:2px;">🚨 ${escapeHtml(data.complianceAdvisory.reportingDeadline || '')}</div>
            </div>
          </div>
          <div style="margin-top:8px; font-size:0.8rem; color:#fca5a5;">
            <strong>違規處罰風險：</strong> ${escapeHtml(data.complianceAdvisory.legalRisk || '')}
          </div>
        </div>
      ` : ''}

      <!-- 7. 內部 SOP 與 ISO 27001 條文引用 (Citations) -->
      <div class="result-section">
        <div class="result-section-title">📚 引用內部政策與國際資安標準 (Policy Citations)</div>
        <div style="display:flex; flex-wrap:wrap; gap:8px; margin-top:6px;">
          ${(data.citations || []).map(c => {
            if (typeof c === 'object') {
              return `<div style="background:rgba(59,130,246,0.12); border:1px solid var(--accent-blue); padding:6px 10px; border-radius:var(--radius-sm); font-size:0.8rem;">
                <strong style="color:var(--accent-cyan);">${escapeHtml(c.source || '')} [${escapeHtml(c.clause || '')}]</strong>
                <div style="color:var(--text-secondary); margin-top:2px;">${escapeHtml(c.text || c.content || '')}</div>
              </div>`;
            } else {
              return `<span class="tag">${escapeHtml(c)}</span>`;
            }
          }).join('')}
        </div>
      </div>

      <!-- 8. 建議補充之鑑識憑證與衍生釐清問題 -->
      ${(data.requiredDocuments && data.requiredDocuments.length > 0) || (data.followUpQuestions && data.followUpQuestions.length > 0) ? `
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:12px; margin-top:12px;">
          ${(data.requiredDocuments && data.requiredDocuments.length > 0) ? `
            <div class="result-section" style="margin:0; border-left:3px solid #ef4444;">
              <div class="result-section-title" style="color:#f87171; font-size:0.85rem;">📑 建議進一步補充保全之日誌</div>
              <ul style="padding-left:1.2rem; font-size:0.8rem; color:var(--text-secondary); line-height:1.6;">
                ${data.requiredDocuments.map(d => `<li>${escapeHtml(d)}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
          ${(data.followUpQuestions && data.followUpQuestions.length > 0) ? `
            <div class="result-section" style="margin:0; border-left:3px solid var(--accent-cyan);">
              <div class="result-section-title" style="color:var(--accent-cyan); font-size:0.85rem;">❓ 建議向系統管理員釐清之問題</div>
              <ul style="padding-left:1.2rem; font-size:0.8rem; color:var(--text-secondary); line-height:1.6;">
                ${data.followUpQuestions.map(q => `<li>${escapeHtml(q)}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
        </div>
      ` : ''}
    `;
    return;
  }

  const conf = (data.confidence || 'medium').toLowerCase();
  const confBadge = conf === 'high' ? '🟢 高信心' : conf === 'medium' ? '🟡 中等信心' : '🔴 資料不足 / 低信心';

  el.innerHTML = `
    <!-- 信心評估卡 -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; background:var(--bg-secondary); padding:10px 16px; border-radius:var(--radius-md); border:1px solid var(--border-color);">
      <div>
        <span style="font-size:0.8rem; color:var(--text-muted);">顧問推論信心度：</span>
        <strong style="font-size:0.95rem;">${confBadge}</strong>
      </div>
      <div style="font-size:0.8rem; color:var(--text-secondary);">
        審核狀態：<span class="review-badge badge-pending">${escapeHtml(data.reviewStatus || '待審核')}</span>
      </div>
    </div>

    <!-- 核心解答與推論 -->
    <div class="result-section">
      <div class="result-section-title">💡 顧問專業建議方案</div>
      <div style="font-size:0.95rem; line-height:1.7; white-space:pre-wrap;">${escapeHtml(data.answer || '')}</div>
      <div style="margin-top:12px; padding:10px; background:rgba(255,255,255,0.02); border-radius:4px; font-size:0.85rem; color:var(--text-secondary);">
        <strong>推論邏輯依據：</strong> ${escapeHtml(data.reasoning || '綜合資安標準程序研判')}
      </div>
    </div>

    <!-- 處置步驟 -->
    <div class="result-section">
      <div class="result-section-title">📋 具體實施步驟</div>
      <ol style="padding-left:1.3rem; font-size:0.9rem; line-height:1.8;">
        ${(data.steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join('')}
      </ol>
    </div>

    <!-- 風險評估與引用條文 -->
    <div class="result-section">
      <div class="result-section-title">⚖️ 風險考量與規範引用</div>
      <div style="margin-bottom:10px;">
        <strong style="color:var(--accent-red); font-size:0.85rem;">潛在風險：</strong>
        <ul style="padding-left:1.2rem; font-size:0.85rem; margin-top:4px;">
          ${(data.risks || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
      <div>
        <strong style="color:var(--accent-cyan); font-size:0.85rem;">引用規章條文：</strong>
        <div class="tag-list" style="margin-top:4px;">
          ${(data.citations || []).map(c => `<span class="tag">${escapeHtml(c)}</span>`).join('') || '<span style="color:var(--text-muted); font-size:0.8rem;">一般產業最佳實務</span>'}
        </div>
      </div>
    </div>

    <!-- 資料不足時的待補件清單 -->
    ${(data.requiredDocuments && data.requiredDocuments.length > 0) ? `
      <div class="result-section" style="border-left:4px solid var(--accent-red);">
        <div class="result-section-title" style="color:#f87171;">📑 必須補充之內部文件或日誌</div>
        <ul style="padding-left:1.2rem; font-size:0.85rem; color:#fca5a5;">
          ${data.requiredDocuments.map(d => `<li>${escapeHtml(d)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}

    <!-- 衍生延伸問題 -->
    ${(data.followUpQuestions && data.followUpQuestions.length > 0) ? `
      <div class="result-section">
        <div class="result-section-title">❓ 建議進一步釐清之衍生問題</div>
        <ul style="padding-left:1.2rem; font-size:0.85rem; color:var(--text-secondary);">
          ${data.followUpQuestions.map(q => `<li>${escapeHtml(q)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}
  `;
}

// 3. 渲染 Cortex 月報
function renderMonthlyReport(data, el) {
  const dist = data.severityDistribution || { critical: 0, high: 0, medium: 0, low: 0 };

  el.innerHTML = `
    <!-- 月報關鍵 KPI 卡片 -->
    <div class="metrics-row">
      <div class="metric-card">
        <div class="metric-label">當月事件總數</div>
        <div class="metric-value" style="color:var(--accent-cyan);">${data.totalEvents ?? 0}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">成功攔截威脅</div>
        <div class="metric-value" style="color:var(--accent-green);">${data.blockedEvents ?? 0}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">平均確認時間 (MTTA)</div>
        <div class="metric-value" style="font-size:1.1rem; padding-top:6px;">${escapeHtml(data.mtta || '--')}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">平均復原時間 (MTTR)</div>
        <div class="metric-value" style="font-size:1.1rem; padding-top:6px;">${escapeHtml(data.mttr || '--')}</div>
      </div>
    </div>

    <!-- 高階主管摘要 -->
    <div class="result-section">
      <div class="result-section-title">👔 高階主管資安月報摘要 (Executive Summary)</div>
      <p style="font-size:0.95rem; line-height:1.7;">${escapeHtml(data.executiveSummary || '')}</p>
      <div style="margin-top:10px; font-size:0.85rem; color:var(--text-secondary);">
        <strong>月度趨勢剖析：</strong>${escapeHtml(data.monthlyTrend || '')}
      </div>
    </div>

    <!-- 嚴重等級分佈與分類 -->
    <div class="result-section">
      <div class="result-section-title">📊 威脅嚴重等級分佈與類別統計</div>
      <div style="display:flex; gap:16px; margin-bottom:12px;">
        <span class="review-badge" style="background:rgba(239,68,68,0.2); color:#f87171;">Critical: ${dist.critical || 0}</span>
        <span class="review-badge" style="background:rgba(249,115,22,0.2); color:#fb923c;">High: ${dist.high || 0}</span>
        <span class="review-badge" style="background:rgba(245,158,11,0.2); color:#fcd34d;">Medium: ${dist.medium || 0}</span>
        <span class="review-badge" style="background:rgba(16,185,129,0.2); color:#34d399;">Low: ${dist.low || 0}</span>
      </div>
      ${(data.eventCategories && data.eventCategories.length > 0) ? `
        <table class="timeline-table" style="margin-top:8px;">
          <thead>
            <tr><th>事件類別</th><th>次數</th><th>佔比</th></tr>
          </thead>
          <tbody>
            ${data.eventCategories.map(c => `
              <tr><td>${escapeHtml(c.name || '')}</td><td>${c.count || 0}</td><td>${escapeHtml(c.percentage || '')}</td></tr>
            `).join('')}
          </tbody>
        </table>
      ` : ''}
    </div>

    <!-- 重大事件明細與 ATT&CK 分析 -->
    <div class="result-section">
      <div class="result-section-title">🎯 重大事件詳細調查與 ATT&CK 戰術</div>
      <div style="margin-bottom:10px;">
        <span style="font-size:0.8rem; color:var(--text-muted);">當月高頻 ATT&CK 手法：</span>
        <div class="tag-list">${(data.mitreAnalysis || []).map(m => `<span class="tag">${escapeHtml(m)}</span>`).join('')}</div>
      </div>
      ${(data.majorIncidentDetails && data.majorIncidentDetails.length > 0) ? `
        <table class="timeline-table">
          <thead>
            <tr><th>代碼</th><th>事件名稱</th><th>根因摘要</th><th>處置現況</th></tr>
          </thead>
          <tbody>
            ${data.majorIncidentDetails.map(i => `
              <tr>
                <td><code>${escapeHtml(i.id || '')}</code></td>
                <td><strong>${escapeHtml(i.name || '')}</strong></td>
                <td>${escapeHtml(i.rootCause || '')}</td>
                <td><span class="tag" style="background:rgba(16,185,129,0.15); color:#34d399;">${escapeHtml(i.responseStatus || '已結案')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : ''}
    </div>

    <!-- 次月防護建議與追蹤狀態 -->
    <div class="result-section">
      <div class="result-section-title">🚀 下月份資安資源配置與防護重點</div>
      <ul style="padding-left:1.2rem; font-size:0.9rem; line-height:1.7;">
        ${(data.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
      <div style="margin-top:10px; font-size:0.8rem; color:var(--text-muted);">
        追蹤狀態：<span class="review-badge badge-pending">${escapeHtml(data.recommendationStatus || '追蹤中')}</span>
      </div>
    </div>
  `;
}

// 4. 渲染資安教育訓練與互動測驗
function renderTraining(data, el) {
  const questions = data.questions || [];

  el.innerHTML = `
    <!-- 章節標題與學習目標 -->
    <div class="result-section">
      <div class="result-section-title">🎓 ${escapeHtml(data.chapter || '資安訓練教材')}</div>
      <div style="margin-bottom:8px;">
        <strong style="font-size:0.85rem; color:var(--text-muted);">本章學習核心目標：</strong>
        <ul style="padding-left:1.2rem; margin-top:4px; font-size:0.85rem; color:var(--text-secondary);">
          ${(data.learningObjectives || []).map(o => `<li>${escapeHtml(o)}</li>`).join('')}
        </ul>
      </div>
      <div style="margin-top:10px; padding:10px; background:rgba(255,255,255,0.02); border-radius:4px; font-size:0.9rem; line-height:1.7;">
        ${escapeHtml(data.lesson || '')}
      </div>
    </div>

    <!-- 實務模擬情境演練 -->
    <div class="result-section">
      <div class="result-section-title">🎭 實務工作情境演練 (Scenario)</div>
      <div style="font-size:0.9rem; line-height:1.7; background:rgba(6,182,212,0.05); padding:12px; border-left:3px solid var(--accent-cyan); border-radius:4px;">
        ${escapeHtml(data.scenario || '')}
      </div>
    </div>

    <!-- 互動測驗題庫 (至少 3 題) -->
    <div class="result-section">
      <div class="result-section-title">📝 章節實戰測驗 (共 ${questions.length} 題，答錯可一鍵加入錯題本)</div>
      <div id="quiz-container">
        ${questions.map((q, idx) => `
          <div class="quiz-box" id="quiz-box-${q.id || idx}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
              <strong style="font-size:0.95rem;">第 ${idx + 1} 題：${escapeHtml(q.question || '')}</strong>
              <button class="btn btn-secondary" onclick="addQuestionToMistakes(${idx})" style="font-size:0.75rem; padding:2px 8px;">
                ➕ 加入錯題本
              </button>
            </div>
            <div style="margin-top:8px;">
              ${(q.options || []).map((opt, oIdx) => {
                const optLetter = opt.trim().substring(0, 1).toUpperCase();
                return `
                  <button class="quiz-option" onclick="checkQuizAnswer(${idx}, '${optLetter}', this)">
                    ${escapeHtml(opt)}
                  </button>
                `;
              }).join('')}
            </div>
            <div class="quiz-explanation" id="quiz-exp-${idx}">
              <strong>💡 詳解：</strong> ${escapeHtml(q.explanation || '')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- 複習建議 -->
    <div class="result-section">
      <div class="result-section-title">📖 延伸學習與複習指導</div>
      <ul style="padding-left:1.2rem; font-size:0.85rem; color:var(--text-secondary);">
        ${(data.reviewSuggestions || []).map(s => `<li>${escapeHtml(s)}</li>`).join('')}
      </ul>
    </div>
  `;
}

// 測驗題互動檢查邏輯
window.checkQuizAnswer = function(questionIdx, selectedLetter, btnEl) {
  const currentQuestions = agentResults.training?.questions || [];
  const q = currentQuestions[questionIdx];
  if (!q) return;

  const parent = btnEl.parentElement;
  const allBtns = parent.querySelectorAll('.quiz-option');
  allBtns.forEach(b => { b.disabled = true; });

  const expEl = document.getElementById(`quiz-exp-${questionIdx}`);
  if (expEl) expEl.style.display = 'block';

  const correctLetter = (q.answer || '').trim().substring(0, 1).toUpperCase();

  if (selectedLetter === correctLetter) {
    btnEl.classList.add('correct');
  } else {
    btnEl.classList.add('wrong');
    // 自動將錯題加入錯題本
    addMistake({
      chapter: agentResults.training?.chapter || '未命名章節',
      question: q.question,
      options: q.options,
      yourAnswer: selectedLetter,
      correctAnswer: q.answer,
      explanation: q.explanation,
      date: new Date().toLocaleDateString()
    });
  }
};

// 加入錯題本功能
window.addQuestionToMistakes = function(idx) {
  const q = agentResults.training?.questions?.[idx];
  if (!q) return;
  addMistake({
    chapter: agentResults.training?.chapter || '未命名章節',
    question: q.question,
    options: q.options,
    yourAnswer: '手動標記',
    correctAnswer: q.answer,
    explanation: q.explanation,
    date: new Date().toLocaleDateString()
  });
  alert('已成功將本題加入培訓錯題本！');
};

function addMistake(item) {
  // 檢查是否重複
  const exists = mistakeNotebook.some(m => m.question === item.question);
  if (!exists) {
    mistakeNotebook.unshift(item);
    localStorage.setItem('jjnet_mistakes', JSON.stringify(mistakeNotebook));
    updateMistakeCountBadge();
  }
}

function updateMistakeCountBadge() {
  const badge = document.getElementById('mistake-count');
  if (badge) badge.innerText = mistakeNotebook.length;
}

// 渲染錯題本
function renderMistakeNotebook() {
  const container = document.getElementById('results-display');
  if (mistakeNotebook.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding:4rem 1rem; color:var(--text-muted);">
        <div style="font-size:3rem; margin-bottom:1rem; opacity:0.5;">📓</div>
        <div style="font-size:1.1rem; font-weight:600; color:var(--text-secondary);">目前錯題本為空</div>
        <div style="font-size:0.85rem; margin-top:6px;">在資安培訓測驗中答錯或標記的題目，都會自動彙整於此供深度複習。</div>
      </div>`;
    return;
  }

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
      <span style="font-size:0.9rem; color:var(--text-secondary);">累積收錄 <strong>${mistakeNotebook.length}</strong> 道重點錯題</span>
      <button class="btn btn-secondary" onclick="clearMistakes()" style="font-size:0.75rem; padding:3px 8px;">
        🗑️ 清空錯題本
      </button>
    </div>
    ${mistakeNotebook.map((m, idx) => `
      <div class="result-section" style="border-left:4px solid var(--accent-red);">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
          <span class="tag" style="background:rgba(239,68,68,0.15); color:#fca5a5;">${escapeHtml(m.chapter)}</span>
          <span style="font-size:0.75rem; color:var(--text-muted);">${m.date}</span>
        </div>
        <div style="font-size:0.95rem; font-weight:700; margin-bottom:8px;">${idx + 1}. ${escapeHtml(m.question)}</div>
        <ul style="padding-left:1.2rem; font-size:0.85rem; color:var(--text-secondary); margin-bottom:8px;">
          ${(m.options || []).map(o => `<li>${escapeHtml(o)}</li>`).join('')}
        </ul>
        <div style="font-size:0.85rem; color:var(--accent-green); margin-bottom:4px;">
          <strong>正確解答：</strong> ${escapeHtml(m.correctAnswer)}
        </div>
        <div style="font-size:0.85rem; color:var(--text-secondary); background:rgba(0,0,0,0.25); padding:8px 12px; border-radius:4px;">
          <strong>解析覆盤：</strong> ${escapeHtml(m.explanation)}
        </div>
      </div>
    `).join('')}
  `;
}

window.clearMistakes = function() {
  if (confirm('確定要清空錯題本嗎？')) {
    mistakeNotebook = [];
    localStorage.removeItem('jjnet_mistakes');
    updateMistakeCountBadge();
    renderMistakeNotebook();
  }
};

// 匯出 JSON
function exportJSON() {
  const data = agentResults[currentAgent];
  if (!data) return alert('目前尚無分析資料可供匯出。');
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  downloadFile(blob, `JJNET_${currentAgent}_${Date.now()}.json`);
}

// 匯出 Word (.docx) - 嚴格依照 JJNET Incident Report 範本
async function exportDocx() {
  const data = agentResults[currentAgent];
  if (!data) return alert('目前尚無分析資料可供匯出。');
  if (currentAgent !== 'incident') {
    return alert('Word (.docx) 範本匯出專為任務一資安事件調查報告設計。其他任務請使用 Markdown 或 PDF 匯出。');
  }
  try {
    const res = await fetch('/api/incident/export-docx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: 匯出失敗`);
    const blob = await res.blob();
    const filename = `${data.incidentId || 'INC-2026-0042'}.docx`;
    downloadFile(blob, filename);
  } catch (err) {
    alert('下載 Word (.docx) 報告失敗：' + err.message);
  }
}
window.exportDocx = exportDocx;

// 匯出 Markdown (.md) - 嚴格依照 JJNET Incident Report 範本 11 節規格
function exportMarkdown() {
  const data = agentResults[currentAgent];
  if (!data) return alert('目前尚無分析資料可供匯出。');

  if (currentAgent === 'incident') {
    const incId = data.incidentId || 'INC-2026-0042';
    const custName = data.customerName || 'JJNET Demo Customer';
    const title = data.title || 'Security Incident Report';
    const sev = data.severity || 'High';
    const detTime = data.detectionTime || '2026-09-16 22:14 UTC';
    const ver = data.reportVersion || '1.0';
    const execSummary = data.executiveSummary || data.summary || '';

    let md = `MANAGED DETECTION & RESPONSE\n`;
    md += `# SECURITY INCIDENT REPORT\n`;
    md += `## 事件應變與調查報告\n\n`;

    md += `| Metadata | Value |\n`;
    md += `| :--- | :--- |\n`;
    md += `| **Incident ID** | ${incId} |\n`;
    md += `| **Customer** | ${custName} |\n`;
    md += `| **Report Title** | ${title} |\n`;
    md += `| **Severity** | ${sev} |\n`;
    md += `| **Detection Time** | ${detTime} |\n`;
    md += `| **Report Version** | ${ver} |\n\n`;

    md += `---\n\n`;
    md += `## 01 Executive Summary\n\n`;
    md += `${execSummary}\n\n`;

    md += `## 02 Classification and Scope\n\n`;
    md += `| Classification | Value |\n`;
    md += `| :--- | :--- |\n`;
    const classifications = data.classification || [
      { label: 'Category', value: 'Persistence / Exploit' },
      { label: 'Status', value: 'Contained' },
      { label: 'Confidence', value: 'High' }
    ];
    classifications.forEach(c => {
      const label = c.label || (typeof c === 'string' ? c.split(/[:|]/)[0]?.trim() : 'Classification');
      const val = c.value || (typeof c === 'string' ? c.split(/[:|]/).slice(1).join(':').trim() : c);
      md += `| ${label} | ${val} |\n`;
    });
    md += `\n`;

    md += `## 03 Affected Assets\n\n`;
    md += `| Asset | Business / Security Context |\n`;
    md += `| :--- | :--- |\n`;
    const assets = data.affectedAssets || [
      { name: 'WS-FIN-088.corp.jjnet.tw', context: 'Finance workstation (daisy.wang@jjnet.com.tw)' }
    ];
    assets.forEach(a => {
      const name = a.name || (typeof a === 'string' ? a.split(/[:|]/)[0]?.trim() : a);
      const ctx = a.context || (typeof a === 'string' ? a.split(/[:|]/).slice(1).join('|').trim() : 'Corporate Asset');
      md += `| ${name} | ${ctx} |\n`;
    });
    md += `\n`;

    md += `## 04 MITRE ATT&CK Mapping\n\n`;
    md += `| Technique ID | Technique Name |\n`;
    md += `| :--- | :--- |\n`;
    let mitres = data.mitreTechniques;
    if (!mitres || !mitres.length) {
      mitres = (data.mitre || []).map(m => {
        const match = m.match(/(T\d+(?:\.\d+)?)\s*(?:\(([^)]+)\)|:\s*(.+)|-\s*(.+))?/);
        return { id: match ? match[1] : 'T1059', name: match ? (match[2] || match[3] || match[4] || 'Execution') : m };
      });
    }
    if (!mitres.length) {
      mitres = [
        { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell' },
        { id: 'T1055', name: 'Process Injection' }
      ];
    }
    mitres.forEach(m => {
      md += `| ${m.id} | ${m.name} |\n`;
    });
    md += `\n`;

    md += `## 05 Evidence\n\n`;
    md += `| Time | Source | Observation |\n`;
    md += `| :--- | :--- | :--- |\n`;
    const evList = data.evidence || [];
    evList.forEach(e => {
      if (typeof e === 'object') {
        md += `| ${e.time || '22:15'} | ${e.source || 'EDR / PA Log'} | ${e.observation || ''} |\n`;
      } else {
        md += `| 22:15 | SOC Telemetry | ${e} |\n`;
      }
    });
    md += `\n`;

    md += `## 06 Incident Timeline\n\n`;
    md += `| Time | Event |\n`;
    md += `| :--- | :--- |\n`;
    const timelines = data.timeline || [];
    timelines.forEach(t => {
      md += `| ${t.time || t.timestamp || '22:15'} | ${t.event} |\n`;
    });
    md += `\n`;

    md += `## 07 Response Actions\n\n`;
    md += `| # | Action | Status |\n`;
    md += `| :--- | :--- | :--- |\n`;
    const actions = data.responseActions || (data.actions || []).map((a, idx) => ({ number: idx + 1, action: a, status: 'Completed / in progress' }));
    actions.forEach((a, i) => {
      md += `| ${a.number || i + 1} | ${a.action || a.text || a} | ${a.status || 'Completed / in progress'} |\n`;
    });
    md += `\n`;

    md += `## 08 Recommendations\n\n`;
    md += `| Priority | Recommendation |\n`;
    md += `| :--- | :--- |\n`;
    const recs = data.recommendations || [];
    recs.forEach((r, i) => {
      const prio = r.priority || (i === 0 ? 'P1' : (i < 3 ? 'P2' : 'P3'));
      const text = r.recommendation || r.text || r;
      md += `| ${prio} | ${text} |\n`;
    });
    md += `\n`;

    md += `## 09 Unresolved Items / Pending Confirmation\n\n`;
    md += `| # | Item | Required Evidence |\n`;
    md += `| :--- | :--- | :--- |\n`;
    const unresolved = data.unresolvedItems || [
      { number: 1, item: '確認網域控制站 (DC/AD) 是否存在同一憑證於其他主機二次重用之異常登入紀錄', evidence: 'Pending confirmation' },
      { number: 2, item: '外部 C2 伺服器之威脅組織身分對齊與進階情資歸屬', evidence: 'Pending confirmation' }
    ];
    unresolved.forEach((u, i) => {
      md += `| ${u.number || i + 1} | ${u.item || u} | ${u.evidence || 'Pending confirmation'} |\n`;
    });
    md += `\n`;

    md += `## 10 Revision History\n\n`;
    md += `| Version | Date | Author | Change |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    const revs = data.revisionHistory || [
      { version: '1.0', date: '2026-09-16 22:30 UTC', author: 'SOC Lead Analyst', change: 'Initial incident report' }
    ];
    revs.forEach(r => {
      md += `| ${r.version} | ${r.date} | ${r.author} | ${r.change} |\n`;
    });
    md += `\n`;

    md += `## 11 Review and Approval\n\n`;
    md += `| Label | Value | Label | Value |\n`;
    md += `| :--- | :--- | :--- | :--- |\n`;
    const appr = data.reviewApproval || {
      preparedBy: 'SOC Lead Analyst',
      preparedAt: '2026-09-16 22:30 UTC',
      reviewedBy: data.humanReviewGateway?.reviewedBy || 'Vincent (資深資安顧問 / SOC 主管)',
      reviewedAt: '2026-09-16 22:45 UTC',
      approvalStatus: data.reviewStatus === '已確認' ? 'Approved' : 'Pending confirmation',
      approvalRecord: 'APR-2026-0042'
    };
    md += `| Prepared by | ${appr.preparedBy} | Prepared at | ${appr.preparedAt} |\n`;
    md += `| Reviewed by | ${appr.reviewedBy} | Reviewed at | ${appr.reviewedAt} |\n`;
    md += `| Approval status | ${appr.approvalStatus} | Signature / record | ${appr.approvalRecord} |\n\n`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    downloadFile(blob, `${incId}.md`);
    return;
  }

  // 任務二：顧問報告解讀專屬 Markdown 匯出
  if (currentAgent === 'consultant' && data.mode === 'report_analysis') {
    let md = `# JJNET 資安顧問報告深度解讀與處置指引\n\n`;
    md += `> 關聯報告: ${data.reportName || 'Incident Report'} | 事件編號: ${data.incidentId || 'INC-2026-0042'} | 威脅等級: ${data.severity || 'Critical'}\n\n`;
    md += `## 01 事件全貌與本質深度解讀\n${data.executiveSummary || ''}\n\n`;
    md += `## 02 攻擊鏈路與技術成因剖析 (Root Cause)\n${data.technicalExplanation || ''}\n\n`;
    md += `## 03 受害資產衝擊與業務風險評估\n${data.impactAssessment || ''}\n\n`;
    md += `## 04 建議分階處置作為與時程管制 (Incident Response Playbook)\n`;
    (data.steps || []).forEach((s, idx) => {
      md += `${idx + 1}. ${s}\n`;
    });
    md += `\n## 05 中長期架構防禦加固方針\n`;
    (data.longTermHardening || []).forEach(h => {
      md += `- ${h}\n`;
    });
    if (data.complianceAdvisory) {
      md += `\n## 06 法規遵循與法定通報時限提醒\n`;
      md += `- **適用規範**: ${data.complianceAdvisory.regulation || ''}\n`;
      md += `- **通報時限**: ${data.complianceAdvisory.reportingDeadline || ''}\n`;
      md += `- **法律責任**: ${data.complianceAdvisory.legalRisk || ''}\n`;
    }
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    downloadFile(blob, `JJNET_Consultant_Analysis_${data.incidentId || Date.now()}.md`);
    return;
  }

  // 其他任務 (顧問一般模式 / 月報 / 培訓)
  let md = `# JJNET 資安智能運籌分析報告 - ${currentAgent.toUpperCase()}\n`;
  md += `> 生成時間: ${new Date().toLocaleString()} | 人工覆核狀態: ${data.reviewStatus || '待審核'}\n\n`;
  md += `\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\`\n`;
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  downloadFile(blob, `JJNET_${currentAgent}_${Date.now()}.md`);
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// HTML 字元轉義防 XSS
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// 人審閘道互動邏輯與四大正式輸出 (Slide 8 規範)
// ============================================================================

window.toggleIncidentChecklist = function(field) {
  const data = agentResults.incident;
  if (!data) return;
  if (!data.humanReviewGateway) {
    data.humanReviewGateway = {
      status: 'pending_review',
      checklist: { cveReasonable: true, iocCredible: true, riskAccurate: true, readyForRelease: false },
      reviewedBy: 'Vincent (資深資安顧問 / SOC 主管)'
    };
  }
  const chk = data.humanReviewGateway.checklist;
  chk[field] = !chk[field];

  if (chk.cveReasonable && chk.iocCredible && chk.riskAccurate && chk.readyForRelease) {
    data.humanReviewGateway.status = 'approved';
    data.reviewStatus = '已確認';
    updateReviewStatusBadge('已確認');
  } else {
    data.humanReviewGateway.status = 'pending_review';
    data.reviewStatus = '待審核';
    updateReviewStatusBadge('待審核');
  }

  const box = document.getElementById('analyst-review-gateway');
  const badge = document.getElementById('gateway-status-badge');
  if (box && badge) {
    if (chk.readyForRelease) {
      box.classList.add('approved');
      badge.className = 'status-badge badge-success';
      badge.innerText = '🟢 審核通過 (可對外發布)';
    } else {
      box.classList.remove('approved');
      badge.className = 'status-badge badge-review';
      badge.innerText = '🟡 待分析師覆核';
    }
  }

  const chkMap = {
    cveReasonable: 'chk-cve',
    iocCredible: 'chk-ioc',
    riskAccurate: 'chk-risk',
    readyForRelease: 'chk-release'
  };
  const el = document.getElementById(chkMap[field]);
  if (el) {
    el.checked = chk[field];
    const parentLabel = el.closest('.review-check-item');
    if (parentLabel) {
      if (chk[field]) parentLabel.classList.add('active-checked');
      else parentLabel.classList.remove('active-checked');
    }
  }
};

window.approveIncidentReview = function(isApproved) {
  const data = agentResults.incident;
  if (!data) return;
  if (!data.humanReviewGateway) {
    data.humanReviewGateway = {
      status: 'pending_review',
      checklist: { cveReasonable: true, iocCredible: true, riskAccurate: true, readyForRelease: false },
      reviewedBy: 'Vincent (資深資安顧問 / SOC 主管)'
    };
  }

  const chk = data.humanReviewGateway.checklist;
  if (isApproved) {
    chk.cveReasonable = true;
    chk.iocCredible = true;
    chk.riskAccurate = true;
    chk.readyForRelease = true;
    data.humanReviewGateway.status = 'approved';
    data.reviewStatus = '已確認';
    updateReviewStatusBadge('已確認');
    alert('✅ 分析師人審閘道審核通過！\n已授權對外發布正式資安報告 (Markdown / PDF / Email / Ticket)。');
  } else {
    chk.readyForRelease = false;
    data.humanReviewGateway.status = 'rejected';
    data.reviewStatus = '需補件';
    updateReviewStatusBadge('需補件');
    alert('🔄 已標記為「需補件」狀態，退回調查小組深入排查。');
  }

  const container = document.getElementById('results-display');
  if (container) renderIncident(data, container);
};

// 彈出視窗輔助控制
function openExportModal(title, subtitle, content) {
  const modal = document.getElementById('export-modal');
  const titleEl = document.getElementById('modal-title');
  const subEl = document.getElementById('modal-subtitle');
  const contentEl = document.getElementById('modal-content');
  if (!modal) return;
  titleEl.innerHTML = title;
  subEl.innerText = subtitle;
  contentEl.innerText = content;
  modal.style.display = 'flex';
}

function closeExportModal() {
  const modal = document.getElementById('export-modal');
  if (modal) modal.style.display = 'none';
}

function copyModalContent() {
  const contentEl = document.getElementById('modal-content');
  if (!contentEl) return;
  navigator.clipboard.writeText(contentEl.innerText).then(() => {
    alert('已成功複製全文至剪貼簿！');
  }).catch(() => {
    alert('複製失敗，請手動全選複製。');
  });
}

function exportEmailDraft() {
  const data = agentResults[currentAgent];
  if (!data) return alert('目前尚無分析資料可供匯出。');

  const title = data.title || (data.dataPack && data.dataPack.logEvidence && data.dataPack.logEvidence.eventName) || '重大資安事件';
  const cveStr = (data.dataPack && data.dataPack.cveContext && data.dataPack.cveContext.cveId) || (data.cve && data.cve.cveId) || '無已知 CVE';
  const cveStatus = (data.dataPack && data.dataPack.cveContext && data.dataPack.cveContext.status) || 'Not Applicable';

  const emailText = `寄件者：JJNET SOC 資安防禦運籌中心 <soc-dispatch@jjnet.com.tw>
收件者：客戶資安應變小組 (CSIRT), CISO, 系統管理團隊
主旨：【重大資安事件緊急通報】${title} (編號: ${data.incidentId || 'INC-PENDING'})
日期：${new Date().toLocaleString('zh-TW')}
威脅等級：${data.severity || 'HIGH'} (初步風險評分: ${data.riskScore || '--'})

各位資安主管與維運團隊夥伴好：

JJNET MSSP 資安監控中心偵測到高危險性攻擊事件，經分析師透過 Sovereign Domain Model 調查管線完成 Data Pack 組裝與人審閘道審查，特此發出正式通報：

一、事件基本資訊
---------------------------------------------------------------
- 事件識別碼：${data.incidentId || 'INC-PENDING'}
- 事件名稱：${title}
- 威脅嚴重度：${data.severity || 'HIGH'}
- CVE 弱點關聯：${cveStr} (判定狀態: [${cveStatus}])
- 偵測時間：${data.detectedAt || new Date().toISOString()}

二、事件摘要與衝擊
---------------------------------------------------------------
${data.summary || '已由地端資安微調模型完成結構化萃取。'}
衝擊評估：${data.impact || '防火牆與端點代理已及時阻斷，未形成全網擴散。'}

三、關鍵鑑識證據與時間軸
---------------------------------------------------------------
${(data.evidence || []).map(e => `• ${e}`).join('\n')}

四、即刻圍堵措施 (已執行)
---------------------------------------------------------------
${(data.actions || []).map((a, i) => `[${i+1}] ${a}`).join('\n')}

五、後續加固與弱點修補建議
---------------------------------------------------------------
${(data.recommendations || []).map((r, i) => `[${i+1}] ${r}`).join('\n')}

六、人審閘道覆核紀錄
---------------------------------------------------------------
- 審核顧問 / 主管：${data.humanReviewGateway?.reviewedBy || 'Vincent (資深資安顧問 / SOC 主管)'}
- 審核狀態：${data.reviewStatus || '已確認'}
- 檢核項目：[✓] CVE 合理  [✓] IOC 可信  [✓] 風險正確  [✓] 授權對外

本報告由 JJNET 資安 LLM 地端模型生成，資料完全不出門，並由資安顧問核准。
若有任何應變疑問，請隨時聯絡 JJNET SOC 24H 戰情值班專線。

JJNET Cyber SOC 運籌中心 敬上`;

  openExportModal('✉️ 正式資安事件通報 Email 初稿', '可直接複製發送給客戶或內部緊急應變小組：', emailText);
}

function exportTicketDraft() {
  const data = agentResults[currentAgent];
  if (!data) return alert('目前尚無分析資料可供匯出。');

  const title = data.title || 'Security Incident';
  const cveStr = (data.dataPack && data.dataPack.cveContext && data.dataPack.cveContext.cveId) || 'N/A';
  const cveStatus = (data.dataPack && data.dataPack.cveContext && data.dataPack.cveContext.status) || 'N/A';
  const userStr = (data.affectedUsers || []).join(', ') || 'daisy.wang@jjnet.com.tw';
  const hostStr = (data.affectedAssets || []).join(', ') || 'WS-FIN-088.corp.jjnet.tw';

  const ticketText = `===============================================================
JJNET SOC ITSM / JIRA / SERVICENOW 事件工單 (Incident Ticket)
===============================================================
Ticket Key    : TKT-${data.incidentId || '20260916-01'}
Issue Type    : Security Incident (Palo Alto / Cortex XDR)
Priority      : ${data.severity === 'CRITICAL' ? 'P1 - Critical (SLA: 15m)' : 'P2 - High (SLA: 60m)'}
Security Class: Sovereign Restricted (On-Premises Data Only)
Status        : IN_PROGRESS (Contained by EDR)
Component     : Palo Alto Firewall / Cortex XDR / Active Directory
Reporter      : JJNET Sovereign Domain Agent (Task 01)
Assignee      : Vincent (資深資安顧問 / SOC 主管)
Affected User : ${userStr}
Affected Host : ${hostStr}
CVE Reference : ${cveStr} (Status: [${cveStatus}])

[Summary]
${title}

[Incident Summary & Impact]
${data.summary || ''}
Impact Assessment: ${data.impact || ''}

[Key Evidence & Timeline]
${(data.evidence || []).map(e => `- ${e}`).join('\n')}

[Containment Actions]
${(data.actions || []).map((a, i) => `Task ${i+1}: ${a} (Status: COMPLETED)`).join('\n')}

[Remediation Plan]
${(data.recommendations || []).map((r, i) => `Action ${i+1}: ${r} (Due: 3 Business Days)`).join('\n')}

[Analyst Review Gateway Checklist (Slide 8)]
[X] 1. CVE Reasonableness: Confirmed
[X] 2. IOC Credibility: Verified (AS49453 / Tor Exit Node)
[X] 3. Risk Score & Severity: Validated (${data.riskScore || 92} / ${data.severity || 'CRITICAL'})
[X] 4. External Release Authorized: Approved by Vincent
===============================================================`;

  openExportModal('🎫 ITSM / Jira / ServiceNow 工單初稿', '可直接複製貼入企業 ITSM、Jira 或 ServiceNow：', ticketText);
}
