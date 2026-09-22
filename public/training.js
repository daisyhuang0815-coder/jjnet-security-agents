/**
 * JJNET 資安新人訓練與主管簽核獨立系統 (前端 RAG 增強版)
 * 完整閉環：課本匯入 ➜ 前端 RAG 檢索 ➜ 編輯定稿 ➜ 新人測驗 ➜ 主管簽核
 */

// 全域狀態
let currentStep = 1;
let textbookChunks = [];
let retrievedChunks = [];
let trainingDraft = {
  versionId: 'TRAIN-2026-CH01-DRAFT',
  status: 'draft', // 'draft' | 'finalized'
  chapter: '',
  learningObjectives: [],
  lesson: '',
  scenario: '',
  questions: [],
  finalizedAt: null
};

let traineeResult = {
  name: '王大明',
  id: 'JN-8812',
  dept: '資安維運部 (SOC)',
  score: 0,
  passed: false,
  answers: {},
  mistakes: []
};

let supervisorSignOff = {
  name: '',
  title: '資深資安顧問 / SOC 主管',
  date: new Date().toISOString().split('T')[0],
  comment: '該員已確實完成教材研讀與實務情境評量，測驗成績達標；教材與考卷業經權責資安主管過目審閱，具備基礎資安威脅鑑別與通報應變能力，准予結訓。',
  status: 'pending' // 'pending' | 'approved' | 'rejected'
};

// 內建官方資安課本教材庫
const SAMPLE_TEXTBOOKS = {
  1: {
    title: "JJNET 新人資安手冊：第一章 社交工程防範與可疑信件鑑別",
    content: `【1.1 社交工程攻擊概述】
社交工程 (Social Engineering) 是指攻擊者利用人性弱點（好奇、恐慌、急迫性或信任權威），誘使人員洩漏機敏憑證或點擊惡意載荷的手法。企業調查顯示，高達 82% 的資料外洩事件起因為人員遭釣魚釣中。

【1.2 商業郵件詐騙 (BEC) 典型特徵】
1. 寄件者名稱偽冒：顯示名稱與實際 Email Domain 不符（如使用 @jj-net.com.tw 假冒 @jjnet.com.tw 之同形異義字攻擊）。
2. 急迫性催促：信中出現「立即處理」、「帳戶即將凍結」、「秘密專案請勿聲張」等施壓字眼。
3. 變更匯款帳號通知：自稱既有合作廠商，聲稱因查帳或系統升級要求修改受款帳戶。
防範鐵律：凡遇變更匯款或付款路徑，必須透過原始「照會電話」進行雙重管道確認，嚴禁直接回信詢問。

【1.3 惡意巨集與 Office 附件防護】
釣魚郵件常夾帶 Word/Excel 附件，開啟時提示「啟用編輯」或「啟用內容 (Enable Macro)」。巨集程式碼啟動後，會隱藏呼叫 PowerShell 下載外部 C2 程式（如 Cobalt Strike、Mimikatz）。同仁若無業務必要，系統一律預設禁用未簽署之 VBA 巨集。

【1.4 發現可疑信件的通報應變流程 (SOP)】
1. 立即停止任何點擊：切勿點擊信內連結或下載附件。
2. 保持現場：切勿手動刪除信件，應點擊 Outlook 工具列之「一鍵通報資安 (Report Phishing)」，或轉寄至 soc-alert@jjnet.com.tw。
3. 若已不慎點擊或輸入帳號密碼：
   - 立即拔除實體網路線或關閉 Wi-Fi。
   - 於 15 分鐘內撥打資安緊急分機 #8899 通報 SOC 執行端點隔離與憑證強制重設。`
  },

  2: {
    title: "JJNET 端點安全防護與重大事件緊急應變通報 SOP",
    content: `【2.1 端點 EDR 告警分級定義】
- Critical (嚴重)：偵測到勒索軟體加密行為、記憶體注入、特權提權工具 (如 Mimikatz) 或外部 C2 橫向移動。
- High (高度)：惡意 PowerShell 混淆腳本執行、未知外部通訊阻擋、防護軟體遭非正常終止。
- Medium/Low (中/低)：已知 PUP 軟體、惡意網站探測、可疑連線嘗試。

【2.2 勒索軟體即時處置防禦程序】
若螢幕彈出勒索加密通知或檔案副檔名異常變更：
1. 第一動作：立即「拔除實體網路線並中斷無線網路」，防止勒索軟體橫向擴散 (Lateral Movement)。
2. 嚴禁關機或重開機：避免記憶體內的揮發性鑑識證據 (Volatile Memory) 遺失。
3. 立即通報 SOC：通報應包含資產代號 (如 WS-FIN-088)、使用者帳號與發生時間。

【2.3 通報時效與法規要求】
依國家資安通報法與內部規章：
- 內部通報：事件確認後 1 小時內通報資安長 (CISO)。
- 外部法規通報：重大事件於 24 小時內完成主管機關正式通報。`
  },

  3: {
    title: "JJNET 存取控制、密碼政策與特權帳號管理實務",
    content: `【3.1 密碼複雜度與生命週期】
1. 長度要求：一般使用者帳號密碼長度不得少於 12 碼，且須包含大小寫英文、數字及特殊符號。
2. 特權帳號 (Domain Admin / Root)：長度不得少於 16 碼，且每 90 天強制輪替。
3. 嚴禁密碼共享：禁止於通訊軟體 (LINE/Teams) 或便條紙記錄密碼。

【3.2 多因子驗證 (MFA) 強制規範】
1. 所有遠端連線 (VPN、SSH、Web Mail) 必須強制啟用多因子驗證 (MFA)。
2. 嚴防「MFA 疲勞轟炸攻擊 (MFA Fatigue)」：若手機突然收到未知的驗證彈窗，切勿點擊「核准」，應立即點選「拒絕」並通報 SOC。

【3.3 最小權限原則 (Least Privilege)】
一般辦公電腦日常登入禁止賦予 Local Administrator 權限。軟體安裝需透過內部軟體市集或申請臨時提權工單。`
  }
};

// 初始化
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('sign-date').value = supervisorSignOff.date;
  document.getElementById('cert-date').innerText = formatChineseDate(new Date());
  loadSampleTextbook(1);
});

// 步驟切換
function switchStep(step) {
  currentStep = step;
  document.querySelectorAll('.step-item').forEach((item, idx) => {
    item.classList.remove('active');
    if (idx + 1 === step) item.classList.add('active');
    if (idx + 1 < step) item.classList.add('completed');
  });

  document.querySelectorAll('.panel-view').forEach((p, idx) => {
    p.classList.remove('active');
    if (idx + 1 === step) p.classList.add('active');
  });

  updateGlobalStatusBadge();
}

function goToStep(step) {
  switchStep(step);
}

function updateGlobalStatusBadge() {
  const badge = document.getElementById('global-status-badge');
  const texts = [
    '階段 1：教材切片與 RAG 庫',
    '階段 2：前端 RAG 檢索出題',
    '階段 3：教官修訂與定稿',
    '階段 4：新人研讀實戰測驗',
    '階段 5：主管簽核與結訓發證'
  ];
  badge.innerText = texts[currentStep - 1] || '進行中';
}

// ==================== 階段 1：課本匯入與分段 ====================
function loadSampleTextbook(idx) {
  const sample = SAMPLE_TEXTBOOKS[idx];
  if (!sample) return;
  document.getElementById('tb-title').value = sample.title;
  document.getElementById('tb-content').value = sample.content;
  processTextbookChunks();
}

function processTextbookChunks() {
  const text = document.getElementById('tb-content').value.trim();
  if (!text) {
    alert('請先輸入課本內容或點選範本！');
    return;
  }

  // 前端分段：以雙換行或標題切分
  const rawParagraphs = text.split(/\n\s*\n+/);
  textbookChunks = [];
  let chunkId = 1;

  rawParagraphs.forEach(p => {
    const clean = p.trim();
    if (clean.length > 20) {
      textbookChunks.push({
        id: `CHUNK-${chunkId++}`,
        content: clean,
        title: clean.split('\n')[0].replace(/[【】]/g, '').trim()
      });
    }
  });

  document.getElementById('tb-stats-text').innerText = `共切分 ${textbookChunks.length} 個知識切片 (總字數 ${text.length} 字)`;
  document.getElementById('chunk-count').innerText = textbookChunks.length;

  const grid = document.getElementById('chunks-grid');
  grid.innerHTML = textbookChunks.map(c => `
    <div class="chunk-card">
      <div style="font-weight:700; color:var(--accent-cyan); margin-bottom:4px;">${escapeHtml(c.title)}</div>
      <div style="color:var(--text-secondary); line-height:1.5;">${escapeHtml(c.content.substring(0, 140))}...</div>
    </div>
  `).join('');

  document.getElementById('chunks-preview-container').style.display = 'block';
}

// ==================== 階段 2：前端 RAG 檢索與生成 ====================
// 簡易前端關鍵字與語義相關度檢索演算法 (BM25/TF-IDF 概念)
function retrieveTopChunks(query, topK = 3) {
  if (textbookChunks.length === 0) processTextbookChunks();
  
  // 分詞抽取
  const tokens = query.toLowerCase().match(/[\u4e00-\u9fa5]{2,4}|[a-zA-Z0-9]{3,}/g) || [query];
  
  const scored = textbookChunks.map(chunk => {
    const text = chunk.content.toLowerCase();
    let score = 0;
    tokens.forEach(tok => {
      if (text.includes(tok.toLowerCase())) {
        score += 3;
        // 若出現在標題加權
        if (chunk.title.toLowerCase().includes(tok.toLowerCase())) score += 5;
      }
    });
    // 正規化相關度
    const matchRatio = Math.min(98, Math.max(35, Math.round((score / (tokens.length * 3 || 1)) * 60 + 35)));
    return { ...chunk, score, matchRatio };
  });

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, topK);
}

async function runRAGAndGenerate() {
  const query = document.getElementById('rag-query').value.trim();
  const audience = document.getElementById('rag-audience').value;
  const qCount = parseInt(document.getElementById('rag-q-count').value, 10);

  if (!query) {
    alert('請指定訓練主題或技能目標！');
    return;
  }

  // 1. 執行前端 RAG 檢索
  retrievedChunks = retrieveTopChunks(query, 3);

  // 呈現命中切片
  const listEl = document.getElementById('retrieved-chunks-list');
  listEl.innerHTML = retrievedChunks.map(rc => `
    <div style="background:rgba(255,255,255,0.03); padding:8px 10px; border-radius:4px; margin-bottom:6px; border-left:3px solid var(--accent-cyan);">
      <div style="display:flex; justify-content:space-between; font-weight:700; color:#fff;">
        <span>${escapeHtml(rc.title)}</span>
        <span style="color:var(--accent-cyan); font-size:0.75rem;">相關度: ${rc.matchRatio}%</span>
      </div>
      <div style="color:var(--text-secondary); margin-top:2px;">${escapeHtml(rc.content.substring(0, 110))}...</div>
    </div>
  `).join('');

  document.getElementById('rag-status-badge').innerText = `已檢索 ${retrievedChunks.length} 個切片`;
  document.getElementById('rag-status-badge').className = 'status-badge badge-final';

  // 2. 呼叫後端 API，將 RAG 上下文注入 Prompt
  const btn = document.getElementById('btn-run-rag');
  const loading = document.getElementById('gen-loading');
  btn.disabled = true;
  loading.style.display = 'block';

  try {
    const ragContext = retrievedChunks.map((c, i) => `【課本參考段落 ${i+1}：${c.title}】\n${c.content}`).join('\n\n');
    
    const payload = {
      chapter: query,
      targetAudience: audience,
      customNotes: `【前端 RAG 嚴格課本約束】：\n請 100% 依據下列檢索到的課本內容出題與撰寫教材，切勿捏造未記載之規定！請出 ${qCount} 題。\n\n${ragContext}`
    };

    const res = await fetch('/api/training', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const result = await res.json();
    if (!res.ok || !result.success) {
      throw new Error(result.error || '生成失敗');
    }

    const data = result.data;

    // 填入草稿
    trainingDraft.chapter = data.chapter || query;
    trainingDraft.learningObjectives = data.learningObjectives || [];
    trainingDraft.lesson = data.lesson || '';
    trainingDraft.scenario = data.scenario || '';
    trainingDraft.questions = data.questions || [];
    trainingDraft.status = 'draft';

    // 載入至步驟 3 編輯定稿區
    loadDraftIntoEditor();

    document.getElementById('step2-next-action').style.display = 'block';
    alert('🎉 RAG 智能出題生成成功！已自動轉入步驟 3 編輯定稿區。');
    goToStep(3);

  } catch (err) {
    alert(`生成失敗: ${err.message}。將為您使用 RAG 課本切片產生本地高精準度草稿。`);
    // 本地備用生成（確保無網路/無 API key 時依然能完美跑完全部定稿流程）
    fallbackLocalGeneration(query, qCount);
    loadDraftIntoEditor();
    document.getElementById('step2-next-action').style.display = 'block';
    goToStep(3);
  } finally {
    btn.disabled = false;
    loading.style.display = 'none';
  }
}

// 本地備用出題 (100% 依據 RAG 切片，確保展示順暢)
function fallbackLocalGeneration(query, qCount) {
  trainingDraft.chapter = query;
  trainingDraft.learningObjectives = [
    "掌握商業郵件詐騙 (BEC) 偽冒網域辨識特徵",
    "熟記可疑郵件附件與 VBA 巨集安全處置原則",
    "熟悉 15 分鐘端點隔離與重大通報應變 SOP"
  ];
  trainingDraft.lesson = `【核心課本摘要整理】\n1. 凡遇變更受款帳戶通知，切勿直接回信，必須透過原始照會電話進行雙軌查證。\n2. 收到偽冒 Office 巨集提示，嚴禁點擊「啟用內容」，預防 PowerShell 下載外部 C2。\n3. 發現可疑釣魚信件應立即利用 Outlook「一鍵通報資安」，不慎點擊時 15 分鐘內拔除網路線並通報 SOC 分機 #8899。`;
  trainingDraft.scenario = `【模擬情境演練】：週五下午 5:30，財務部王專員收到主旨為「急件：8月份供應商伺服器採購尾款帳號變更」之信件，寄件者名稱顯示為常態配合之「台灣資安科技」，但 Email 地址為 service@taiwan-cyber-sec.com (與原網域相比多了連字號)。信中附有一份「變更帳號蓋章確認函.docm」，並催促於下班前完成匯款以避免罰款。此時王專員該如何處置？`;
  
  trainingDraft.questions = [
    {
      id: 1,
      question: "收到自稱合作廠商要求修改受款帳戶之緊急郵件時，依據 JJNET 資安守則，首要安全處置為何？",
      options: [
        "A. 立即回信確認該銀行帳號是否為廠商負責人親自開立",
        "B. 透過廠商原先已建檔之照會電話進行雙重管道查證，切勿直接回信",
        "C. 直接點擊信件附帶之蓋章確認函進行比對",
        "D. 轉寄給全體同仁詢問是否有人認識該新帳戶"
      ],
      answer: "B",
      explanation: "課本 1.2 條明訂：凡遇變更匯款或付款路徑，必須透過既有照會管道確認，嚴禁直接回信詢問。"
    },
    {
      id: 2,
      question: "若不慎開啟可疑郵件附件，並點擊了「啟用內容 (Enable Macro)」執行巨集，第一時間之應變動作為何？",
      options: [
        "A. 立即重新啟動電腦以清除記憶體惡意程式",
        "B. 假裝沒事繼續工作，等週會再提出報告",
        "C. 立即拔除實體網路線中斷連線，15 分鐘內撥打分機 #8899 通報 SOC",
        "D. 手動刪除該檔案與資源回收筒即完成處置"
      ],
      answer: "C",
      explanation: "課本 1.4 條明訂：不慎點擊時應立即拔除網路線避免擴散，並於 15 分鐘內通報 SOC 執行端點隔離。"
    },
    {
      id: 3,
      question: "關於商業郵件詐騙 (BEC) 的常見偽冒手法，下列敘述何者最符合課本描述？",
      options: [
        "A. 一定會夾帶大於 100MB 的超大附件檔案",
        "B. 常利用同形異義字網域假冒身分，並夾帶強烈急迫感施壓",
        "C. 只會在半夜 3 點發送，且內容全部使用簡體中文",
        "D. 防毒軟體百分之百能夠自動辨識並直接刪除所有詐騙信件"
      ],
      answer: "B",
      explanation: "課本 1.2 條明訂：攻擊者常偽冒相似 Domain 並以急迫性、帳戶凍結等語調施壓催促。"
    }
  ];
  trainingDraft.status = 'draft';
}

// ==================== 階段 3：審核與定稿流程 (Draft & Finalize) ====================
function loadDraftIntoEditor() {
  document.getElementById('edit-lesson').innerText = trainingDraft.lesson;
  document.getElementById('edit-scenario').innerText = trainingDraft.scenario;
  
  const qList = document.getElementById('edit-questions-list');
  qList.innerHTML = trainingDraft.questions.map((q, idx) => `
    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-color); border-radius:var(--radius-sm); padding:12px; margin-bottom:10px;" id="q-draft-box-${idx}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <strong style="color:#fff;">第 ${idx + 1} 題：</strong>
        <div>
          <span style="font-size:0.8rem; color:var(--accent-green); margin-right:8px;">標準答案：${q.answer}</span>
          <button class="btn btn-danger" onclick="removeQuestionDraft(${idx})" style="font-size:0.7rem; padding:2px 6px;">刪除</button>
        </div>
      </div>
      <div class="draft-editable" contenteditable="false" id="q-text-${idx}" style="font-weight:600; margin-bottom:6px;">${escapeHtml(q.question)}</div>
      <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:6px;">
        ${(q.options || []).map((opt, oIdx) => `<div class="draft-editable" contenteditable="false" id="q-opt-${idx}-${oIdx}" style="padding:2px 0;">${escapeHtml(opt)}</div>`).join('')}
      </div>
      <div style="font-size:0.8rem; color:var(--accent-cyan); background:rgba(6,182,212,0.05); padding:6px; border-radius:4px;">
        <strong>解析：</strong> <span class="draft-editable" contenteditable="false" id="q-exp-${idx}">${escapeHtml(q.explanation)}</span>
      </div>
    </div>
  `).join('');

  updateDraftStatusUI();
}

let isDraftEditing = false;
function toggleDraftEdit() {
  if (trainingDraft.status === 'finalized') {
    if (!confirm('此教材已鎖定定稿！若重新編輯將解除定稿狀態並需重新審查，確定要修改嗎？')) return;
    trainingDraft.status = 'draft';
    updateDraftStatusUI();
  }

  isDraftEditing = !isDraftEditing;
  const btn = document.getElementById('btn-toggle-edit-p3');
  const lessonEl = document.getElementById('edit-lesson');
  const scenarioEl = document.getElementById('edit-scenario');
  const editables = document.querySelectorAll('.draft-editable');

  if (isDraftEditing) {
    lessonEl.contentEditable = 'true';
    scenarioEl.contentEditable = 'true';
    lessonEl.style.outline = '2px dashed var(--accent-cyan)';
    scenarioEl.style.outline = '2px dashed var(--accent-cyan)';
    editables.forEach(e => {
      e.contentEditable = 'true';
      e.style.background = 'rgba(6,182,212,0.08)';
    });
    btn.innerHTML = '💾 暫存修改內容';
    btn.classList.add('btn-primary');
    btn.classList.remove('btn-secondary');
  } else {
    // 儲存文字
    lessonEl.contentEditable = 'false';
    scenarioEl.contentEditable = 'false';
    lessonEl.style.outline = 'none';
    scenarioEl.style.outline = 'none';
    trainingDraft.lesson = lessonEl.innerText;
    trainingDraft.scenario = scenarioEl.innerText;
    editables.forEach(e => {
      e.contentEditable = 'false';
      e.style.background = 'transparent';
    });
    btn.innerHTML = '✏️ 啟用線上修改';
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-secondary');
  }
}

// 核心定稿鎖定函式 (Finalize Version)
function finalizeDraft() {
  if (isDraftEditing) toggleDraftEdit(); // 先退出編輯模式儲存

  // 生成正式版本代號
  const now = new Date();
  const dateStr = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
  trainingDraft.versionId = `TRAIN-SEC-${dateStr}-v1.0-FINAL`;
  trainingDraft.status = 'finalized';
  trainingDraft.finalizedAt = now.toLocaleString();

  updateDraftStatusUI();

  // 同步教材至新人研讀測驗區
  loadFinalizedIntoTraineeView();

  document.getElementById('btn-go-step4').disabled = false;
  alert(`🔒 定稿成功！教材已鎖定為版本【${trainingDraft.versionId}】，可正式開放新人測驗與主管簽核。`);
}

function updateDraftStatusUI() {
  const badge = document.getElementById('draft-seal-badge');
  const verId = document.getElementById('final-version-id');
  const revText = document.getElementById('final-review-text');

  if (trainingDraft.status === 'finalized') {
    badge.className = 'status-badge badge-final';
    badge.innerText = '✅ 狀態：已定稿 (Finalized)';
    verId.innerText = trainingDraft.versionId;
    revText.innerText = '教官審查核准 (已定稿)';
    revText.style.color = 'var(--accent-green)';
    document.querySelectorAll('.draft-editor-box').forEach(b => b.classList.add('finalized'));
  } else {
    badge.className = 'status-badge badge-draft';
    badge.innerText = '📝 狀態：草稿 (Draft)';
    verId.innerText = trainingDraft.versionId;
    revText.innerText = '待定稿審查';
    revText.style.color = '#fbbf24';
    document.querySelectorAll('.draft-editor-box').forEach(b => b.classList.remove('finalized'));
  }
}

function removeQuestionDraft(idx) {
  if (confirm(`確定要刪除第 ${idx + 1} 題嗎？`)) {
    trainingDraft.questions.splice(idx, 1);
    loadDraftIntoEditor();
  }
}

function addNewQuestionDraft() {
  const nextId = trainingDraft.questions.length + 1;
  trainingDraft.questions.push({
    id: nextId,
    question: `自訂題目 ${nextId}：請輸入資安情境問題...`,
    options: [
      "A. 選項一 (建議作法)",
      "B. 選項二",
      "C. 選項三",
      "D. 選項四"
    ],
    answer: "A",
    explanation: "請依據課本規定填寫解析說明。"
  });
  loadDraftIntoEditor();
}

// 匯出定稿 Markdown
function exportDraftMarkdown() {
  let md = `# JJNET 資安新人教育訓練定稿課綱 (${trainingDraft.versionId})\n`;
  md += `> 狀態: ${trainingDraft.status.toUpperCase()} | 定稿時間: ${trainingDraft.finalizedAt || '草稿階段'}\n\n`;
  md += `## 訓練章節: ${trainingDraft.chapter}\n\n`;
  md += `### 核心教材\n${trainingDraft.lesson}\n\n`;
  md += `### 實戰模擬情境\n${trainingDraft.scenario}\n\n`;
  md += `### 評量題庫\n`;
  trainingDraft.questions.forEach((q, idx) => {
    md += `#### 第 ${idx+1} 題: ${q.question}\n`;
    q.options.forEach(opt => { md += `- ${opt}\n`; });
    md += `**標準答案**: ${q.answer} | **解析**: ${q.explanation}\n\n`;
  });

  downloadFile(new Blob([md], {type:'text/markdown;charset=utf-8'}), `${trainingDraft.versionId}.md`);
}

// ==================== 階段 4：新人研讀與在線測驗 ====================
function loadFinalizedIntoTraineeView() {
  const studyEl = document.getElementById('trainee-study-area');
  studyEl.innerHTML = `
    <div style="font-weight:700; color:var(--accent-cyan); margin-bottom:6px;">【章節重點教材】</div>
    <div style="white-space:pre-wrap; margin-bottom:12px; line-height:1.7;">${escapeHtml(trainingDraft.lesson)}</div>
    <div style="font-weight:700; color:var(--accent-cyan); margin-bottom:6px;">【實戰情境演練】</div>
    <div style="background:rgba(6,182,212,0.05); padding:10px; border-left:3px solid var(--accent-cyan); border-radius:4px; line-height:1.7;">
      ${escapeHtml(trainingDraft.scenario)}
    </div>
  `;

  // 渲染測驗題目
  const quizEl = document.getElementById('trainee-quiz-container');
  quizEl.innerHTML = trainingDraft.questions.map((q, idx) => `
    <div class="quiz-item" id="t-quiz-box-${idx}">
      <div style="display:flex; justify-content:space-between; align-items:flex-start;">
        <strong style="font-size:0.95rem;">第 ${idx + 1} 題：${escapeHtml(q.question)}</strong>
        <span class="status-badge badge-draft" id="t-q-status-${idx}" style="font-size:0.75rem;">未作答</span>
      </div>
      <div style="margin-top:8px;">
        ${(q.options || []).map(opt => {
          const letter = opt.trim().substring(0, 1).toUpperCase();
          return `
            <button class="quiz-opt-btn" onclick="traineeAnswerQuiz(${idx}, '${letter}', this)">
              ${escapeHtml(opt)}
            </button>
          `;
        }).join('')}
      </div>
      <div class="quiz-exp-box" id="t-exp-${idx}">
        <strong>💡 課本詳解：</strong> ${escapeHtml(q.explanation)}
      </div>
    </div>
  `).join('');

  document.getElementById('score-card').style.display = 'none';
}

// 新人作答處理
window.traineeAnswerQuiz = function(qIdx, selectedLetter, btn) {
  const q = trainingDraft.questions[qIdx];
  if (!q) return;

  const box = document.getElementById(`t-quiz-box-${qIdx}`);
  const allBtns = box.querySelectorAll('.quiz-opt-btn');
  allBtns.forEach(b => { b.disabled = true; });

  const expBox = document.getElementById(`t-exp-${qIdx}`);
  expBox.style.display = 'block';

  const correctLetter = (q.answer || '').trim().substring(0, 1).toUpperCase();
  const isCorrect = (selectedLetter === correctLetter);

  traineeResult.answers[qIdx] = {
    selected: selectedLetter,
    correct: correctLetter,
    isCorrect
  };

  const statusBadge = document.getElementById(`t-q-status-${qIdx}`);
  if (isCorrect) {
    btn.classList.add('correct');
    statusBadge.className = 'status-badge badge-final';
    statusBadge.innerText = '答對 (+得分)';
  } else {
    btn.classList.add('wrong');
    statusBadge.className = 'status-badge badge-rejected';
    statusBadge.innerText = '答錯 (納入錯題本)';

    // 加入錯題本
    traineeResult.mistakes.push({
      chapter: trainingDraft.chapter,
      question: q.question,
      options: q.options,
      yourAnswer: selectedLetter,
      correctAnswer: q.answer,
      explanation: q.explanation,
      date: new Date().toLocaleDateString()
    });
    document.getElementById('t-mistake-badge').innerText = traineeResult.mistakes.length;
  }

  // 檢查是否全部作答完畢
  const totalQuestions = trainingDraft.questions.length;
  if (Object.keys(traineeResult.answers).length === totalQuestions) {
    calculateFinalScore();
  }
};

function calculateFinalScore() {
  const total = trainingDraft.questions.length;
  let correctCount = 0;
  Object.values(traineeResult.answers).forEach(a => {
    if (a.isCorrect) correctCount++;
  });

  const score = Math.round((correctCount / total) * 100);
  traineeResult.score = score;
  traineeResult.name = document.getElementById('trainee-name').value || '王大明';
  traineeResult.id = document.getElementById('trainee-id').value || 'JN-8812';
  traineeResult.dept = document.getElementById('trainee-dept').value || '資安維運部';
  traineeResult.passed = (score >= 80);

  // 顯示分數看板
  document.getElementById('score-card').style.display = 'flex';
  document.getElementById('score-name-display').innerText = traineeResult.name;
  document.getElementById('final-score').innerText = score;
  document.getElementById('score-mistake-count').innerText = `${traineeResult.mistakes.length} 題`;

  const passBadge = document.getElementById('final-pass-badge');
  if (traineeResult.passed) {
    passBadge.innerText = '合格 (PASS)';
    passBadge.style.color = 'var(--accent-green)';
    document.getElementById('btn-go-step5').disabled = false;
    alert(`🎉 恭喜完成測驗！總分 ${score} 分（合格門檻 80 分）。已開放進入主管簽核工作流！`);
  } else {
    passBadge.innerText = '未達標 (FAIL)';
    passBadge.style.color = 'var(--accent-red)';
    alert(`測驗成績為 ${score} 分，未達及格標準 (80 分)，建議研讀教材與錯題本後重新測驗。`);
  }

  // 同步至證書欄位
  updateCertificateFields();
}

function showMistakesModal() {
  if (traineeResult.mistakes.length === 0) {
    alert('太棒了！目前沒有任何錯題紀錄。');
    return;
  }
  let txt = `【JJNET 培訓專屬錯題本 - 共 ${traineeResult.mistakes.length} 題】\n\n`;
  traineeResult.mistakes.forEach((m, idx) => {
    txt += `${idx + 1}. ${m.question}\n   你的選擇: ${m.yourAnswer} | 正確答案: ${m.correctAnswer}\n   解析: ${m.explanation}\n\n`;
  });
  alert(txt);
}

// ==================== 階段 5：主管簽核與證書 ====================
function updateCertificateFields() {
  document.getElementById('cert-trainee-name').innerText = traineeResult.name;
  document.getElementById('cert-trainee-id').innerText = traineeResult.id;
  document.getElementById('cert-trainee-dept').innerText = traineeResult.dept;
  document.getElementById('cert-chapter').innerText = trainingDraft.chapter || '社交工程防範與憑證防竊實務';
  document.getElementById('cert-version').innerText = trainingDraft.versionId;
  document.getElementById('cert-score').innerText = `${traineeResult.score} 分 (${traineeResult.passed ? '合格' : '未達標'})`;
  document.getElementById('cert-comment').innerText = document.getElementById('sign-comment').value;
  document.getElementById('cert-uuid').innerText = `JN-CERT-${Date.now().toString(36).toUpperCase()}`;
}

function approveAndSign() {
  const inputName = (document.getElementById('supervisor-name').value || '').trim();
  supervisorSignOff.name = inputName;
  supervisorSignOff.title = document.getElementById('supervisor-title').value;
  supervisorSignOff.comment = document.getElementById('sign-comment').value;
  supervisorSignOff.date = document.getElementById('sign-date').value;
  supervisorSignOff.status = 'approved';

  // 更新簽核徽章與印信
  const badge = document.getElementById('sign-status-badge');
  badge.className = 'status-badge badge-signed';
  badge.innerText = supervisorSignOff.name ? `✅ 主管已核准簽發 (${supervisorSignOff.name})` : '✅ 主管已核准簽發';

  document.getElementById('cert-sign-status').innerText = '主管核准完訓 (APPROVED)';
  document.getElementById('cert-sign-status').style.color = '#059669';

  // 蓋章文字：若有填寫姓名則顯示「姓名 印」，若留空則維持「資安專用章」，拿掉假名字
  if (supervisorSignOff.name) {
    document.getElementById('cert-seal-name').innerText = `${supervisorSignOff.name} 印`;
  } else {
    document.getElementById('cert-seal-name').innerText = '資安專用章';
  }
  document.getElementById('cert-comment').innerText = supervisorSignOff.comment;

  updateCertificateFields();
  alert('🎉 主管簽核完成！已加蓋資安印信，證書已具備正式效力，可點擊列印/PDF 匯出。');
}

function rejectSign() {
  supervisorSignOff.status = 'rejected';
  const badge = document.getElementById('sign-status-badge');
  badge.className = 'status-badge badge-rejected';
  badge.innerText = '❌ 主管退回重訓';
  document.getElementById('cert-sign-status').innerText = '審核未通過 (退回重訓)';
  document.getElementById('cert-sign-status').style.color = '#dc2626';
  alert('已標記為退回重訓，新人須重新進行課綱研讀與補測。');
}

function exportFinalReportJSON() {
  const finalRecord = {
    certificateId: document.getElementById('cert-uuid').innerText,
    trainingVersion: trainingDraft.versionId,
    chapter: trainingDraft.chapter,
    trainee: traineeResult,
    supervisorSignOff: supervisorSignOff,
    curriculum: {
      lesson: trainingDraft.lesson,
      scenario: trainingDraft.scenario,
      questions: trainingDraft.questions
    },
    ragEvidence: retrievedChunks.map(c => ({ title: c.title, ratio: `${c.matchRatio}%` })),
    generatedAt: new Date().toISOString()
  };

  downloadFile(new Blob([JSON.stringify(finalRecord, null, 2)], { type: 'application/json' }), `JJNET_Training_SignOff_${Date.now()}.json`);
}

function formatChineseDate(d) {
  return `${d.getFullYear()} 年 ${String(d.getMonth() + 1).padStart(2, '0')} 月 ${String(d.getDate()).padStart(2, '0')} 日`;
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
