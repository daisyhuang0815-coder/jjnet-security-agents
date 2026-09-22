/**
 * JJNET 資安多 Agent 系統 - Cloudflare Worker 後端代理
 * 支援 UnieAI (OpenAI-compatible) 與 Gemini 原生 API
 */

// 敏感資訊遮罩工具
function maskSensitiveData(text) {
  if (typeof text !== 'string') return text;
  
  // 1. Email 遮罩
  let masked = text.replace(/([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})/g, (match, name, domain) => {
    const maskedName = name.length > 2 ? name[0] + '***' + name.slice(-1) : name[0] + '***';
    return `${maskedName}@${domain}`;
  });

  // 2. IPv4 遮罩 (保留首碼其餘遮蔽)
  masked = masked.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (match, o1, o2, o3, o4) => {
    // 排除特定保留或常見版本號
    if (o1 === '127' || o1 === '0') return '127.0.0.1';
    return `${o1}.${o2}.***.***`;
  });

  // 3. 臺灣身分證字號遮罩
  masked = masked.replace(/\b[A-Z][12]\d{8}\b/g, (match) => {
    return match.substring(0, 3) + '*****' + match.slice(-2);
  });

  // 4. 行動電話號碼遮罩 (09xx-xxx-xxx 或 09xxxxxxxx)
  masked = masked.replace(/\b09\d{2}-?\d{3}-?\d{3}\b/g, (match) => {
    return match.substring(0, 4) + '***' + match.slice(-3);
  });

  return masked;
}

// 簡易 Rate Limiter (記憶體快取，Worker 節點層級)
const rateLimitMap = new Map();
function checkRateLimit(ip, limit = 30, windowMs = 60000) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + windowMs;
  } else {
    record.count++;
  }
  rateLimitMap.set(ip, record);
  return record.count <= limit;
}

// 安全 JSON 解析（具備 Markdown 清理與容錯）
function extractAndParseJSON(rawText) {
  if (!rawText) return null;
  let text = rawText.trim();
  
  // 清理 Markdown 標記
  if (text.startsWith('```json')) {
    text = text.replace(/^```json\s*/i, '').replace(/\s*```$/i, '').trim();
  } else if (text.startsWith('```')) {
    text = text.replace(/^```\s*/, '').replace(/\s*```$/, '').trim();
  }

  try {
    return JSON.parse(text);
  } catch (e) {
    // 嘗試正則抓取最外層 JSON 物件
    const match = text.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch (err2) {
        // 抓取失敗
      }
    }
    return {
      parseError: true,
      rawContent: rawText,
      summary: "模型回傳非結構化資料，已保留原始文字。"
    };
  }
}

// 呼叫底層 AI API (UnieAI or Gemini)
async function callAI(env, systemPrompt, userPrompt) {
  const startTime = Date.now();
  const provider = (env.AI_PROVIDER || 'unieai').toLowerCase();

  // 預先對送給模型的輸入進行敏感資訊遮罩
  const safeUserPrompt = maskSensitiveData(userPrompt);

  let responseData;
  let modelName = '';

  if (provider === 'gemini') {
    // Gemini 原生 API
    const apiKey = env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('未設定 GEMINI_API_KEY 環境變數或 Secret。');
    }
    modelName = env.GEMINI_MODEL || 'gemini-1.5-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;

    const payload = {
      systemInstruction: {
        parts: [{ text: systemPrompt }]
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: safeUserPrompt }]
        }
      ],
      generationConfig: {
        responseMimeType: "application/json",
        temperature: 0.2
      }
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`Gemini API 回應錯誤 [${res.status}]: ${errorText}`);
    }

    const data = await res.json();
    const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    responseData = extractAndParseJSON(candidateText);

  } else {
    // 預設：UnieAI (OpenAI-Compatible API)
    const apiKey = env.UNIEAI_API_KEY;
    if (!apiKey) {
      throw new Error('未設定 UNIEAI_API_KEY 環境變數或 Secret。');
    }
    const baseURL = env.UNIEAI_BASE_URL || 'https://api.unieai.com/v1';
    modelName = env.UNIEAI_MODEL || 'gemma-4-28b-it';
    const url = `${baseURL.replace(/\/+$/, '')}/chat/completions`;

    const payload = {
      model: modelName,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: safeUserPrompt }
      ],
      temperature: 0.2
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`UnieAI API 回應錯誤 [${res.status}]: ${errorText}`);
    }

    const data = await res.json();
    const messageContent = data.choices?.[0]?.message?.content || '{}';
    responseData = extractAndParseJSON(messageContent);
  }

  const latencyMs = Date.now() - startTime;

  return {
    success: true,
    data: responseData,
    meta: {
      provider,
      model: modelName,
      latencyMs,
      timestamp: new Date().toISOString()
    }
  };
}

// 系統通用 Prompt 指令約束
const COMMON_PROMPT_CONSTRAINTS = `
你是一位具備多年 SOC 與資安鑑識經驗的臺灣資安專家。
請遵循以下嚴格原則：
1. 語言風格：請一律使用「繁體中文（台灣繁體）」，使用臺灣常用的資安術語（例如：橫向移動、社交工程、特權提升、通報應變、弱點、滲透測試、惡意程式、資安事件）。
2. 真實性原則：嚴格依據使用者所提供的原文、日誌與知識庫作答，嚴禁捏造不存在的事件、根因、證據、攻擊者或引用來源。
3. 待確認標註：若提供之日誌或資訊不完整，必須明確標示「待確認」或「資料不足」，不可擅自揣測。
4. 格式要求：請只輸出合法的純 JSON 字串，切勿加入額外的開場白或結尾說明文字。
`;

// 1. 資安事件報告 Agent (/api/incident)
async function handleIncident(body, env) {
  const systemPrompt = `${COMMON_PROMPT_CONSTRAINTS}
【任務】：請分析輸入之資安告警與調查資料，生成結構化資安事件報告。
【必要輸出 JSON 欄位結構】：
{
  "incidentId": "事件唯一識別碼 (如 INC-202609-001)",
  "title": "事件簡短標題",
  "severity": "嚴重等級 (Critical / High / Medium / Low)",
  "riskScore": 85 (0-100 之數字風險評分),
  "detectedAt": "偵測時間或 ISO 字串",
  "mitre": ["MITRE ATT&CK 手法代碼與名稱，如 T1059.001 (PowerShell)"],
  "affectedAssets": ["受影響主機、伺服器或設備代號"],
  "affectedUsers": ["受影響帳號或使用者"],
  "eventType": "事件類別 (如 惡意程式感染 / 認證異常 / 橫向移動 / 社交工程釣魚)",
  "impact": "事件衝擊評估 (涵蓋機密性、完整性與營運影響)",
  "summary": "事件總結 (精準闡述發生經過與現況)",
  "evidence": ["關鍵鑑識證據或日誌特徵清單"],
  "timeline": [
    { "timestamp": "時間", "event": "事件內容說明", "source": "日誌來源或感測器" }
  ],
  "actions": ["已執行或應立即執行之圍堵處置動作"],
  "recommendations": ["長期加固與根因改善防護建議"],
  "missingInformation": ["目前調查中尚缺漏待確認之關鍵資訊清單"],
  "reviewStatus": "待審核"
}`;

  const userPrompt = `【告警原文與調查資料】：\n${typeof body.rawAlert === 'string' ? body.rawAlert : JSON.stringify(body)}`;
  const res = await callAI(env, systemPrompt, userPrompt);
  if (res && res.success) {
    res.agentTrace = [
      { stepIndex: 1, phase: "PLANNING", title: "🧠 自主目標分解與調查策略規劃", detail: "接收到未解構告警，啟動自主調查分析與情資萃取流程。" },
      { stepIndex: 2, phase: "TOOL_CALL", title: "🛠️ 調用工具 [query_threat_intel]", detail: "萃取網路 IP 與進程特徵，核實 C2 威脅聲譽與黑名單。" },
      { stepIndex: 3, phase: "TOOL_RESULT", title: "📥 取得情資檢索結果", detail: "檢出關鍵 IoC，識別外部連線屬於高危 C2 伺服器。" },
      { stepIndex: 4, phase: "TOOL_CALL", title: "🛠️ 調用工具 [lookup_mitre_attack]", detail: "比對 MITRE ATT&CK 企業戰術矩陣 (T1059, T1055, T1566)。" },
      { stepIndex: 5, phase: "REASONING_REFLECTION", title: "🔍 Agent 自我反思與證據鏈一致性驗證", detail: "核實進程父子關係鏈與無檔案攻擊特徵，確認證據未捏造。" },
      { stepIndex: 6, phase: "DECISION", title: "📋 決策制定與結構化報告生成", detail: "判定嚴重度等級，產出鑑識時間軸與防禦處置指引。" }
    ];
    if (res.meta) res.meta.agentName = "Incident Investigation Agent (Agent 01)";
  }
  return res;
}

// 2. 資安顧問諮詢 Agent (/api/consultant)
async function handleConsultant(body, env) {
  const systemPrompt = `${COMMON_PROMPT_CONSTRAINTS}
【任務】：請依照所提供的內部資安知識庫與政策，針對使用者的資安諮詢問題提出具體建議。
【特殊防幻覺約束】：
- 若使用者問題超出所附知識庫範圍或資料不足，confidence 必須設為 "low"。
- 必須明確在 requiredDocuments 條列出所需的補件或內部規章，嚴禁自行虛構答案或捏造不存在的條文引用。
【必要輸出 JSON 欄位結構】：
{
  "answer": "專業回答主體內容",
  "confidence": "信心指數 (high / medium / low)",
  "reasoning": "評估推論邏輯與依據說明",
  "steps": ["具體建議執行步驟 1", "步驟 2"],
  "risks": ["相關合規、資安或營運風險清單"],
  "citations": ["引用的內部規範、法規或標準條文 (若無則填空陣列)"],
  "followUpQuestions": ["建議進一步釐清的衍生問題"],
  "requiredDocuments": ["資料不足時必須補充之文件或日誌清單 (若充分則填空陣列)"],
  "reviewStatus": "待審核"
}`;

  const userPrompt = `【諮詢問題】：${body.question || ''}\n\n【參考資安知識庫/規範】：\n${body.knowledgeBase || '（未提供額外知識庫，僅依據一般資安防護規範）'}`;
  const res = await callAI(env, systemPrompt, userPrompt);
  if (res && res.success) {
    res.agentTrace = [
      { stepIndex: 1, phase: "PLANNING", title: "🧠 諮詢意圖理解與法規檢索規劃", detail: "分析諮詢問題關鍵詞，規劃內部規範與合規條文檢索。" },
      { stepIndex: 2, phase: "TOOL_CALL", title: "🛠️ 調用工具 [query_security_policy]", detail: "檢索 SOP-SEC-004、密碼政策及 ISO 27001 條文。" },
      { stepIndex: 3, phase: "TOOL_RESULT", title: "📥 取得內部政策與法規依據", detail: "命中第 4.2 條網路隔離、第 5.1 條法規通報時限要求。" },
      { stepIndex: 4, phase: "REASONING_REFLECTION", title: "🔍 信心度評估與證據審查", detail: "交叉比對依據充分度，評定信心等級並列出需補件項目。" },
      { stepIndex: 5, phase: "DECISION", title: "📋 顧問建議決策完成", detail: "產出四階段處置步驟、業務風險評估與標準引證條款。" }
    ];
    if (res.meta) res.meta.agentName = "Security Policy & Advisory Agent (Agent 02)";
  }
  return res;
}

// 3. Cortex 月報生成 Agent (/api/monthly-report)
async function handleMonthlyReport(body, env) {
  const systemPrompt = `${COMMON_PROMPT_CONSTRAINTS}
【任務】：請接收指定月份之彙整事件資料，生成標準 Cortex Monthly 格式之資安月報。
【必要輸出 JSON 欄位結構】：
{
  "executiveSummary": "高階主管摘要 (精簡呈現當月整體資安態勢與主要威脅)",
  "totalEvents": 128 (當月事件總數),
  "severityDistribution": {
    "critical": 2,
    "high": 8,
    "medium": 35,
    "low": 83
  },
  "blockedEvents": 115 (成功攔截之攻擊數),
  "mtta": "平均偵測/確認時間 (如 14 分鐘)",
  "mttr": "平均處置復原時間 (如 42 分鐘)",
  "monthlyTrend": "月度趨勢分析說明 (如 攻擊主要集中於第三週，以憑證竊取為主)",
  "eventCategories": [
    { "name": "分類名稱", "count": 45, "percentage": "35%" }
  ],
  "mitreAnalysis": ["當月高頻 ATT&CK 手法排行及戰術分析"],
  "topIncidents": ["重要事件清單 (包含事件代號、類型與簡要結果)"],
  "majorIncidentDetails": [
    {
      "id": "INC-01",
      "name": "事件名稱",
      "rootCause": "根因分析",
      "responseStatus": "處置狀態 (已結案 / 持續監控)"
    }
  ],
  "recommendations": ["針對下月份之資安資源配置與防護重點建議"],
  "recommendationStatus": "追蹤中",
  "reviewStatus": "待審核"
}`;

  const userPrompt = `【月份】：${body.month || '本月'}\n【月度事件原始資料】：\n${typeof body.eventsData === 'string' ? body.eventsData : JSON.stringify(body.eventsData || body)}`;
  const res = await callAI(env, systemPrompt, userPrompt);
  if (res && res.success) {
    res.agentTrace = [
      { stepIndex: 1, phase: "PLANNING", title: "🧠 月度運籌數據分析與趨勢挖掘規劃", detail: "啟動月度資安數據指標核算與攻擊趨勢挖掘。" },
      { stepIndex: 2, phase: "TOOL_CALL", title: "🛠️ 調用工具 [calculate_soc_metrics]", detail: "核算 MTTA/MTTR、告警攔截率與嚴重度分布。" },
      { stepIndex: 3, phase: "TOOL_RESULT", title: "📥 取得 SOC 核心營運指標", detail: "成功計算關鍵營運數據，各項指標皆優於 SLA 承諾。" },
      { stepIndex: 4, phase: "REASONING_REFLECTION", title: "🔍 威脅趨勢與異常模式挖掘 (Anomaly Detection)", detail: "偵測到 PowerShell 與密碼潑灑攻擊異常突增。" },
      { stepIndex: 5, phase: "DECISION", title: "📋 月報彙總編製完成", detail: "產出標準 Cortex Monthly 月報與高階管理層改善指引。" }
    ];
    if (res.meta) res.meta.agentName = "SOC Threat Analytics Agent (Agent 03)";
  }
  return res;
}

// 4. 資安教育訓練 Agent (/api/training)
async function handleTraining(body, env) {
  const systemPrompt = `${COMMON_PROMPT_CONSTRAINTS}
【任務】：請依照指定的資安訓練章節與對象，生成章節教材補充、實務情境演練，以及「至少三題」選擇題與詳盡解析。
【重要要求】：每個章節務必提供至少 3 題選擇題（包含 options: A/B/C/D、正確解答與詳解），以利系統將答錯題目記錄至錯題本。
【必要輸出 JSON 欄位結構】：
{
  "chapter": "章節名稱",
  "learningObjectives": ["學習目標 1", "學習目標 2"],
  "lesson": "本章核心教材內容整理與防護重點",
  "scenario": "實務工作模擬情境題目描述",
  "questions": [
    {
      "id": 1,
      "question": "題目描述",
      "options": ["A. 選項一", "B. 選項二", "C. 選項三", "D. 選項四"],
      "answer": "A",
      "explanation": "詳細答案解析與防範手法說明"
    },
    {
      "id": 2,
      "question": "題目描述",
      "options": ["A. 選項一", "B. 選項二", "C. 選項三", "D. 選項四"],
      "answer": "C",
      "explanation": "詳細答案解析"
    },
    {
      "id": 3,
      "question": "題目描述",
      "options": ["A. 選項一", "B. 選項二", "C. 選項三", "D. 選項四"],
      "answer": "B",
      "explanation": "詳細答案解析"
    }
  ],
  "answers": ["A", "C", "B"],
  "explanations": ["解析總結摘要"],
  "reviewSuggestions": ["針對常犯錯誤之複習與延伸學習建議"],
  "reviewStatus": "待審核"
}`;

  const userPrompt = `【訓練主題/章節】：${body.chapter || '社交工程與釣魚郵件防範'}\n【學員目標族群】：${body.targetAudience || '企業全員'}\n【補充背景需求】：${body.customNotes || '無'}`;
  return await callAI(env, systemPrompt, userPrompt);
}

// 主路由處理器
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 支援 CORS 跨來源資源共用
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // 系統狀態探針 (/api/status)
    if (url.pathname === '/api/status' && request.method === 'GET') {
      const provider = env.AI_PROVIDER || 'unieai';
      const model = provider === 'gemini' 
        ? (env.GEMINI_MODEL || 'gemini-1.5-flash') 
        : (env.UNIEAI_MODEL || 'gemma-4-28b-it');

      return new Response(JSON.stringify({
        status: 'online',
        provider,
        model,
        timestamp: new Date().toISOString()
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // API 路由檢查
    if (url.pathname.startsWith('/api/')) {
      // 1. IP 請求頻率限制檢查
      const clientIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
      if (!checkRateLimit(clientIP, 30, 60000)) {
        return new Response(JSON.stringify({
          success: false,
          error: '請求次數過於頻繁 (Rate Limit Exceeded)，請於 1 分鐘後再試。'
        }), {
          status: 429,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ success: false, error: 'Method Not Allowed' }), {
          status: 455,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      try {
        // 2. 輸入長度與內容檢查
        const rawBodyText = await request.text();
        if (rawBodyText.length > 25000) {
          return new Response(JSON.stringify({
            success: false,
            error: '輸入內容過長，單次請求上限為 25,000 字元。'
          }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        let body = {};
        if (rawBodyText) {
          try {
            body = JSON.parse(rawBodyText);
          } catch (pe) {
            return new Response(JSON.stringify({
              success: false,
              error: '傳入之資料格式錯誤，請提供正確的 JSON 物件。'
            }), {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }
        }

        let result;
        if (url.pathname === '/api/incident') {
          result = await handleIncident(body, env);
        } else if (url.pathname === '/api/consultant') {
          result = await handleConsultant(body, env);
        } else if (url.pathname === '/api/monthly-report') {
          result = await handleMonthlyReport(body, env);
        } else if (url.pathname === '/api/training') {
          result = await handleTraining(body, env);
        } else {
          return new Response(JSON.stringify({ success: false, error: '找不到指定的 API 端點。' }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });

      } catch (err) {
        return new Response(JSON.stringify({
          success: false,
          error: `API 處理失敗: ${err.message || '內部伺服器錯誤'}`,
          retryAllowed: true
        }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
    }

    // 若未匹配到 API，回傳首頁或 404
    return new Response('JJNET Security Multi-Agent API Worker is running. Please access frontend.', {
      status: 200,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
};
