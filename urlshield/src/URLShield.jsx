import { useState, useEffect, useRef } from "react";

const API_KEY = "AIzaSyDyy7jT8umqVBEhPi_zRbkBKg4ZTliDSe8";
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${API_KEY}`;

async function callGemini(prompt) {
  const res = await fetch(GEMINI_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "No response";
}

const THREAT_CONFIG = {
  benign:     { color: "#00ffa3", bg: "rgba(0,255,163,0.08)", border: "rgba(0,255,163,0.3)", icon: "✓", label: "SAFE", desc: "No threats detected" },
  phishing:   { color: "#a78bfa", bg: "rgba(167,139,250,0.08)", border: "rgba(167,139,250,0.3)", icon: "⚠", label: "PHISHING", desc: "Identity theft risk" },
  malware:    { color: "#ff4d4d", bg: "rgba(255,77,77,0.08)", border: "rgba(255,77,77,0.3)", icon: "✕", label: "MALWARE", desc: "Malicious software detected" },
  defacement: { color: "#fbbf24", bg: "rgba(251,191,36,0.08)", border: "rgba(251,191,36,0.3)", icon: "!", label: "DEFACEMENT", desc: "Site integrity compromised" },
  scam:       { color: "#f97316", bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.3)", icon: "⚑", label: "SCAM", desc: "Fraudulent content" },
  legitimate: { color: "#00ffa3", bg: "rgba(0,255,163,0.08)", border: "rgba(0,255,163,0.3)", icon: "✓", label: "LEGITIMATE", desc: "Authentic content" },
};

function getThreat(raw = "") {
  const lower = raw.toLowerCase();
  for (const key of Object.keys(THREAT_CONFIG)) {
    if (lower.includes(key)) return key;
  }
  return null;
}

function ScanLine({ active }) {
  const [pos, setPos] = useState(0);
  useEffect(() => {
    if (!active) { setPos(0); return; }
    const id = setInterval(() => setPos(p => (p >= 100 ? 0 : p + 1.2)), 16);
    return () => clearInterval(id);
  }, [active]);
  if (!active) return null;
  return (
    <div style={{ position: "absolute", left: 0, right: 0, top: `${pos}%`, height: 2, background: "linear-gradient(90deg, transparent, #00ffa3, transparent)", boxShadow: "0 0 12px #00ffa3", pointerEvents: "none", zIndex: 10 }} />
  );
}

function GridBg() {
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", overflow: "hidden" }}>
      <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M 48 0 L 0 0 0 48" fill="none" stroke="rgba(0,255,163,0.04)" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>
      <div style={{ position: "absolute", top: "20%", left: "60%", width: 600, height: 600, background: "radial-gradient(circle, rgba(0,255,163,0.04) 0%, transparent 70%)", borderRadius: "50%" }} />
      <div style={{ position: "absolute", bottom: "10%", left: "10%", width: 400, height: 400, background: "radial-gradient(circle, rgba(167,139,250,0.04) 0%, transparent 70%)", borderRadius: "50%" }} />
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: "16px 20px", backdropFilter: "blur(12px)" }}>
      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.12em", fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase", marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "'Syne', sans-serif", letterSpacing: "-0.02em" }}>{value}</div>
    </div>
  );
}

function ThreatBadge({ type }) {
  const cfg = THREAT_CONFIG[type] || { color: "#fff", label: type?.toUpperCase(), icon: "?" };
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 12px", borderRadius: 6, background: cfg.bg, border: `1px solid ${cfg.border}`, color: cfg.color, fontSize: 12, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em", fontWeight: 600 }}>
      <span>{cfg.icon}</span> {cfg.label}
    </span>
  );
}

export default function URLShield() {
  const [url, setUrl] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [urlRaw, setUrlRaw] = useState("");
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState("");

  const [file, setFile] = useState(null);
  const [fileResult, setFileResult] = useState(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [fileError, setFileError] = useState("");

  const [scanCount, setScanCount] = useState(0);
  const [threatCount, setThreatCount] = useState(0);
  const [history, setHistory] = useState([]);

  const fileRef = useRef();

  async function scanUrl() {
    if (!url.trim()) return;
    setUrlLoading(true); setUrlError(""); setUrlResult(null);
    try {
      const prompt = `You are an advanced AI specializing in URL security. Classify this URL into exactly ONE of: benign, phishing, malware, defacement.
Rules:
- benign = safe, trusted sites (google.com, wikipedia.org, etc.)
- phishing = fake login/scam pages designed to steal credentials
- malware = URLs distributing viruses, ransomware, trojans
- defacement = hacked/altered websites

URL: ${url}

Return ONLY the single classification word in lowercase. No explanation, no punctuation.`;
      const raw = await callGemini(prompt);
      const threat = getThreat(raw) || raw.toLowerCase().trim();
      setUrlResult(threat);
      setUrlRaw(raw);
      setScanCount(c => c + 1);
      if (threat !== "benign") setThreatCount(c => c + 1);
      setHistory(h => [{ type: "url", input: url, result: threat, time: new Date().toLocaleTimeString() }, ...h.slice(0, 9)]);
    } catch (e) {
      setUrlError("Scan failed. Check your connection and try again.");
    } finally {
      setUrlLoading(false);
    }
  }

  async function scanFile() {
    if (!file) return;
    setFileLoading(true); setFileError(""); setFileResult(null);
    try {
      let text = "";
      if (file.name.endsWith(".txt")) {
        text = await file.text();
      } else if (file.name.endsWith(".pdf")) {
        setFileResult({ type: "error", message: "PDF text extraction requires a server environment. Please use a .txt file or paste content directly." });
        setFileLoading(false);
        return;
      } else {
        setFileError("Only .txt and .pdf files are supported.");
        setFileLoading(false);
        return;
      }
      const prompt = `You are an expert in detecting scam and phishing messages. Analyze the following text and classify it as SCAM/FAKE or LEGITIMATE.

Text:
"""
${text.slice(0, 3000)}
"""

Respond with:
1. Classification: SCAM or LEGITIMATE
2. Confidence: HIGH / MEDIUM / LOW
3. Reason: One clear sentence explaining why.

Format your response as:
CLASSIFICATION: [SCAM or LEGITIMATE]
CONFIDENCE: [HIGH/MEDIUM/LOW]
REASON: [one sentence]`;
      const raw = await callGemini(prompt);
      setFileResult({ type: "analysis", raw });
      setScanCount(c => c + 1);
      if (raw.toUpperCase().includes("SCAM")) setThreatCount(c => c + 1);
      setHistory(h => [{ type: "file", input: file.name, result: raw.includes("SCAM") ? "scam" : "legitimate", time: new Date().toLocaleTimeString() }, ...h.slice(0, 9)]);
    } catch (e) {
      setFileError("Analysis failed. Please try again.");
    } finally {
      setFileLoading(false);
    }
  }

  const urlCfg = urlResult ? (THREAT_CONFIG[urlResult] || { color: "#fff", label: urlResult?.toUpperCase(), bg: "rgba(255,255,255,0.05)", border: "rgba(255,255,255,0.1)", desc: "" }) : null;

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #070b0f; }
        ::selection { background: rgba(0,255,163,0.2); }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: rgba(0,255,163,0.2); border-radius: 2px; }
        .glass { background: rgba(255,255,255,0.03); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.07); border-radius: 16px; }
        .glass-strong { background: rgba(255,255,255,0.05); backdrop-filter: blur(30px); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; }
        input[type=text], input[type=url] { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; padding: 14px 18px; font-family: 'JetBrains Mono', monospace; font-size: 14px; width: 100%; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        input[type=text]:focus, input[type=url]:focus { border-color: rgba(0,255,163,0.5); box-shadow: 0 0 0 3px rgba(0,255,163,0.08); }
        input[type=text]::placeholder, input[type=url]::placeholder { color: rgba(255,255,255,0.2); }
        .scan-btn { background: rgba(0,255,163,0.1); border: 1px solid rgba(0,255,163,0.3); color: #00ffa3; padding: 14px 28px; border-radius: 10px; font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600; letter-spacing: 0.08em; cursor: pointer; transition: all 0.2s; white-space: nowrap; }
        .scan-btn:hover:not(:disabled) { background: rgba(0,255,163,0.18); box-shadow: 0 0 20px rgba(0,255,163,0.15); transform: translateY(-1px); }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .upload-zone { border: 1.5px dashed rgba(255,255,255,0.12); border-radius: 12px; padding: 32px; text-align: center; cursor: pointer; transition: all 0.2s; background: rgba(255,255,255,0.02); }
        .upload-zone:hover { border-color: rgba(0,255,163,0.3); background: rgba(0,255,163,0.03); }
        @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }
        @keyframes slideIn { from { opacity:0; transform:translateY(8px) } to { opacity:1; transform:translateY(0) } }
        @keyframes rotate { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
        .spinner { width: 20px; height: 20px; border: 2px solid rgba(0,255,163,0.2); border-top-color: #00ffa3; border-radius: 50%; animation: rotate 0.8s linear infinite; display: inline-block; }
        .fade-in { animation: slideIn 0.3s ease forwards; }
        .history-row:hover { background: rgba(255,255,255,0.03); }
      `}</style>

      <GridBg />

      <div style={{ position: "relative", zIndex: 1, minHeight: "100vh", color: "#fff", fontFamily: "'Syne', sans-serif", padding: "0 0 60px" }}>

        {/* Header */}
        <div style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", padding: "0 40px", display: "flex", alignItems: "center", justifyContent: "space-between", height: 64 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(0,255,163,0.12)", border: "1px solid rgba(0,255,163,0.3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⬡</div>
            <span style={{ fontSize: 18, fontWeight: 800, letterSpacing: "-0.02em" }}>URL<span style={{ color: "#00ffa3" }}>Shield</span></span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#00ffa3", boxShadow: "0 0 8px #00ffa3", animation: "pulse 2s infinite" }} />
            <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "rgba(255,255,255,0.4)", letterSpacing: "0.1em" }}>SYSTEM ONLINE</span>
          </div>
        </div>

        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 40px 0" }}>

          {/* Top Stats */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, marginBottom: 40 }}>
            <StatCard label="Total Scans" value={scanCount} color="#fff" />
            <StatCard label="Threats Found" value={threatCount} color="#ff4d4d" />
            <StatCard label="Safe URLs" value={Math.max(0, scanCount - threatCount)} color="#00ffa3" />
            <StatCard label="Threat Rate" value={scanCount ? `${Math.round((threatCount / scanCount) * 100)}%` : "—"} color="#fbbf24" />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>

            {/* URL Scanner */}
            <div className="glass" style={{ padding: 28, position: "relative", overflow: "hidden" }}>
              <ScanLine active={urlLoading} />
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#00ffa3", boxShadow: "0 0 8px #00ffa3" }} />
                <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "rgba(255,255,255,0.7)" }}>URL Threat Scanner</span>
              </div>

              <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "rgba(255,255,255,0.25)", letterSpacing: "0.08em", marginBottom: 8 }}>TARGET URL</div>
              <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
                <input type="url" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} onKeyDown={e => e.key === "Enter" && !urlLoading && scanUrl()} />
                <button className="scan-btn" onClick={scanUrl} disabled={urlLoading || !url.trim()}>
                  {urlLoading ? <span className="spinner" /> : "SCAN →"}
                </button>
              </div>

              {urlError && <div style={{ color: "#ff4d4d", fontSize: 13, fontFamily: "'JetBrains Mono', monospace", padding: "12px 16px", background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.2)", borderRadius: 8 }}>{urlError}</div>}

              {urlResult && urlCfg && (
                <div className="fade-in" style={{ background: urlCfg.bg, border: `1px solid ${urlCfg.border}`, borderRadius: 12, padding: 20 }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <div style={{ width: 36, height: 36, borderRadius: 10, background: `${urlCfg.color}18`, border: `1px solid ${urlCfg.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, color: urlCfg.color, fontWeight: 700 }}>{urlCfg.icon}</div>
                      <div>
                        <div style={{ fontSize: 18, fontWeight: 800, color: urlCfg.color, letterSpacing: "-0.01em" }}>{urlCfg.label}</div>
                        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", fontFamily: "'JetBrains Mono', monospace" }}>{urlCfg.desc}</div>
                      </div>
                    </div>
                    <ThreatBadge type={urlResult} />
                  </div>
                  <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 14 }}>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace", marginBottom: 4, letterSpacing: "0.08em" }}>ANALYZED URL</div>
                    <div style={{ fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: "rgba(255,255,255,0.7)", wordBreak: "break-all" }}>{url}</div>
                  </div>
                </div>
              )}

              {!urlResult && !urlLoading && (
                <div style={{ border: "1px dashed rgba(255,255,255,0.06)", borderRadius: 12, padding: "32px 20px", textAlign: "center" }}>
                  <div style={{ fontSize: 32, marginBottom: 8, opacity: 0.2 }}>⬡</div>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.2)", fontFamily: "'JetBrains Mono', monospace" }}>Enter a URL above to begin analysis</div>
                </div>
              )}

              {urlLoading && (
                <div style={{ border: "1px solid rgba(0,255,163,0.15)", borderRadius: 12, padding: "28px 20px", textAlign: "center" }}>
                  <div style={{ display: "flex", justifyContent: "center", marginBottom: 12 }}>
                    <div className="spinner" style={{ width: 32, height: 32, borderWidth: 3 }} />
                  </div>
                  <div style={{ fontSize: 12, color: "#00ffa3", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em" }}>SCANNING TARGET...</div>
                  <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>Analyzing threat patterns</div>
                </div>
              )}
            </div>

            {/* File Scanner */}
            <div className="glass" style={{ padding: 28, position: "relative", overflow: "hidden" }}>
              <ScanLine active={fileLoading} />
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 24 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#a78bfa", boxShadow: "0 0 8px #a78bfa" }} />
                <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: "0.1em", textTransform: "uppercase", color: "rgba(255,255,255,0.7)" }}>File Content Analyzer</span>
              </div>

              <input type="file" ref={fileRef} accept=".txt,.pdf" style={{ display: "none" }} onChange={e => { setFile(e.target.files[0]); setFileResult(null); setFileError(""); }} />

              <div className="upload-zone" onClick={() => fileRef.current.click()} style={{ marginBottom: 16 }}>
                {file ? (
                  <div>
                    <div style={{ fontSize: 24, marginBottom: 8 }}>📄</div>
                    <div style={{ fontSize: 14, color: "#fff", fontWeight: 600 }}>{file.name}</div>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>{(file.size / 1024).toFixed(1)} KB · Click to change</div>
                  </div>
                ) : (
                  <div>
                    <div style={{ fontSize: 28, marginBottom: 8, opacity: 0.3 }}>⬆</div>
                    <div style={{ fontSize: 14, color: "rgba(255,255,255,0.5)", marginBottom: 4 }}>Drop file or click to upload</div>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", fontFamily: "'JetBrains Mono', monospace" }}>TXT files supported · PDF requires server</div>
                  </div>
                )}
              </div>

              <button className="scan-btn" onClick={scanFile} disabled={!file || fileLoading} style={{ width: "100%", justifyContent: "center", display: "flex", alignItems: "center", gap: 8, background: "rgba(167,139,250,0.1)", borderColor: "rgba(167,139,250,0.3)", color: "#a78bfa" }}>
                {fileLoading ? <><span className="spinner" style={{ borderTopColor: "#a78bfa", borderColor: "rgba(167,139,250,0.2)" }} /> ANALYZING...</> : "ANALYZE FILE →"}
              </button>

              {fileError && <div style={{ color: "#ff4d4d", fontSize: 13, fontFamily: "'JetBrains Mono', monospace", padding: "12px 16px", background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.2)", borderRadius: 8, marginTop: 14 }}>{fileError}</div>}

              {fileResult && fileResult.type === "analysis" && (
                <div className="fade-in" style={{ marginTop: 16 }}>
                  {(() => {
                    const raw = fileResult.raw;
                    const isScam = raw.toUpperCase().includes("SCAM");
                    const cfg = isScam ? THREAT_CONFIG.scam : THREAT_CONFIG.legitimate;
                    const lines = raw.split("\n").filter(Boolean);
                    return (
                      <div style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 12, padding: 18 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                          <div style={{ fontSize: 22, color: cfg.color }}>{cfg.icon}</div>
                          <div style={{ fontSize: 16, fontWeight: 800, color: cfg.color }}>{cfg.label}</div>
                          <ThreatBadge type={isScam ? "scam" : "legitimate"} />
                        </div>
                        {lines.map((line, i) => (
                          <div key={i} style={{ fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: "rgba(255,255,255,0.6)", marginBottom: 6, lineHeight: 1.6 }}>
                            {line}
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </div>
              )}

              {fileResult && fileResult.type === "error" && (
                <div style={{ marginTop: 14, padding: 16, background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.2)", borderRadius: 10, fontSize: 13, fontFamily: "'JetBrains Mono', monospace", color: "#fbbf24", lineHeight: 1.6 }}>{fileResult.message}</div>
              )}
            </div>
          </div>

          {/* Threat Legend + History */}
          <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 24 }}>

            {/* Threat Legend */}
            <div className="glass" style={{ padding: 24 }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 18, fontFamily: "'JetBrains Mono', monospace" }}>Threat Classifications</div>
              {Object.entries(THREAT_CONFIG).slice(0, 4).map(([key, cfg]) => (
                <div key={key} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <div style={{ width: 28, height: 28, borderRadius: 7, background: cfg.bg, border: `1px solid ${cfg.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, color: cfg.color, flexShrink: 0 }}>{cfg.icon}</div>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: cfg.color }}>{cfg.label}</div>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontFamily: "'JetBrains Mono', monospace" }}>{cfg.desc}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Scan History */}
            <div className="glass" style={{ padding: 24 }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase", color: "rgba(255,255,255,0.35)", marginBottom: 18, fontFamily: "'JetBrains Mono', monospace" }}>Scan History</div>
              {history.length === 0 ? (
                <div style={{ textAlign: "center", padding: "32px 0", color: "rgba(255,255,255,0.15)", fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}>No scans yet — results will appear here</div>
              ) : (
                <div>
                  {history.map((item, i) => {
                    const cfg = THREAT_CONFIG[item.result] || { color: "#fff", label: item.result?.toUpperCase(), icon: "?" };
                    return (
                      <div key={i} className="history-row" style={{ display: "grid", gridTemplateColumns: "24px 1fr auto auto", alignItems: "center", gap: 12, padding: "9px 8px", borderRadius: 8, transition: "background 0.15s" }}>
                        <div style={{ fontSize: 14, color: cfg.color }}>{cfg.icon}</div>
                        <div style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: "rgba(255,255,255,0.5)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.input}</div>
                        <ThreatBadge type={item.result} />
                        <div style={{ fontSize: 10, color: "rgba(255,255,255,0.2)", fontFamily: "'JetBrains Mono', monospace", whiteSpace: "nowrap" }}>{item.time}</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

        </div>
      </div>
    </>
  );
}
