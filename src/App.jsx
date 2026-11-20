import { useState } from "react";
import { Activity, ArrowUpRight, Clock3, FileCheck2, History, LayoutDashboard, ScanLine, ShieldCheck, Sparkles } from "lucide-react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import UploadPanel from "./components/UploadPanel";
import ResultPanel from "./components/ResultPanel";
import { analyzeScreenshot, getHistory } from "./services/api";

export default function App() {
  const [page,setPage] = useState("overview");
  const [busy,setBusy] = useState(false);
  const [result,setResult] = useState(null);
  const [error,setError] = useState("");
  const [history,setHistory] = useState([]);
  const [menuOpen,setMenuOpen] = useState(false);

  async function runAnalysis(file) {
    setBusy(true); setError(""); setResult(null);
    try {
      const data = await analyzeScreenshot(file);
      setResult(data);
      setPage("scan");
      loadHistory();
    } catch (e) {
      const isTimeout = e.code === "ECONNABORTED";
      setError(
        isTimeout
          ? "Analysis took too long. Please try again with a smaller screenshot."
          : e.response?.data?.detail || e.message || "Unable to reach the analysis service."
      );
    } finally { setBusy(false); }
  }
  async function loadHistory() {
    try {
      const data = await getHistory();
      setHistory(Array.isArray(data) ? data : data.items || data.history || []);
    } catch { setHistory([]); }
  }
  function navigate(next) {
    setPage(next); setMenuOpen(false);
    if (next === "history") loadHistory();
    if (next === "scan") { setResult(null); setError(""); }
  }

  return <div className="app-shell">
    <div className={`sidebar-wrap ${menuOpen?"open":""}`}><Sidebar page={page} setPage={navigate}/></div>
    {menuOpen && <button className="mobile-overlay" onClick={()=>setMenuOpen(false)} aria-label="Close menu"/>}
    <main className="main-area">
      <Topbar onMenu={()=>setMenuOpen(v=>!v)}/>
      <div className="content">
        <div className="welcome-row"><div><span className="eyebrow">PAYMENT SCREENSHOT INTELLIGENCE</span><h1>{page==="history"?"Scan history":page==="scan"?"New analysis":"Good evening, team."}</h1><p>{page==="history"?"Review previous screenshot assessments.":page==="scan"?"Run a forensic check on a UPI payment screenshot.":"A clearer view of payment screenshot risk starts here."}</p></div><div className="date-chip"><Activity size={15}/> Detection workspace</div></div>
        {page==="overview" && <>
          <div className="stats-grid">
            <div className="stat-card"><div className="stat-icon blue"><FileCheck2/></div><small>ANALYSIS ENGINE</small><b>Ready</b><span>Waiting for screenshot</span></div>
            <div className="stat-card"><div className="stat-icon green"><ShieldCheck/></div><small>DETECTION METHOD</small><b>Multi-check</b><span>OCR + visual rules</span></div>
            <div className="stat-card"><div className="stat-icon amber"><Clock3/></div><small>RESPONSE TARGET</small><b>&lt; 3 seconds</b><span>Measured during testing</span></div>
          </div>
          <div className="main-grid"><UploadPanel onAnalyze={runAnalysis} busy={busy}/><ResultPanel result={result} error={error}/></div>
          <div className="bottom-tip"><Sparkles size={18}/><div><b>How UPIShield works</b><p>It extracts visible payment details, checks known layout patterns and looks for suspicious inconsistencies. A screenshot cannot prove that funds were transferred.</p></div><button onClick={()=>navigate("scan")}>Start analysis <ArrowUpRight size={15}/></button></div>
        </>}
        {page==="scan" && <div className="main-grid single-result"><UploadPanel onAnalyze={runAnalysis} busy={busy}/><ResultPanel result={result} error={error}/></div>}
        {page==="history" && <section className="panel history-panel"><div className="section-heading"><div><span className="eyebrow">YOUR ACTIVITY</span><h2>Recent analyses</h2><p>Previous reports returned by the backend.</p></div><button className="secondary-button" onClick={loadHistory}>Refresh</button></div>{history.length ? <div className="history-list">{history.map((item,i)=><div className="history-row" key={item.id || item.analysis_id || i}><div className="history-file"><FileCheck2 size={18}/></div><div className="history-meta"><b>Analysis #{item.id || item.analysis_id || i+1}</b><small>{item.app_detected || "Unknown app"} · {item.created_at || "Date unavailable"}</small></div><span className={`history-verdict ${String(item.verdict).includes("SUSPICIOUS")?"fail":"pass"}`}>{item.verdict || "INCONCLUSIVE"}</span><b className="history-score">{item.risk_score ?? "—"}</b></div>)}</div>:<div className="history-empty"><Clock3 size={25}/><b>No analysis history yet</b><p>Once the backend saves reports, they will appear here.</p></div>}</section>}
        <nav className="mobile-bottom-nav" aria-label="Mobile navigation">
          <button className={page==="overview"?"active":""} onClick={()=>navigate("overview")}><LayoutDashboard size={20}/><span>Overview</span></button>
          <button className={`mobile-scan-button ${page==="scan"?"active":""}`} onClick={()=>navigate("scan")}><span><ScanLine size={23}/></span><b>Scan</b></button>
          <button className={page==="history"?"active":""} onClick={()=>navigate("history")}><History size={20}/><span>History</span></button>
        </nav>
        <footer className="footer"><span>© 2026 UPIShield · Built for Code Fuzion</span><span><ShieldCheck size={14}/> Screenshot analysis, not payment verification</span></footer>
      </div>
    </main>
  </div>;
}