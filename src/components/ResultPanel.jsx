import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock3, FileSearch, ShieldAlert, ShieldCheck } from "lucide-react";

function pretty(value="") { return String(value).replaceAll("_"," ").toLowerCase().replace(/\b\w/g, c=>c.toUpperCase()); }
export default function ResultPanel({ result, error }) {
  const [showDetails, setShowDetails] = useState(false);
  const [reportedLocally, setReportedLocally] = useState(false);
  const [humanAnswer, setHumanAnswer] = useState("");

  useEffect(() => {
    setReportedLocally(false);
    setHumanAnswer("");
  }, [result?.analysis_id]);
  if (error) return <section className="panel result-empty"><div className="empty-icon danger"><AlertTriangle/></div><h3>Analysis couldn't be completed</h3><p>{error}</p><span className="muted">Check that the backend is running and try again.</span></section>;
  if (!result) return <section className="panel result-empty"><div className="empty-icon"><FileSearch size={25}/></div><h3>Your analysis will appear here</h3><p>Upload a screenshot to see extracted details, risk indicators and the analysis summary.</p><div className="empty-tags"><span>OCR extraction</span><span>Visual checks</span><span>Duplicate ID check</span></div></section>;

  const score = Number(result.risk_score ?? 0);
  const verdict = result.verdict || "INCONCLUSIVE";
  const danger = ["DANGEROUS","SUSPICIOUS","HIGH_RISK"].includes(verdict);
  const caution = ["CAUTION","INCONCLUSIVE"].includes(verdict);
  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  const checks = result.checks || [];
  const extracted = result.extracted_data || {};
  const evidence = result.evidence || {};
  const evidenceItems = evidence.items || [];
  const reputation = result.reputation || {};
  const payeeName = String(result.payee_name || extracted.payee_name || "").trim();

  async function reportQrLocally() {
    const vpaHash = reputation.vpa_hash;
    if (!vpaHash) return;
    try {
      const stored = JSON.parse(localStorage.getItem("upishield_reported_vpa_hashes") || "[]");
      const hashes = Array.isArray(stored) ? stored : [];
      if (!hashes.includes(vpaHash)) {
        hashes.push(vpaHash);
        localStorage.setItem("upishield_reported_vpa_hashes", JSON.stringify(hashes.slice(-100)));
      }
      setReportedLocally(true);
    } catch {
      setReportedLocally(false);
    }
  }
  return <section className="panel result-panel">
    <div className="result-top"><div><span className="eyebrow">ANALYSIS REPORT</span><h2>Screenshot assessment</h2></div><span className="report-id">#{result.analysis_id ?? "NEW"}</span></div>
    <div className={`verdict-card ${danger?"verdict-danger":caution?"verdict-warn":"verdict-safe"}`}>
      <div className="verdict-symbol">{danger?<ShieldAlert/>:caution?<AlertTriangle/>:<ShieldCheck/>}</div>
      <div className="verdict-copy"><small>DETECTION RESULT</small><h3>{pretty(verdict)}</h3><p>{result.summary || "Assessment based on available screenshot indicators."}</p></div>
      <div className="risk-score"><b>{score}</b><small>/ 100 risk</small></div>
    </div>
    <div className="score-track"><span style={{width:`${Math.min(100,Math.max(0,score))}%`}} className={danger?"score-danger":""}/></div>
    {payeeName && <div className="human-verification">
      <small>PAYEE NAME</small>
      <b>{payeeName}</b>
      <p>Does this match the shop name or soundbox?</p>
      <div className="human-actions">
        <button type="button" className={humanAnswer==="yes"?"selected":""} onClick={()=>setHumanAnswer("yes")} aria-pressed={humanAnswer==="yes"}>Yes</button>
        <button type="button" className={humanAnswer==="no"?"selected no":""} onClick={()=>setHumanAnswer("no")} aria-pressed={humanAnswer==="no"}>No</button>
      </div>
      {humanAnswer==="no" && <span className="human-warning">Check the payee name carefully before paying.</span>}
    </div>}
    <p className="sticker-reminder">Also check that the QR is not a sticker placed over the original.</p>
    {reasons.length > 0 && <div className="security-reasons">
      <div className="checks-heading"><h3>Top security reasons</h3><span>{reasons.length} rules triggered</span></div>
      <div className="reason-list">{reasons.slice(0,3).map((reason,i)=><div className="reason-row" key={`${reason.id}-${i}`}>
        <span className={`reason-severity ${reason.severity}`}>{pretty(reason.severity)}</span>
        <p>{reason.reason}</p>
      </div>)}</div>
      {reasons.length > 3 && <button type="button" className="details-button" onClick={()=>setShowDetails(v=>!v)} aria-expanded={showDetails}>
        {showDetails ? "Hide details" : "Details"}
      </button>}
      {showDetails && reasons.length > 3 && <div className="reason-details">{reasons.slice(3).map((reason,i)=><div key={`${reason.id}-${i}`}><b>{pretty(reason.id)}</b><span>{reason.reason}</span></div>)}</div>}
    </div>}
    {reputation.vpa_hash && <div className="report-actions">
      <button type="button" className="report-button" onClick={reportQrLocally} disabled={reportedLocally}>
        {reportedLocally ? "Reported locally" : "Report this QR"}
      </button>
      {reputation.blocklisted && <span className="local-reputation">Found in local reported list</span>}
    </div>}
    <div className="detail-grid">
      <div className="detail-item"><small>APP DETECTED</small><b>{result.app_detected || "Unknown"}</b></div>
      <div className="detail-item"><small>LAYOUT CONFIDENCE</small><b>{result.confidence == null ? "Not available" : `${Math.round(Number(result.confidence)*100)}%`}</b></div>
      <div className="detail-item"><small>AMOUNT</small><b>{extracted.amount ? `₹${extracted.amount}` : "Not extracted"}</b></div>
      <div className="detail-item"><small>TRANSACTION ID</small><b className="mono">{extracted.transaction_id || "Not extracted"}</b></div>
      <div className="detail-item"><small>TIMESTAMP</small><b>{extracted.timestamp || "Not extracted"}</b></div>
      <div className="detail-item"><small>PROCESSING</small><b><Clock3 size={14}/> {result.processing_ms != null ? `${result.processing_ms} ms` : "Not reported"}</b></div>
    </div>
    <div className="evidence-heading"><h3>What the scan found</h3><span>{evidence.ocr_confidence == null ? "OCR confidence unavailable" : `${Math.round(Number(evidence.ocr_confidence))}% OCR confidence`}</span></div>
    {evidence.orientation_corrected && <p className="evidence-note">The photo was rotated to improve text reading.</p>}
    {evidenceItems.length ? <div className="evidence-grid">{evidenceItems.map((item, i) => <div className="evidence-item" key={i}>
      <span className={`evidence-mark ${item.detected ? "found" : "missing"}`}>{item.detected ? <CheckCircle2 size={14}/> : <AlertTriangle size={14}/>}</span>
      <div><b>{item.label}</b><p>{item.snippet}</p></div>
    </div>)}</div> : <p className="muted">Field-level OCR evidence is not available for this scan.</p>}
    <p className="evidence-caveat">OCR confidence measures text readability only. It does not confirm that a payment settled.</p>
    <div className="checks-heading"><h3>Security checks</h3><span>{checks.length} checks reported</span></div>
    {checks.length ? <div className="check-list">{checks.map((check,i)=>{
      const pass = ["PASS","SAFE","OK"].includes(String(check.status).toUpperCase());
      return <div className="check-row" key={i}><span className={`check-icon ${pass?"pass":"fail"}`}>{pass?<CheckCircle2 size={17}/>:<AlertTriangle size={17}/>}</span><div><b>{pretty(check.name)}</b><p>{check.message || pretty(check.status)}</p></div><span className={`check-status ${pass?"pass":"fail"}`}>{pretty(check.status)}</span></div>;
    })}</div> : <p className="muted">No individual checks were returned by the API.</p>}
    <div className="disclaimer"><AlertTriangle size={16}/><p>This is an automated screenshot assessment, not bank or UPI payment confirmation. Verify receipt in the recipient's official bank or payment app before releasing goods.</p></div>
  </section>;
}