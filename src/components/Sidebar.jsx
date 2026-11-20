import { ShieldCheck, LayoutDashboard, ScanLine, History, CircleHelp } from "lucide-react";

const items = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "scan", label: "New analysis", icon: ScanLine },
  { id: "history", label: "Scan history", icon: History }
];

export default function Sidebar({ page, setPage }) {
  return <aside className="sidebar">
    <div className="brand"><div className="brand-mark"><ShieldCheck size={22}/></div><div><b>UPIShield</b><small>PAYMENT SECURITY</small></div></div>
    <div className="nav-label">WORKSPACE</div>
    {items.map(({id,label,icon:Icon}) => <button key={id} onClick={() => setPage(id)} className={`nav-item ${page===id?"active":""}`}><Icon size={18}/>{label}</button>)}
    <div className="sidebar-bottom">
      <div className="help-card"><CircleHelp size={18}/><b>Need help?</b><p>Learn how screenshot analysis works.</p><span>View guide ↗</span></div>
      <div className="privacy-note"><span className="live-dot"/> Privacy-first analysis<br/><small>Uploads are processed for analysis.</small></div>
    </div>
  </aside>;
}