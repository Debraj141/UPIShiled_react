import { Bell, Menu, ShieldCheck } from "lucide-react";
export default function Topbar({ onMenu }) {
  return <header className="topbar">
    <button className="mobile-menu icon-button" onClick={onMenu}><Menu size={20}/></button>
    <div className="crumb"><ShieldCheck size={16}/> <span>Security workspace</span><i>/</i><b>Overview</b></div>
    <div className="top-actions"><span className="system-status"><span className="live-dot"/> System ready</span><button className="icon-button" aria-label="Notifications"><Bell size={18}/></button><div className="avatar">UP</div></div>
  </header>;
}