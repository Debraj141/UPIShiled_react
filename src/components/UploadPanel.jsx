import { useRef, useState } from "react";
import { Upload, Image as ImageIcon, ScanLine, ShieldCheck, X } from "lucide-react";
export default function UploadPanel({ onAnalyze, busy }) {
  const inputRef = useRef(null);
  const cameraRef = useRef(null);
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [error, setError] = useState("");

  function choose(next) {
    setError("");
    if (!next) return;
    if (!["image/png", "image/jpeg", "image/webp"].includes(next.type)) {
      setError("Please select a PNG, JPG or WEBP image."); return;
    }
    if (next.size > 8 * 1024 * 1024) {
      setError("Image must be smaller than 8 MB."); return;
    }
    setFile(next);
    setPreview(URL.createObjectURL(next));
  }
  function clear() {
    if (preview) URL.revokeObjectURL(preview);
    setFile(null); setPreview(""); setError("");
    if (inputRef.current) inputRef.current.value = "";
    if (cameraRef.current) cameraRef.current.value = "";
  }
  return <section className="panel upload-panel">
    <div className="section-heading"><div><span className="eyebrow">START A CHECK</span><h2>Analyze a payment screenshot</h2><p>Upload a payment confirmation image to inspect its authenticity indicators.</p></div><div className="heading-icon"><ScanLine size={21}/></div></div>
    <input
  ref={inputRef}
  type="file"
  accept="image/*"
  hidden
  onChange={(e) => choose(e.target.files?.[0])}
/>
    <input
      ref={cameraRef}
      type="file"
      accept="image/*"
      capture="environment"
      hidden
      onChange={(e) => choose(e.target.files?.[0])}
    />
    {!file ? <button className="dropzone" onClick={() => inputRef.current?.click()} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();choose(e.dataTransfer.files?.[0]);}}>
      <span className="upload-icon"><Upload size={23}/></span><b>Drop your screenshot here</b><span>or <em>browse files</em> from your device</span><small>PNG, JPG or WEBP · Max 8 MB</small>
    </button> : <div className="preview-box"><img src={preview} alt="Selected payment screenshot"/><div className="file-info"><ImageIcon size={17}/><div><b>{file.name}</b><small>{(file.size/1024).toFixed(0)} KB · Ready for analysis</small></div></div><button className="remove-file" onClick={clear} aria-label="Remove image"><X size={17}/></button></div>}
    {!file && <div className="mobile-source-actions"><button type="button" onClick={() => cameraRef.current?.click()}><ScanLine size={18}/> Take photo</button><button type="button" onClick={() => inputRef.current?.click()}><ImageIcon size={18}/> Choose image</button></div>}
    {error && <div className="error-text">{error}</div>}
    <div className="upload-footer"><div className="secure-note"><ShieldCheck size={16}/> Secure image processing</div><button className="primary-button" disabled={!file || busy} onClick={()=>onAnalyze(file)}>{busy ? <><span className="spinner"/> Analyzing…</> : <><ScanLine size={17}/> Analyze screenshot</>}</button></div>
    <p className="fine-print">UPIShield evaluates screenshot indicators only. It does not verify bank settlement or confirm that funds were received.</p>
  </section>;
}