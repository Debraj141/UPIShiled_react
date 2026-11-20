import { useRef, useState } from "react";
import { Upload, Image as ImageIcon, ScanLine, ShieldCheck, X } from "lucide-react";
import { Capacitor } from "@capacitor/core";
import { Camera, CameraResultType, CameraSource } from "@capacitor/camera";

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
    if (preview) URL.revokeObjectURL(preview);
    setPreview(URL.createObjectURL(next));
  }

  async function captureNative(source) {
    setError("");
    try {
      const photo = await Camera.getPhoto({
        quality: 90,
        allowEditing: false,
        resultType: CameraResultType.Uri,
        source,
      });
      if (!photo.webPath) throw new Error("The selected image could not be opened.");

      const response = await fetch(photo.webPath);
      if (!response.ok) throw new Error("The selected image could not be read.");
      const blob = await response.blob();
      const type = blob.type || (photo.format === "png" ? "image/png" : "image/jpeg");
      const extension = type === "image/png" ? "png" : type === "image/webp" ? "webp" : "jpg";
      choose(new File([blob], `payment-screenshot-${Date.now()}.${extension}`, { type }));
    } catch (error) {
      if (!String(error?.message || error).toLowerCase().includes("cancel")) {
        setError(error.message || "Unable to open the camera or photo library.");
      }
    }
  }

  function openCamera() {
    if (Capacitor.isNativePlatform()) {
      captureNative(CameraSource.Camera);
    } else {
      cameraRef.current?.click();
    }
  }

  function openPhotos() {
    if (Capacitor.isNativePlatform()) {
      captureNative(CameraSource.Photos);
    } else {
      inputRef.current?.click();
    }
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
    {!file ? <button className="dropzone" onClick={openPhotos} onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();choose(e.dataTransfer.files?.[0]);}}>
      <span className="upload-icon"><Upload size={23}/></span><b>Drop your screenshot here</b><span>or <em>browse files</em> from your device</span><small>PNG, JPG or WEBP · Max 8 MB</small>
    </button> : <div className="preview-box"><img src={preview} alt="Selected payment screenshot"/><div className="file-info"><ImageIcon size={17}/><div><b>{file.name}</b><small>{(file.size/1024).toFixed(0)} KB · Ready for analysis</small></div></div><button className="remove-file" onClick={clear} aria-label="Remove image"><X size={17}/></button></div>}
    {!file && <div className="mobile-source-actions"><button type="button" onClick={openCamera}><ScanLine size={18}/> Take photo</button><button type="button" onClick={openPhotos}><ImageIcon size={18}/> Choose image</button></div>}
    {error && <div className="error-text">{error}</div>}
    <div className="upload-footer"><div className="secure-note"><ShieldCheck size={16}/> Secure image processing</div><button className="primary-button" disabled={!file || busy} onClick={()=>onAnalyze(file)}>{busy ? <><span className="spinner"/> Analyzing…</> : <><ScanLine size={17}/> Analyze screenshot</>}</button></div>
    <p className="fine-print">UPIShield evaluates screenshot indicators only. It does not verify bank settlement or confirm that funds were received.</p>
  </section>;
}