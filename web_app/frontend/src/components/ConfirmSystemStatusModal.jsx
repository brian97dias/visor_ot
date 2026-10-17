import { useEffect, useId, useRef } from "react";

export default function ConfirmSystemStatusModal({system,busy,onCancel,onConfirm}) {
  const titleId=useId();
  const dialogRef=useRef(null);
  const cancelRef=useRef(null);
  const restoring=system.status==="ARCHIVED";

  useEffect(()=>{
    const previous=document.activeElement;
    cancelRef.current?.focus();
    function onKey(e){
      if(e.key==="Escape") {if(!busy){e.preventDefault();onCancel();}return;}
      if(e.key!=="Tab")return;
      const buttons=[...(dialogRef.current?.querySelectorAll("button:not(:disabled)")||[])];
      if(buttons.length<2)return;
      if(e.shiftKey&&document.activeElement===buttons[0]){
        e.preventDefault();buttons[buttons.length-1].focus();
      }else if(!e.shiftKey&&document.activeElement===buttons[buttons.length-1]){
        e.preventDefault();buttons[0].focus();
      }
    }
    document.addEventListener("keydown",onKey);
    return ()=>{document.removeEventListener("keydown",onKey);previous?.focus?.();};
  },[busy,onCancel]);

  return <div className="modal-backdrop asset-confirm-backdrop">
    <section ref={dialogRef} className="asset-confirm-dialog" role="dialog"
      aria-modal="true" aria-labelledby={titleId} aria-busy={busy}>
      <div className="asset-confirm-header">
        <span className={restoring?
          "asset-confirm-symbol asset-confirm-symbol-restore":"asset-confirm-symbol"}
          aria-hidden="true">{restoring?"↺":"!"}</span>
        <div><span className="page-eyebrow">SISTEMAS OT</span>
          <h2 id={titleId}>{restoring?"¿Restaurar sistema?":"¿Archivar sistema?"}</h2>
        </div>
      </div>
      <p className="asset-confirm-description">
        El sistema <strong>{system.name}</strong> {restoring?
          "volverá a estar activo.":"se conservará para consulta y podrás restaurarlo después."}
      </p>
      <div className="asset-confirm-actions">
        <button ref={cancelRef} type="button" className="button-secondary"
          disabled={busy} onClick={onCancel}>Cancelar</button>
        <button type="button" disabled={busy}
          className={restoring?
            "asset-confirm-submit asset-confirm-submit-restore":"asset-confirm-submit"}
          onClick={onConfirm}>{busy?"Procesando...":
            restoring?"Restaurar sistema":"Archivar sistema"}</button>
      </div>
    </section>
  </div>;
}
