import { useEffect, useId, useRef } from "react";

function ConfirmAssetStatusModal({ asset, busy, onCancel, onConfirm }) {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef(null);
  const cancelRef = useRef(null);

  const restoring = asset.inventory_status === "ARCHIVED";

  useEffect(() => {
    const previouslyFocused = document.activeElement;
    cancelRef.current?.focus();

    return () => {
      previouslyFocused?.focus?.();
    };
  }, []);

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!busy) onCancel();
        return;
      }

      if (event.key !== "Tab") return;

      const buttons = Array.from(
        dialogRef.current?.querySelectorAll("button:not(:disabled)") || []
      );

      if (!buttons.length) {
        event.preventDefault();
        return;
      }

      const first = buttons[0];
      const last = buttons[buttons.length - 1];

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [busy, onCancel]);

  return (
    <div className="modal-backdrop asset-confirm-backdrop">
      <section
        ref={dialogRef}
        className="asset-confirm-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        aria-busy={busy}
      >
        <div className="asset-confirm-header">
          <span
            className={
              restoring
                ? "asset-confirm-symbol asset-confirm-symbol-restore"
                : "asset-confirm-symbol"
            }
            aria-hidden="true"
          >
            {restoring ? "↺" : "!"}
          </span>
          <div>
            <span className="page-eyebrow">INVENTARIO DE ACTIVOS</span>
            <h2 id={titleId}>
              {restoring ? "¿Restaurar activo?" : "¿Archivar activo?"}
            </h2>
          </div>
        </div>

        <p id={descriptionId} className="asset-confirm-description">
          {restoring
            ? <>El activo <strong>{asset.name}</strong> volverá a aparecer en el inventario actual.</>
            : <>El activo <strong>{asset.name}</strong> dejará de aparecer en el inventario actual. Sus datos se conservarán y podrás restaurarlo después.</>}
        </p>

        <div className="asset-confirm-actions">
          <button
            ref={cancelRef}
            type="button"
            className="button-secondary"
            onClick={onCancel}
            disabled={busy}
          >
            Cancelar
          </button>
          <button
            type="button"
            className={
              restoring
                ? "asset-confirm-submit asset-confirm-submit-restore"
                : "asset-confirm-submit"
            }
            onClick={onConfirm}
            disabled={busy}
          >
            {busy
              ? "Procesando..."
              : restoring ? "Restaurar activo" : "Archivar activo"}
          </button>
        </div>
      </section>
    </div>
  );
}

export default ConfirmAssetStatusModal;
