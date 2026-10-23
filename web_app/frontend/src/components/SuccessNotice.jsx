import { useEffect } from "react";

function SuccessNotice({ message, onClose, durationMs = 6000 }) {
  useEffect(() => {
    if (!message) return undefined;
    const timeoutId = window.setTimeout(onClose, durationMs);
    return () => window.clearTimeout(timeoutId);
  }, [message, onClose, durationMs]);

  if (!message) return null;

  return (
    <div className="success-message dismissible-message" role="status">
      <span>{message}</span>
      <button
        type="button"
        className="message-close"
        aria-label="Cerrar notificación"
        onClick={onClose}
      >
        ×
      </button>
    </div>
  );
}

export default SuccessNotice;
