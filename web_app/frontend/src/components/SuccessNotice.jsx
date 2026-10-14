import { useEffect } from "react";

function SuccessNotice({ message, onClose }) {
  useEffect(() => {
    if (!message) return undefined;
    const timeoutId = window.setTimeout(onClose, 6000);
    return () => window.clearTimeout(timeoutId);
  }, [message, onClose]);

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
