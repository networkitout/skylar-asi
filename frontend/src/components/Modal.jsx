import React from 'react';
import { X } from 'lucide-react';

const Modal = ({ isOpen, onClose, title, children, footer }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2 className="modal-title">{title}</h2>
          <button className="btn-icon" onClick={onClose} aria-label="Close"><X /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
};

// Replaces window.confirm (see docs/UI_CONVENTIONS.md). Usage:
//   const [confirm, setConfirm] = useState(null);
//   setConfirm({ message, detail, onConfirm, destructive: true })
//   <ConfirmModal state={confirm} onClose={() => setConfirm(null)} />
export const ConfirmModal = ({ state, onClose }) => {
  if (!state) return null;
  const { title = 'Confirm', message, detail, confirmLabel = 'Confirm', destructive = false, onConfirm } = state;
  const run = async () => {
    await onConfirm?.();
    onClose();
  };
  return (
    <Modal
      isOpen
      onClose={onClose}
      title={title}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className={`btn ${destructive ? 'btn-danger' : 'btn-primary'}`} onClick={run}>{confirmLabel}</button>
        </>
      }
    >
      <div className="confirm-message">{message}</div>
      {detail && <div className="confirm-submessage">{detail}</div>}
    </Modal>
  );
};

// Replaces window.alert for error reporting.
export const NoticeModal = ({ state, onClose }) => {
  if (!state) return null;
  const { title = 'Something went wrong', message } = state;
  return (
    <Modal isOpen onClose={onClose} title={title} footer={<button className="btn btn-secondary" onClick={onClose}>Close</button>}>
      <div className="confirm-message">{message}</div>
    </Modal>
  );
};

export default Modal;
