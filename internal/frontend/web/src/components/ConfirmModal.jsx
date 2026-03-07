import {
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CButton, CAlert,
} from '@coreui/react'

/**
 * props: opened, onClose, onConfirm, title, message,
 *        confirmLabel = "Confirm", confirmColor = "danger"
 */
export default function ConfirmModal({
  opened,
  onClose,
  onConfirm,
  title = 'Confirm action',
  message,
  confirmLabel = 'Confirm',
  confirmColor = 'danger',
}) {
  return (
    <CModal visible={opened} onClose={onClose} alignment="center">
      <CModalHeader><CModalTitle>{title}</CModalTitle></CModalHeader>
      <CModalBody>
        {message && <p className="mb-0">{message}</p>}
      </CModalBody>
      <CModalFooter>
        <CButton color="secondary" variant="outline" onClick={onClose}>Cancel</CButton>
        <CButton color={confirmColor} onClick={() => { onConfirm(); onClose() }}>{confirmLabel}</CButton>
      </CModalFooter>
    </CModal>
  )
}
