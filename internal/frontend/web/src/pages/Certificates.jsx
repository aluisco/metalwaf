import { useEffect, useState } from 'react'
import { certs as api } from '../api.js'
import {
  CAlert, CSpinner, CBadge, CButton, CFormInput, CFormLabel, CFormTextarea,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
} from '@coreui/react'
import { notifications } from '../lib/notifications.js'
import { useDisclosure } from '../lib/use-disclosure.js'

function expiryBadge(expiry) {
  if (!expiry) return <CBadge color="secondary">Unknown</CBadge>
  const days = Math.ceil((new Date(expiry) - Date.now()) / 86400000)
  if (days < 0)   return <CBadge color="danger">Expired</CBadge>
  if (days < 14)  return <CBadge color="warning">{days}d left</CBadge>
  return <CBadge color="success">{new Date(expiry).toLocaleDateString()}</CBadge>
}

function Empty() {
  return (
    <tr>
      <td colSpan={5} className="text-center text-body-secondary py-4">No certificates found</td>
    </tr>
  )
}

export default function Certificates() {
  const [certs,    setCerts]   = useState([])
  const [loading, setLoading]  = useState(true)
  const [error,   setError]    = useState('')
  const [form,    setForm]     = useState({ domain:'', cert:'', key:'' })
  const [acme,    setAcme]     = useState({ domain:'' })
  const [saving,  setSaving]   = useState(false)
  const [uploadOpen, { open: openUpload, close: closeUpload }] = useDisclosure(false)
  const [acmeOpen,   { open: openAcme,   close: closeAcme   }] = useDisclosure(false)

  function load() {
    setLoading(true)
    api.list().then(setCerts).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  async function handleUpload(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.upload(form)
      notifications.show({ message: 'Certificate uploaded', color: 'teal' })
      closeUpload()
      load()
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(false) }
  }

  async function handleAcme(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.requestACME(acme.domain)
      notifications.show({ message: 'ACME cert requested — check back soon', color: 'teal' })
      closeAcme()
      load()
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(false) }
  }

  async function deleteCert(id) {
    try {
      await api.delete(id)
      notifications.show({ message: 'Certificate deleted', color: 'teal' })
      load()
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="fw-semibold mb-0">Certificates</h2>
        <div className="d-flex gap-2">
          <CButton color="secondary" variant="outline" onClick={openAcme}>Request ACME</CButton>
          <CButton color="primary" onClick={openUpload}>Upload Certificate</CButton>
        </div>
      </div>

      {error && <CAlert color="danger">{error}</CAlert>}
      {loading ? (
        <div className="text-center py-5"><CSpinner color="primary" /></div>
      ) : (
        <CTable bordered hover responsive>
          <CTableHead>
            <CTableRow>
              <CTableHeaderCell>Domain</CTableHeaderCell>
              <CTableHeaderCell>Source</CTableHeaderCell>
              <CTableHeaderCell>Expiry</CTableHeaderCell>
              <CTableHeaderCell>Alt Names</CTableHeaderCell>
              <CTableHeaderCell></CTableHeaderCell>
            </CTableRow>
          </CTableHead>
          <CTableBody>
            {certs.length === 0 ? <Empty /> : certs.map(c => (
              <CTableRow key={c.id}>
                <CTableDataCell>{c.domain}</CTableDataCell>
                <CTableDataCell>
                  <CBadge color={c.source === 'acme' ? 'info' : 'secondary'}>{c.source ?? 'manual'}</CBadge>
                </CTableDataCell>
                <CTableDataCell>{expiryBadge(c.expires_at ?? c.expiry)}</CTableDataCell>
                <CTableDataCell>
                  <small className="text-body-secondary">{(c.alt_names ?? []).join(', ') || '—'}</small>
                </CTableDataCell>
                <CTableDataCell>
                  <CButton size="sm" color="danger" variant="ghost" onClick={() => deleteCert(c.id)}>Delete</CButton>
                </CTableDataCell>
              </CTableRow>
            ))}
          </CTableBody>
        </CTable>
      )}

      {/* Upload modal */}
      <CModal visible={uploadOpen} onClose={closeUpload} size="lg">
        <CModalHeader><CModalTitle>Upload Certificate</CModalTitle></CModalHeader>
        <form onSubmit={handleUpload}>
          <CModalBody>
            <div className="mb-3">
              <CFormLabel>Domain</CFormLabel>
              <CFormInput placeholder="example.com" value={form.domain} required
                onChange={e => setForm(f => ({...f, domain: e.target.value}))} />
            </div>
            <div className="mb-3">
              <CFormLabel>Certificate (PEM)</CFormLabel>
              <CFormTextarea rows={6} placeholder="-----BEGIN CERTIFICATE-----" value={form.cert} required
                onChange={e => setForm(f => ({...f, cert: e.target.value}))}
                style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </div>
            <div className="mb-3">
              <CFormLabel>Private Key (PEM)</CFormLabel>
              <CFormTextarea rows={6} placeholder="-----BEGIN PRIVATE KEY-----" value={form.key} required
                onChange={e => setForm(f => ({...f, key: e.target.value}))}
                style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </div>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" type="button" onClick={closeUpload}>Cancel</CButton>
            <CButton color="primary" type="submit" disabled={saving}>{saving ? <CSpinner size="sm" /> : 'Upload'}</CButton>
          </CModalFooter>
        </form>
      </CModal>

      {/* ACME modal */}
      <CModal visible={acmeOpen} onClose={closeAcme}>
        <CModalHeader><CModalTitle>Request Let&apos;s Encrypt Certificate</CModalTitle></CModalHeader>
        <form onSubmit={handleAcme}>
          <CModalBody>
            <div className="mb-3">
              <CFormLabel>Domain</CFormLabel>
              <CFormInput placeholder="example.com" value={acme.domain} required
                onChange={e => setAcme({ domain: e.target.value })} />
            </div>
            <CAlert color="info" className="small mb-0">
              The domain must resolve to this server. Port 80 must be reachable for the HTTP-01 challenge.
            </CAlert>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" type="button" onClick={closeAcme}>Cancel</CButton>
            <CButton color="primary" type="submit" disabled={saving}>{saving ? <CSpinner size="sm" /> : 'Request'}</CButton>
          </CModalFooter>
        </form>
      </CModal>
    </>
  )
}
