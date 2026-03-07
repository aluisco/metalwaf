import { useEffect, useState } from 'react'
import { sites as api } from '../api.js'
import {
  CButton, CAlert, CSpinner, CBadge,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CForm, CFormLabel, CFormInput, CFormSelect, CFormCheck,
} from '@coreui/react'
import { useDisclosure } from '../lib/use-disclosure.js'
import { notifications } from '../lib/notifications.js'
import ConfirmModal from '../components/ConfirmModal.jsx'

const WAF_MODES = ['off', 'detect', 'block']
const EMPTY_SITE = { name: '', domain: '', waf_mode: 'detect', https_only: false, enabled: true }
const EMPTY_UP   = { url: '', weight: 1, enabled: true }

export default function Sites() {
  const [list, setList]       = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [saving, setSaving]   = useState(false)

  const [siteOpened, { open: openSite, close: closeSite }] = useDisclosure()
  const [upOpened,   { open: openUp,   close: closeUp   }] = useDisclosure()
  const [panelOpened,{ open: openPanel,close: closePanel}] = useDisclosure()

  const [current,   setCurrent]   = useState(null)
  const [siteForm,  setSiteForm]  = useState(EMPTY_SITE)
  const [panelSite, setPanelSite] = useState(null)
  const [upList,    setUpList]    = useState([])
  const [currentUp, setCurrentUp] = useState(null)
  const [upForm,    setUpForm]    = useState(EMPTY_UP)
  const [delSite,   setDelSite]   = useState(null)
  const [delUp,     setDelUp]     = useState(null)

  const load = () => {
    setLoading(true)
    api.list().then(setList).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startCreate() { setCurrent(null); setSiteForm(EMPTY_SITE); openSite() }
  function startEdit(s)  { setCurrent(s); setSiteForm({ name: s.name, domain: s.domain, waf_mode: s.waf_mode, https_only: s.https_only, enabled: s.enabled }); openSite() }

  async function saveSite(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!current) await api.create(siteForm); else await api.update(current.id, siteForm)
      closeSite(); load()
      notifications.show({ message: current ? 'Site updated' : 'Site created', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function deleteSite(s) {
    try { await api.delete(s.id); load(); notifications.show({ message: 'Site deleted', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  function openUpstreams(s) {
    setPanelSite(s)
    api.listUpstreams(s.id).then(setUpList).catch(e => notifications.show({ message: e.message, color: 'red' }))
    openPanel()
  }
  function startAddUp()   { setCurrentUp(null); setUpForm(EMPTY_UP); openUp() }
  function startEditUp(u) { setCurrentUp(u); setUpForm({ url: u.url, weight: u.weight, enabled: u.enabled }); openUp() }

  async function saveUpstream(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!currentUp) await api.createUpstream(panelSite.id, upForm)
      else            await api.updateUpstream(panelSite.id, currentUp.id, upForm)
      closeUp(); api.listUpstreams(panelSite.id).then(setUpList)
      notifications.show({ message: 'Upstream saved', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function deleteUpstream(u) {
    try { await api.deleteUpstream(panelSite.id, u.id); api.listUpstreams(panelSite.id).then(setUpList) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  if (loading) return <div className="text-center py-5"><CSpinner color="primary" /></div>
  if (error)   return <CAlert color="danger">{error}</CAlert>

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="mb-0 fw-semibold">Sites</h2>
        <CButton color="primary" onClick={startCreate}>+ New site</CButton>
      </div>

      {list.length === 0 ? (
        <p className="text-body-secondary">No sites configured yet.</p>
      ) : (
        <CTable bordered striped hover responsive>
          <CTableHead><CTableRow>
            <CTableHeaderCell>Name</CTableHeaderCell>
            <CTableHeaderCell>Domain</CTableHeaderCell>
            <CTableHeaderCell>WAF Mode</CTableHeaderCell>
            <CTableHeaderCell>HTTPS only</CTableHeaderCell>
            <CTableHeaderCell>Status</CTableHeaderCell>
            <CTableHeaderCell>Actions</CTableHeaderCell>
          </CTableRow></CTableHead>
          <CTableBody>
            {list.map(s => (
              <CTableRow key={s.id}>
                <CTableDataCell><strong>{s.name}</strong></CTableDataCell>
                <CTableDataCell><code>{s.domain}</code></CTableDataCell>
                <CTableDataCell><WafBadge mode={s.waf_mode} /></CTableDataCell>
                <CTableDataCell>{s.https_only ? '✓' : '—'}</CTableDataCell>
                <CTableDataCell>
                  <CBadge color={s.enabled ? 'success' : 'secondary'}>{s.enabled ? 'active' : 'disabled'}</CBadge>
                </CTableDataCell>
                <CTableDataCell>
                  <div className="d-flex gap-1">
                    <CButton size="sm" color="primary" variant="outline" onClick={() => startEdit(s)}>Edit</CButton>
                    <CButton size="sm" color="info"    variant="outline" onClick={() => openUpstreams(s)}>Upstreams</CButton>
                    <CButton size="sm" color="danger"  variant="outline" onClick={() => setDelSite(s)}>Delete</CButton>
                  </div>
                </CTableDataCell>
              </CTableRow>
            ))}
          </CTableBody>
        </CTable>
      )}

      {/* Site modal */}
      <CModal visible={siteOpened} onClose={closeSite} alignment="center">
        <CModalHeader><CModalTitle>{current ? 'Edit site' : 'New site'}</CModalTitle></CModalHeader>
        <CForm onSubmit={saveSite}>
          <CModalBody>
            <div className="mb-3"><CFormLabel>Name *</CFormLabel><CFormInput value={siteForm.name} onChange={e => setSiteForm(f=>({...f,name:e.target.value}))} required /></div>
            <div className="mb-3"><CFormLabel>Domain *</CFormLabel><CFormInput placeholder="example.com" value={siteForm.domain} onChange={e => setSiteForm(f=>({...f,domain:e.target.value}))} required /></div>
            <div className="mb-3">
              <CFormLabel>WAF Mode</CFormLabel>
              <CFormSelect value={siteForm.waf_mode} onChange={e => setSiteForm(f=>({...f,waf_mode:e.target.value}))}>
                {WAF_MODES.map(m => <option key={m} value={m}>{m.charAt(0).toUpperCase()+m.slice(1)}</option>)}
              </CFormSelect>
            </div>
            <div className="d-flex gap-4">
              <CFormCheck label="HTTPS only" checked={siteForm.https_only} onChange={e => setSiteForm(f=>({...f,https_only:e.target.checked}))} />
              <CFormCheck label="Enabled"    checked={siteForm.enabled}    onChange={e => setSiteForm(f=>({...f,enabled:e.target.checked}))} />
            </div>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" onClick={closeSite}>Cancel</CButton>
            <CButton type="submit" color="primary" disabled={saving}>{saving ? 'Saving…' : 'Save'}</CButton>
          </CModalFooter>
        </CForm>
      </CModal>

      {/* Upstreams panel */}
      <CModal visible={panelOpened} onClose={closePanel} size="lg" alignment="center">
        <CModalHeader><CModalTitle>Upstreams — {panelSite?.name ?? ''}</CModalTitle></CModalHeader>
        <CModalBody>
          <div className="d-flex justify-content-end mb-3">
            <CButton color="primary" size="sm" onClick={startAddUp}>+ Add upstream</CButton>
          </div>
          {upList.length === 0 ? <p className="text-body-secondary">No upstreams yet.</p> : (
            <CTable bordered hover>
              <CTableHead><CTableRow>
                <CTableHeaderCell>URL</CTableHeaderCell>
                <CTableHeaderCell>Weight</CTableHeaderCell>
                <CTableHeaderCell>Status</CTableHeaderCell>
                <CTableHeaderCell></CTableHeaderCell>
              </CTableRow></CTableHead>
              <CTableBody>
                {upList.map(u => (
                  <CTableRow key={u.id}>
                    <CTableDataCell><code>{u.url}</code></CTableDataCell>
                    <CTableDataCell>{u.weight}</CTableDataCell>
                    <CTableDataCell><CBadge color={u.enabled ? 'success' : 'secondary'}>{u.enabled ? 'on' : 'off'}</CBadge></CTableDataCell>
                    <CTableDataCell>
                      <div className="d-flex gap-1">
                        <CButton size="sm" color="primary" variant="outline" onClick={() => startEditUp(u)}>Edit</CButton>
                        <CButton size="sm" color="danger"  variant="outline" onClick={() => setDelUp(u)}>✕</CButton>
                      </div>
                    </CTableDataCell>
                  </CTableRow>
                ))}
              </CTableBody>
            </CTable>
          )}
        </CModalBody>
        <CModalFooter><CButton color="secondary" onClick={closePanel}>Close</CButton></CModalFooter>
      </CModal>

      {/* Upstream edit */}
      <CModal visible={upOpened} onClose={closeUp} alignment="center">
        <CModalHeader><CModalTitle>{currentUp ? 'Edit upstream' : 'Add upstream'}</CModalTitle></CModalHeader>
        <CForm onSubmit={saveUpstream}>
          <CModalBody>
            <div className="mb-3"><CFormLabel>URL *</CFormLabel><CFormInput placeholder="http://10.0.0.1:8080" value={upForm.url} onChange={e => setUpForm(f=>({...f,url:e.target.value}))} required /></div>
            <div className="mb-3"><CFormLabel>Weight</CFormLabel><CFormInput type="number" min={1} max={100} value={upForm.weight} onChange={e => setUpForm(f=>({...f,weight:+e.target.value}))} /></div>
            <CFormCheck label="Enabled" checked={upForm.enabled} onChange={e => setUpForm(f=>({...f,enabled:e.target.checked}))} />
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" onClick={closeUp}>Cancel</CButton>
            <CButton type="submit" color="primary" disabled={saving}>{saving ? 'Saving…' : 'Save'}</CButton>
          </CModalFooter>
        </CForm>
      </CModal>

      <ConfirmModal opened={!!delSite} onClose={() => setDelSite(null)} onConfirm={() => deleteSite(delSite)} title="Delete site" message={`Delete site "${delSite?.name}"? This cannot be undone.`} />
      <ConfirmModal opened={!!delUp}   onClose={() => setDelUp(null)}   onConfirm={() => deleteUpstream(delUp)} title="Delete upstream" message={`Delete upstream "${delUp?.url}"?`} />
    </>
  )
}

function WafBadge({ mode }) {
  const map = { block: 'danger', detect: 'warning', off: 'secondary' }
  return <CBadge color={map[mode] ?? 'secondary'}>{mode}</CBadge>
}
