import { useEffect, useState, useCallback } from 'react'
import { sites as sitesApi, rules as api } from '../api.js'
import {
  CButton, CAlert, CSpinner, CBadge,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CForm, CFormLabel, CFormInput, CFormSelect, CFormCheck, CFormTextarea,
  CRow, CCol, CNav, CNavItem, CNavLink, CTabContent, CTabPane,
  CFormSwitch,
} from '@coreui/react'
import { useDisclosure } from '../lib/use-disclosure.js'
import { notifications } from '../lib/notifications.js'
import ConfirmModal from '../components/ConfirmModal.jsx'

const FIELDS    = ['uri','query','body','ip','user_agent','method','header']
const OPERATORS = ['contains','not_contains','regex','equals','startswith','endswith','cidr']
const EMPTY = { name:'', description:'', field:'uri', operator:'contains', value:'', action:'block', score:50, enabled:true, site_id:null }

export default function WAFRules() {
  const [siteList, setSiteList]     = useState([])
  const [siteId, setSiteId]         = useState(null)
  const [list, setList]             = useState([])
  const [builtin, setBuiltin]       = useState([])
  const [categories, setCategories] = useState([])
  const [catFilter, setCatFilter]   = useState(null)
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState('')
  const [saving, setSaving]         = useState(false)
  const [current, setCurrent]       = useState(null)
  const [form, setForm]             = useState(EMPTY)
  const [opened, { open, close }]                              = useDisclosure()
  const [importOpen, { open: openImport, close: closeImport }] = useDisclosure()
  const [importText, setImportText] = useState('')
  const [importing, setImporting]   = useState(false)
  const [delTarget, setDelTarget]   = useState(null)
  const [tab, setTab]               = useState('custom')

  useEffect(() => { sitesApi.list().then(setSiteList).catch(() => {}) }, [])
  useEffect(() => {
    api.builtin().then(setBuiltin).catch(() => {})
    api.categories().then(setCategories).catch(() => {})
  }, [])

  const load = useCallback(() => {
    setLoading(true)
    api.list()
      .then(rows => setList(siteId == null ? rows.filter(r => !r.site_id) : rows.filter(r => r.site_id === siteId)))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [siteId])
  useEffect(load, [load])

  function startCreate() { setCurrent(null); setForm({...EMPTY, site_id: siteId}); open() }
  function startEdit(r) {
    setCurrent(r)
    setForm({ name: r.name, description: r.description ?? '', field: r.field, operator: r.operator, value: r.value, action: r.action, score: r.score, enabled: r.enabled, site_id: r.site_id })
    open()
  }

  async function save(e) {
    e.preventDefault(); setSaving(true)
    try {
      if (!current) await api.create(form); else await api.update(current.id, form)
      close(); load()
      notifications.show({ message: current ? 'Rule updated' : 'Rule created', color: 'teal' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setSaving(false) }
  }

  async function toggleEnabled(r) {
    try { await api.update(r.id, {...r, enabled: !r.enabled}); load() }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  async function remove(r) {
    try { await api.delete(r.id); load(); notifications.show({ message: 'Rule deleted', color: 'teal' }) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  async function doExport() {
    try {
      const data = await api.export()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = 'metalwaf-rules.json'; a.click()
      URL.revokeObjectURL(url)
    } catch (err) { notifications.show({ title: 'Export failed', message: err.message, color: 'red' }) }
  }

  async function doImport() {
    setImporting(true)
    try {
      let payload
      try { payload = JSON.parse(importText) } catch { throw new Error('Invalid JSON') }
      const result = await api.import(payload)
      closeImport(); setImportText(''); load()
      notifications.show({
        message: `Imported ${result.imported} rule(s)` + (result.failed ? `, ${result.failed} failed` : ''),
        color: result.failed > 0 ? 'orange' : 'teal',
      })
    } catch (err) { notifications.show({ title: 'Import failed', message: err.message, color: 'red' }) }
    finally { setImporting(false) }
  }

  const siteOptions = [
    { value: '__global__', label: 'Global (no site)' },
    ...siteList.map(s => ({ value: String(s.id), label: s.name })),
  ]
  const visibleBuiltin = catFilter ? builtin.filter(r => r.category === catFilter) : builtin

  if (loading && list.length === 0 && builtin.length === 0) return <div className="text-center py-5"><CSpinner color="primary" /></div>

  return (
    <>
      <h2 className="mb-4 fw-semibold">🛡 WAF Rules</h2>
      {error && <CAlert color="danger">{error}</CAlert>}

      <CNav variant="tabs" className="mb-3">
        <CNavItem><CNavLink active={tab==='custom'}  onClick={() => setTab('custom')}  style={{cursor:'pointer'}}>Custom Rules <CBadge color="secondary" className="ms-1">{list.length}</CBadge></CNavLink></CNavItem>
        <CNavItem><CNavLink active={tab==='builtin'} onClick={() => setTab('builtin')} style={{cursor:'pointer'}}>Built-in Rules <CBadge color="warning" className="ms-1">{builtin.length}</CBadge></CNavLink></CNavItem>
      </CNav>

      <CTabContent>
        {/* Custom Rules */}
        <CTabPane visible={tab === 'custom'}>
          <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <CFormSelect style={{width:200}} size="sm"
              value={siteId == null ? '__global__' : String(siteId)}
              onChange={e => setSiteId(e.target.value === '__global__' ? null : +e.target.value)}>
              {siteOptions.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </CFormSelect>
            <div className="d-flex gap-2">
              <CButton size="sm" color="secondary" variant="outline" onClick={doExport}>⬇ Export</CButton>
              <CButton size="sm" color="secondary" variant="outline" onClick={openImport}>⬆ Import</CButton>
              <CButton size="sm" color="primary" onClick={startCreate}>+ New rule</CButton>
            </div>
          </div>
          {list.length === 0 ? (
            <p className="text-body-secondary">No custom rules. Click "New rule" to create one.</p>
          ) : (
            <div className="table-responsive">
              <CTable bordered striped hover>
                <CTableHead><CTableRow>
                  <CTableHeaderCell>Name</CTableHeaderCell>
                  <CTableHeaderCell>Field</CTableHeaderCell>
                  <CTableHeaderCell>Operator</CTableHeaderCell>
                  <CTableHeaderCell>Value</CTableHeaderCell>
                  <CTableHeaderCell>Action</CTableHeaderCell>
                  <CTableHeaderCell>Score</CTableHeaderCell>
                  <CTableHeaderCell>State</CTableHeaderCell>
                  <CTableHeaderCell>Actions</CTableHeaderCell>
                </CTableRow></CTableHead>
                <CTableBody>
                  {list.map(r => (
                    <CTableRow key={r.id}>
                      <CTableDataCell>
                        <strong className="small">{r.name}</strong>
                        {r.description && <div className="text-body-secondary" style={{fontSize:11}}>{r.description}</div>}
                      </CTableDataCell>
                      <CTableDataCell><code>{r.field}</code></CTableDataCell>
                      <CTableDataCell><CBadge color="info">{r.operator}</CBadge></CTableDataCell>
                      <CTableDataCell style={{maxWidth:160,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                        <code style={{fontSize:11}}>{r.value}</code>
                      </CTableDataCell>
                      <CTableDataCell><ActionBadge action={r.action} /></CTableDataCell>
                      <CTableDataCell>{r.score}</CTableDataCell>
                      <CTableDataCell>
                        <CFormSwitch checked={r.enabled} onChange={() => toggleEnabled(r)} color="success" />
                      </CTableDataCell>
                      <CTableDataCell>
                        <div className="d-flex gap-1">
                          <CButton size="sm" color="primary" variant="ghost" onClick={() => startEdit(r)}>✏</CButton>
                          <CButton size="sm" color="danger"  variant="ghost" onClick={() => setDelTarget(r)}>🗑</CButton>
                        </div>
                      </CTableDataCell>
                    </CTableRow>
                  ))}
                </CTableBody>
              </CTable>
            </div>
          )}
        </CTabPane>

        {/* Built-in Rules */}
        <CTabPane visible={tab === 'builtin'}>
          {categories.length > 0 && (
            <div className="d-flex flex-wrap gap-2 mb-3">
              <CBadge role="button" color={!catFilter ? 'secondary' : 'light'} textColor={!catFilter ? undefined : 'dark'}
                onClick={() => setCatFilter(null)} style={{cursor:'pointer'}}>All</CBadge>
              {categories.map(c => (
                <CBadge key={c.category} role="button"
                  color={catFilter === c.category ? 'warning' : 'light'} textColor={catFilter === c.category ? undefined : 'dark'}
                  onClick={() => setCatFilter(catFilter === c.category ? null : c.category)} style={{cursor:'pointer'}}>
                  {c.category} ({c.builtin})
                </CBadge>
              ))}
            </div>
          )}
          <div className="table-responsive">
            <CTable bordered striped hover>
              <CTableHead><CTableRow>
                <CTableHeaderCell>Name</CTableHeaderCell>
                <CTableHeaderCell>Category</CTableHeaderCell>
                <CTableHeaderCell>Field</CTableHeaderCell>
                <CTableHeaderCell>Value</CTableHeaderCell>
                <CTableHeaderCell>Action</CTableHeaderCell>
                <CTableHeaderCell>Score</CTableHeaderCell>
                <CTableHeaderCell>Level</CTableHeaderCell>
              </CTableRow></CTableHead>
              <CTableBody>
                {visibleBuiltin.map(r => (
                  <CTableRow key={r.name + '_' + r.field}>
                    <CTableDataCell><span className="small fw-medium">{r.name}</span></CTableDataCell>
                    <CTableDataCell><CBadge color="warning" textColor="dark">{r.category}</CBadge></CTableDataCell>
                    <CTableDataCell><code style={{fontSize:11}}>{r.field}</code></CTableDataCell>
                    <CTableDataCell style={{maxWidth:220,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                      <code style={{fontSize:11}}>{r.value}</code>
                    </CTableDataCell>
                    <CTableDataCell><ActionBadge action={r.action} /></CTableDataCell>
                    <CTableDataCell>{r.score}</CTableDataCell>
                    <CTableDataCell>
                      <CBadge color={r.level <= 1 ? 'danger' : r.level === 2 ? 'warning' : 'secondary'}>L{r.level}</CBadge>
                    </CTableDataCell>
                  </CTableRow>
                ))}
              </CTableBody>
            </CTable>
          </div>
        </CTabPane>
      </CTabContent>

      {/* Create / Edit modal */}
      <CModal visible={opened} onClose={close} size="lg" alignment="center">
        <CModalHeader><CModalTitle>{current ? 'Edit WAF rule' : 'New WAF rule'}</CModalTitle></CModalHeader>
        <CForm onSubmit={save}>
          <CModalBody>
            <CRow className="g-3">
              <CCol md={8}>
                <CFormLabel>Name *</CFormLabel>
                <CFormInput value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} required />
              </CCol>
              <CCol md={4}>
                <CFormLabel>Score (0–1000)</CFormLabel>
                <CFormInput type="number" min={0} max={1000} value={form.score} onChange={e => setForm(f => ({...f, score: +e.target.value}))} />
              </CCol>
              <CCol xs={12}>
                <CFormLabel>Description</CFormLabel>
                <CFormInput value={form.description} onChange={e => setForm(f => ({...f, description: e.target.value}))} />
              </CCol>
              <CCol md={6}>
                <CFormLabel>Field</CFormLabel>
                <CFormSelect value={form.field} onChange={e => setForm(f => ({...f, field: e.target.value}))}>
                  {FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                </CFormSelect>
              </CCol>
              <CCol md={6}>
                <CFormLabel>Operator</CFormLabel>
                <CFormSelect value={form.operator} onChange={e => setForm(f => ({...f, operator: e.target.value}))}>
                  {OPERATORS.map(o => <option key={o} value={o}>{o}</option>)}
                </CFormSelect>
              </CCol>
              <CCol xs={12}>
                <CFormLabel>Value *</CFormLabel>
                <CFormInput value={form.value} onChange={e => setForm(f => ({...f, value: e.target.value}))} required
                  placeholder="Regex, string, or CIDR (e.g. 192.168.0.0/16)" />
              </CCol>
              <CCol md={6}>
                <CFormLabel>Action</CFormLabel>
                <CFormSelect value={form.action} onChange={e => setForm(f => ({...f, action: e.target.value}))}>
                  <option value="block">Block</option>
                  <option value="detect">Detect</option>
                  <option value="allow">Allow</option>
                </CFormSelect>
              </CCol>
              <CCol md={6} className="d-flex align-items-end pb-1">
                <CFormCheck label="Enabled" checked={form.enabled} onChange={e => setForm(f => ({...f, enabled: e.target.checked}))} />
              </CCol>
            </CRow>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" onClick={close}>Cancel</CButton>
            <CButton type="submit" color="primary" disabled={saving}>{saving ? 'Saving…' : 'Save rule'}</CButton>
          </CModalFooter>
        </CForm>
      </CModal>

      {/* Import modal */}
      <CModal visible={importOpen} onClose={closeImport} alignment="center">
        <CModalHeader><CModalTitle>Import rules (JSON)</CModalTitle></CModalHeader>
        <CModalBody>
          <CFormTextarea rows={10} style={{fontFamily:'monospace',fontSize:12}} placeholder='[{"name":"..."}]'
            value={importText} onChange={e => setImportText(e.target.value)} />
        </CModalBody>
        <CModalFooter>
          <CButton color="secondary" variant="outline" onClick={closeImport}>Cancel</CButton>
          <CButton color="primary" disabled={importing} onClick={doImport}>{importing ? 'Importing…' : 'Import'}</CButton>
        </CModalFooter>
      </CModal>

      <ConfirmModal opened={!!delTarget} onClose={() => setDelTarget(null)} onConfirm={() => remove(delTarget)}
        title="Delete WAF rule" message={`Delete rule "${delTarget?.name}"?`} />
    </>
  )
}

function ActionBadge({ action }) {
  const map = { block: 'danger', detect: 'warning', allow: 'success' }
  return <CBadge color={map[action] ?? 'secondary'}>{action}</CBadge>
}
