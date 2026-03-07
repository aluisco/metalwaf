import { useEffect, useState } from 'react'
import { ipLists as api } from '../api.js'
import {
  CAlert, CSpinner, CBadge, CButton, CFormInput, CFormLabel, CFormSelect,
  CNav, CNavItem, CNavLink, CTabContent, CTabPane,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
} from '@coreui/react'
import { notifications } from '../lib/notifications.js'
import { useDisclosure } from '../lib/use-disclosure.js'

const LISTS = ['blocklist', 'allowlist']

function typeBadge(t) {
  const colors = { cidr:'primary', ip:'secondary', country:'info', asn:'warning' }
  return <CBadge color={colors[t] ?? 'secondary'}>{t}</CBadge>
}

export default function IPLists() {
  const [tab,     setTab]    = useState('blocklist')
  const [entries, setEntries] = useState({ blocklist: [], allowlist: [] })
  const [loading, setLoading] = useState({ blocklist: true, allowlist: true })
  const [error,   setError]   = useState('')
  const [form,    setForm]    = useState({ value:'', type:'ip', note:'' })
  const [saving,  setSaving]  = useState(false)
  const [addOpen, { open: openAdd, close: closeAdd }] = useDisclosure(false)

  function loadList(list) {
    setLoading(l => ({...l, [list]: true}))
    api.list(list).then(data => {
      setEntries(e => ({...e, [list]: Array.isArray(data) ? data : []}))
    }).catch(e => setError(e.message)).finally(() => setLoading(l => ({...l, [list]: false})))
  }

  useEffect(() => { LISTS.forEach(loadList) }, [])

  async function handleAdd(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await api.create({ list: tab, ...form })
      notifications.show({ message: `Entry added to ${tab}`, color: 'teal' })
      closeAdd()
      setForm({ value:'', type:'ip', note:'' })
      loadList(tab)
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(false) }
  }

  async function deleteEntry(id) {
    try {
      await api.delete(id)
      notifications.show({ message: 'Entry removed', color: 'teal' })
      loadList(tab)
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  const rows = entries[tab] ?? []
  const isLoading = loading[tab]

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="fw-semibold mb-0">IP Access Lists</h2>
        <CButton color="primary" onClick={openAdd}>Add Entry</CButton>
      </div>

      {error && <CAlert color="danger">{error}</CAlert>}

      <CNav variant="tabs" className="mb-3">
        {LISTS.map(l => (
          <CNavItem key={l}>
            <CNavLink active={tab === l} onClick={() => setTab(l)} style={{ cursor:'pointer' }}>
              {l === 'blocklist' ? 'Blocklist' : 'Allowlist'}
              {' '}
              <CBadge color={l==='blocklist'?'danger':'success'} className="ms-1">
                {entries[l].length}
              </CBadge>
            </CNavLink>
          </CNavItem>
        ))}
      </CNav>

      <CTabContent>
        <CTabPane visible>
          {isLoading ? (
            <div className="text-center py-5"><CSpinner color="primary" /></div>
          ) : (
            <CTable bordered hover responsive>
              <CTableHead>
                <CTableRow>
                  <CTableHeaderCell>Value</CTableHeaderCell>
                  <CTableHeaderCell>Type</CTableHeaderCell>
                  <CTableHeaderCell>Note</CTableHeaderCell>
                  <CTableHeaderCell>Added</CTableHeaderCell>
                  <CTableHeaderCell></CTableHeaderCell>
                </CTableRow>
              </CTableHead>
              <CTableBody>
                {rows.length === 0 ? (
                  <CTableRow>
                    <CTableDataCell colSpan={5} className="text-center text-body-secondary py-4">
                      {tab === 'blocklist' ? 'Blocklist is empty' : 'Allowlist is empty'}
                    </CTableDataCell>
                  </CTableRow>
                ) : rows.map(r => (
                  <CTableRow key={r.id}>
                    <CTableDataCell><code>{r.value}</code></CTableDataCell>
                    <CTableDataCell>{typeBadge(r.type)}</CTableDataCell>
                    <CTableDataCell><small className="text-body-secondary">{r.note ?? '—'}</small></CTableDataCell>
                    <CTableDataCell><small>{r.created_at ? new Date(r.created_at).toLocaleDateString() : '—'}</small></CTableDataCell>
                    <CTableDataCell>
                      <CButton size="sm" color="danger" variant="ghost" onClick={() => deleteEntry(r.id)}>Remove</CButton>
                    </CTableDataCell>
                  </CTableRow>
                ))}
              </CTableBody>
            </CTable>
          )}
        </CTabPane>
      </CTabContent>

      {/* Add modal */}
      <CModal visible={addOpen} onClose={closeAdd}>
        <CModalHeader>
          <CModalTitle>Add to {tab === 'blocklist' ? 'Blocklist' : 'Allowlist'}</CModalTitle>
        </CModalHeader>
        <form onSubmit={handleAdd}>
          <CModalBody>
            <div className="mb-3">
              <CFormLabel>Type</CFormLabel>
              <CFormSelect value={form.type} onChange={e => setForm(f => ({...f, type: e.target.value}))}>
                <option value="ip">IP address</option>
                <option value="cidr">CIDR range</option>
                <option value="country">Country code</option>
                <option value="asn">ASN</option>
              </CFormSelect>
            </div>
            <div className="mb-3">
              <CFormLabel>Value</CFormLabel>
              <CFormInput
                placeholder={form.type==='cidr'?'192.168.0.0/24':form.type==='country'?'US':form.type==='asn'?'AS12345':'192.168.1.1'}
                value={form.value} required
                onChange={e => setForm(f => ({...f, value: e.target.value}))} />
            </div>
            <div className="mb-3">
              <CFormLabel>Note <small className="text-body-secondary">(optional)</small></CFormLabel>
              <CFormInput placeholder="e.g. Known scanner" value={form.note}
                onChange={e => setForm(f => ({...f, note: e.target.value}))} />
            </div>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" type="button" onClick={closeAdd}>Cancel</CButton>
            <CButton color="primary" type="submit" disabled={saving}>{saving ? <CSpinner size="sm" /> : 'Add'}</CButton>
          </CModalFooter>
        </form>
      </CModal>
    </>
  )
}
