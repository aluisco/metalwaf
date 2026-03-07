import { useEffect, useState } from 'react'
import { settings as api } from '../api.js'
import {
  CAlert, CSpinner, CButton, CFormInput,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
} from '@coreui/react'
import { notifications } from '../lib/notifications.js'

const DESCRIPTIONS = {
  waf_block_score:       'Min threat score to block a request (0–100)',
  waf_detect_score:      'Min threat score to log (not block) a request',
  waf_paranoia_level:    'WAF paranoia level: 1=essential, 2=moderate, 3=aggressive, 4=paranoid',
  alert_block_threshold: 'Blocked requests/minute to trigger alerts (default 20)',
  rate_limit_rps:        'Burst request rate per IP (req/sec)',
  rate_limit_window:     'Window in seconds for rate-limit counting',
  log_retention_days:    'How many days access logs are kept',
  upstream_timeout:      'Timeout in seconds for upstream HTTP calls',
  health_check_interval: 'Upstream health check interval in seconds',
  acme_email:            "Contact email for Let's Encrypt account",
}

export default function Settings() {
  const [map, setMap]         = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [editing, setEditing] = useState({})
  const [saving, setSaving]   = useState({})

  const load = () => {
    setLoading(true)
    api.getAll().then(data => {
      const m = {}
      if (Array.isArray(data)) data.forEach(e => { m[e.key] = e.value })
      else Object.assign(m, data)
      setMap(m)
    }).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startEdit(key) { setEditing(e => ({...e, [key]: String(map[key] ?? '')})) }
  function cancelEdit(key) { setEditing(e => { const n={...e}; delete n[key]; return n }) }

  async function save(key) {
    setSaving(s => ({...s,[key]:true}))
    try {
      await api.set(key, editing[key])
      setMap(m => ({...m,[key]:editing[key]}))
      cancelEdit(key)
      notifications.show({ message: `${key} saved`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(s => ({...s,[key]:false})) }
  }

  if (loading) return <div className="text-center py-5"><CSpinner color="primary" /></div>
  if (error)   return <CAlert color="danger">{error}</CAlert>

  const keys = Object.keys(map).length > 0 ? Object.keys(map) : Object.keys(DESCRIPTIONS)

  return (
    <>
      <h2 className="mb-4 fw-semibold">Settings</h2>
      <CTable bordered hover responsive>
        <CTableHead>
          <CTableRow>
            <CTableHeaderCell>Key</CTableHeaderCell>
            <CTableHeaderCell>Value</CTableHeaderCell>
            <CTableHeaderCell>Description</CTableHeaderCell>
            <CTableHeaderCell style={{ width: 140 }}></CTableHeaderCell>
          </CTableRow>
        </CTableHead>
        <CTableBody>
          {keys.map(key => {
            const isEditing = key in editing
            return (
              <CTableRow key={key}>
                <CTableDataCell><code>{key}</code></CTableDataCell>
                <CTableDataCell>
                  {isEditing ? (
                    <CFormInput size="sm" value={editing[key]}
                      onChange={e => setEditing(d=>({...d,[key]:e.target.value}))}
                      onKeyDown={e => { if (e.key==='Enter') save(key); if (e.key==='Escape') cancelEdit(key) }}
                      autoFocus />
                  ) : (
                    <code>{String(map[key] ?? '')}</code>
                  )}
                </CTableDataCell>
                <CTableDataCell><small className="text-body-secondary">{DESCRIPTIONS[key] ?? ''}</small></CTableDataCell>
                <CTableDataCell>
                  {isEditing ? (
                    <div className="d-flex gap-1">
                      <CButton size="sm" color="primary" disabled={saving[key]} onClick={() => save(key)}>{saving[key] ? '…' : 'Save'}</CButton>
                      <CButton size="sm" color="secondary" variant="outline" onClick={() => cancelEdit(key)}>Cancel</CButton>
                    </div>
                  ) : (
                    <CButton size="sm" color="secondary" variant="ghost" onClick={() => startEdit(key)}>Edit</CButton>
                  )}
                </CTableDataCell>
              </CTableRow>
            )
          })}
        </CTableBody>
      </CTable>
    </>
  )
}
