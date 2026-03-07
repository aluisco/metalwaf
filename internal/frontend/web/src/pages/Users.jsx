import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { users as api } from '../api.js'
import {
  CButton, CAlert, CSpinner, CBadge,
  CTable, CTableHead, CTableBody, CTableRow, CTableHeaderCell, CTableDataCell,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
  CForm, CFormLabel, CFormInput, CFormSelect,
  CTooltip,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilPencil, cilTrash, cilShieldAlt, cilPlus } from '@coreui/icons'
import { useDisclosure } from '../lib/use-disclosure.js'
import { notifications } from '../lib/notifications.js'
import ConfirmModal from '../components/ConfirmModal.jsx'

const EMPTY = { username: '', email: '', password: '', role: 'viewer' }

function initials(u) { return u.slice(0, 2).toUpperCase() }

export default function Users() {
  const navigate = useNavigate()
  const [list, setList]           = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [saving, setSaving]       = useState(false)
  const [form, setForm]           = useState(EMPTY)
  const [opened, { open, close }] = useDisclosure()
  const [delTarget, setDelTarget] = useState(null)

  const load = () => {
    setLoading(true)
    api.list().then(setList).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  function startCreate() { setForm(EMPTY); open() }

  async function save(e) {
    e.preventDefault(); setSaving(true)
    try {
      await api.create({ username: form.username, email: form.email, role: form.role, password: form.password })
      close(); load()
      notifications.show({ message: 'User created', color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setSaving(false) }
  }

  async function doDelete() {
    try {
      await api.delete(delTarget.id); load()
      notifications.show({ message: `User "${delTarget.username}" deleted`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  async function revokeSessions(u) {
    try {
      await api.revokeSessions(u.id)
      notifications.show({ message: `Sessions revoked for "${u.username}"`, color: 'teal' })
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    }
  }

  if (loading) return <div className="text-center py-5"><CSpinner color="primary" /></div>

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="mb-0 fw-semibold">Users</h2>
        <CButton color="primary" onClick={startCreate}>
          <CIcon icon={cilPlus} className="me-1" /> New user
        </CButton>
      </div>

      {error && <CAlert color="danger">{error}</CAlert>}

      {list.length === 0 ? (
        <p className="text-body-secondary">No users found.</p>
      ) : (
        <CTable bordered striped hover responsive>
          <CTableHead>
            <CTableRow>
              <CTableHeaderCell>User</CTableHeaderCell>
              <CTableHeaderCell>Email</CTableHeaderCell>
              <CTableHeaderCell>Role</CTableHeaderCell>
              <CTableHeaderCell>2FA</CTableHeaderCell>
              <CTableHeaderCell>Created</CTableHeaderCell>
              <CTableHeaderCell style={{ width: 140 }}>Actions</CTableHeaderCell>
            </CTableRow>
          </CTableHead>
          <CTableBody>
            {list.map(u => (
              <CTableRow key={u.id}>
                <CTableDataCell>
                  <div className="d-flex align-items-center gap-2">
                    <div
                      className="rounded-circle bg-primary bg-opacity-25 d-flex align-items-center justify-content-center fw-bold"
                      style={{ width: 32, height: 32, fontSize: 12 }}
                    >
                      {initials(u.username)}
                    </div>
                    <strong>{u.username}</strong>
                  </div>
                </CTableDataCell>
                <CTableDataCell>{u.email || <span className="text-body-secondary">—</span>}</CTableDataCell>
                <CTableDataCell><RoleBadge role={u.role} /></CTableDataCell>
                <CTableDataCell>
                  <CBadge color={u.totp_enabled ? 'success' : 'secondary'}>
                    {u.totp_enabled ? '2FA on' : '2FA off'}
                  </CBadge>
                </CTableDataCell>
                <CTableDataCell>
                  <small className="text-body-secondary">
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </small>
                </CTableDataCell>
                <CTableDataCell>
                  <div className="d-flex gap-1">
                    <CTooltip content="Edit user">
                      <CButton color="primary" variant="ghost" size="sm" onClick={() => navigate(`/users/${u.id}`)}>
                        <CIcon icon={cilPencil} />
                      </CButton>
                    </CTooltip>
                    <CTooltip content="Revoke all sessions">
                      <CButton color="warning" variant="ghost" size="sm" onClick={() => revokeSessions(u)}>
                        <CIcon icon={cilShieldAlt} />
                      </CButton>
                    </CTooltip>
                    <CTooltip content="Delete user">
                      <CButton color="danger" variant="ghost" size="sm" onClick={() => setDelTarget(u)}>
                        <CIcon icon={cilTrash} />
                      </CButton>
                    </CTooltip>
                  </div>
                </CTableDataCell>
              </CTableRow>
            ))}
          </CTableBody>
        </CTable>
      )}

      {/* Create modal */}
      <CModal visible={opened} onClose={close} alignment="center">
        <CModalHeader><CModalTitle>New user</CModalTitle></CModalHeader>
        <CForm onSubmit={save}>
          <CModalBody>
            <div className="mb-3">
              <CFormLabel>Username *</CFormLabel>
              <CFormInput value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required autoFocus />
            </div>
            <div className="mb-3">
              <CFormLabel>Email</CFormLabel>
              <CFormInput type="email" placeholder="user@example.com" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
            </div>
            <div className="mb-3">
              <CFormLabel>Password *</CFormLabel>
              <CFormInput type="password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
              <div className="form-text">Minimum 12 characters</div>
            </div>
            <div className="mb-3">
              <CFormLabel>Role</CFormLabel>
              <CFormSelect value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
                <option value="viewer">Viewer</option>
                <option value="admin">Admin</option>
              </CFormSelect>
            </div>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" variant="outline" onClick={close}>Cancel</CButton>
            <CButton type="submit" color="primary" disabled={saving}>{saving ? 'Saving…' : 'Create'}</CButton>
          </CModalFooter>
        </CForm>
      </CModal>

      <ConfirmModal
        opened={!!delTarget}
        onClose={() => setDelTarget(null)}
        onConfirm={doDelete}
        title="Delete user"
        message={`Delete user "${delTarget?.username}"? This cannot be undone.`}
      />
    </>
  )
}

function RoleBadge({ role }) {
  return <CBadge color={role === 'admin' ? 'danger' : 'secondary'}>{role}</CBadge>
}
