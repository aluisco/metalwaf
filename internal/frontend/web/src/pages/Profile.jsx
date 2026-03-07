import { useEffect, useState } from 'react'
import { profile as api, auth as authApi, clearTokens, users as usersApi } from '../api.js'
import { useNavigate, useParams } from 'react-router-dom'
import {
  CAlert, CSpinner, CBadge, CButton, CCard, CCardBody,
  CForm, CFormLabel, CFormInput, CFormSelect,
  CNav, CNavItem, CNavLink, CTabContent, CTabPane,
  CModal, CModalHeader, CModalTitle, CModalBody, CModalFooter,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilArrowLeft } from '@coreui/icons'
import { QRCodeSVG } from 'qrcode.react'
import { useDisclosure } from '../lib/use-disclosure.js'
import { notifications } from '../lib/notifications.js'
import ConfirmModal from '../components/ConfirmModal.jsx'

export default function Profile() {
  const { id }   = useParams()
  const navigate = useNavigate()

  const [user, setUser]       = useState(null)
  const [isSelf, setIsSelf]   = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [tab, setTab]         = useState('account')

  // Account tab
  const [accountForm, setAccountForm]     = useState({ email: '', role: 'viewer' })
  const [accountSaving, setAccountSaving] = useState(false)

  // Password tab
  const [pwForm, setPwForm]   = useState({ current: '', newPw: '', confirm: '' })
  const [pwSaving, setPwSaving] = useState(false)
  const [pwError, setPwError] = useState('')

  // 2FA
  const [totpSetup, setTotpSetup]     = useState(null)
  const [totpCode,  setTotpCode]      = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [totpLoading, setTotpLoading] = useState(false)
  const [disable2FAOpened, { open: openDisable2FA, close: closeDisable2FA }] = useDisclosure()

  // Sessions
  const [logoutAllOpened, { open: openLogoutAll, close: closeLogoutAll }] = useDisclosure()

  const load = () => {
    setLoading(true)
    api.get()
      .then(me => {
        const self = me.id === id
        setIsSelf(self)
        if (self) {
          setUser(me)
          setAccountForm({ email: me.email ?? '', role: me.role })
          setLoading(false)
        } else {
          usersApi.get(id)
            .then(u => { setUser(u); setAccountForm({ email: u.email ?? '', role: u.role }); setLoading(false) })
            .catch(e => { setError(e.message); setLoading(false) })
        }
      })
      .catch(e => { setError(e.message); setLoading(false) })
  }
  useEffect(load, [id])

  async function saveAccount(e) {
    e.preventDefault(); setAccountSaving(true)
    try {
      if (isSelf) await api.update({ email: accountForm.email })
      else        await usersApi.update(id, { email: accountForm.email, role: accountForm.role })
      notifications.show({ message: 'Profile updated', color: 'teal' })
      load()
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setAccountSaving(false) }
  }

  async function savePassword(e) {
    e.preventDefault(); setPwError('')
    if (pwForm.newPw !== pwForm.confirm) { setPwError('Passwords do not match'); return }
    if (pwForm.newPw.length < 12)        { setPwError('Minimum 12 characters'); return }
    if (isSelf && !pwForm.current)       { setPwError('Current password is required'); return }
    setPwSaving(true)
    try {
      if (isSelf) {
        await api.changePassword(pwForm.current, pwForm.newPw)
        notifications.show({ message: 'Password changed — please sign in again', color: 'teal' })
        clearTokens(); navigate('/login')
      } else {
        await usersApi.update(id, { password: pwForm.newPw })
        setPwForm({ current: '', newPw: '', confirm: '' })
        notifications.show({ message: 'Password reset', color: 'orange' })
      }
    } catch (err) { setPwError(err.message) }
    finally { setPwSaving(false) }
  }

  async function startTOTPSetup() {
    setTotpLoading(true); setTotpCode('')
    try { setTotpSetup(await api.setupTOTP()) }
    catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setTotpLoading(false) }
  }

  async function verifyTOTP(e) {
    e.preventDefault(); setTotpLoading(true)
    try {
      await api.verifyTOTP(totpCode)
      setTotpSetup(null); setTotpCode('')
      notifications.show({ message: '2FA enabled', color: 'teal' })
      load()
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setTotpLoading(false) }
  }

  async function doDisable2FA() {
    setTotpLoading(true)
    try {
      await api.disableTOTP(disableCode)
      setDisableCode(''); closeDisable2FA()
      notifications.show({ message: '2FA disabled', color: 'orange' })
      load()
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
    finally { setTotpLoading(false) }
  }

  async function doLogoutAll() {
    try { await authApi.logoutAll() } catch (_) {}
    clearTokens(); navigate('/login')
  }

  async function doRevokeSessions() {
    try {
      await usersApi.revokeSessions(id)
      notifications.show({ message: 'All sessions revoked', color: 'orange' })
    } catch (err) { notifications.show({ title: 'Error', message: err.message, color: 'red' }) }
  }

  if (loading) return <div className="text-center py-5"><CSpinner color="primary" /></div>
  if (error)   return <CAlert color="danger">{error}</CAlert>

  const initials = user?.username?.slice(0, 2).toUpperCase()

  return (
    <>
      <div className="d-flex align-items-center gap-2 mb-4">
        {!isSelf && (
          <CButton color="secondary" variant="ghost" size="sm" onClick={() => navigate('/users')}>
            <CIcon icon={cilArrowLeft} className="me-1" /> Back
          </CButton>
        )}
        <h2 className="mb-0 fw-semibold">{isSelf ? 'My Profile' : `User: ${user?.username}`}</h2>
      </div>

      {/* Info card */}
      <CCard className="mb-4">
        <CCardBody>
          <div className="d-flex align-items-center gap-3">
            <div className="rounded-circle bg-primary bg-opacity-25 d-flex align-items-center justify-content-center fw-bold fs-4"
              style={{ width: 72, height: 72 }}>
              {initials}
            </div>
            <div>
              <div className="fw-bold fs-5">{user?.username}</div>
              <div className="text-body-secondary small">{user?.email || 'No email set'}</div>
              <div className="d-flex gap-2 mt-2">
                <CBadge color={user?.role === 'admin' ? 'danger' : 'secondary'}>{user?.role}</CBadge>
                <CBadge color={user?.totp_enabled ? 'success' : 'secondary'}>
                  {user?.totp_enabled ? '🔐 2FA on' : '2FA off'}
                </CBadge>
              </div>
            </div>
          </div>
        </CCardBody>
      </CCard>

      {/* Tabs */}
      <CNav variant="tabs" className="mb-3">
        {['account','password','twofa','sessions'].map(t => (
          <CNavItem key={t}>
            <CNavLink active={tab === t} onClick={() => setTab(t)} style={{ cursor: 'pointer' }}>
              {{ account: 'Account', password: 'Password', twofa: 'Two-Factor Auth', sessions: 'Sessions' }[t]}
            </CNavLink>
          </CNavItem>
        ))}
      </CNav>

      <CTabContent>
        {/* Account */}
        <CTabPane visible={tab === 'account'}>
          <CCard style={{ maxWidth: 480 }}>
            <CCardBody>
              <CForm onSubmit={saveAccount}>
                <div className="mb-3">
                  <CFormLabel>Username</CFormLabel>
                  <CFormInput value={user?.username ?? ''} disabled />
                  <div className="form-text">Username cannot be changed</div>
                </div>
                <div className="mb-3">
                  <CFormLabel>Email</CFormLabel>
                  <CFormInput type="email" placeholder="user@example.com" value={accountForm.email}
                    onChange={e => setAccountForm(f => ({ ...f, email: e.target.value }))} />
                </div>
                {!isSelf && (
                  <div className="mb-3">
                    <CFormLabel>Role</CFormLabel>
                    <CFormSelect value={accountForm.role} onChange={e => setAccountForm(f => ({ ...f, role: e.target.value }))}>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </CFormSelect>
                  </div>
                )}
                <div className="d-flex justify-content-end">
                  <CButton type="submit" color="primary" disabled={accountSaving}>
                    {accountSaving ? 'Saving…' : 'Save changes'}
                  </CButton>
                </div>
              </CForm>
            </CCardBody>
          </CCard>
        </CTabPane>

        {/* Password */}
        <CTabPane visible={tab === 'password'}>
          <CCard style={{ maxWidth: 480 }}>
            <CCardBody>
              {!isSelf && (
                <CAlert color="info" className="small">As an admin you can force a new password. The user's sessions will be revoked.</CAlert>
              )}
              <CForm onSubmit={savePassword}>
                {isSelf && (
                  <div className="mb-3">
                    <CFormLabel>Current password *</CFormLabel>
                    <CFormInput type="password" value={pwForm.current} onChange={e => setPwForm(f => ({ ...f, current: e.target.value }))} required />
                  </div>
                )}
                <div className="mb-3">
                  <CFormLabel>New password *</CFormLabel>
                  <CFormInput type="password" value={pwForm.newPw} onChange={e => setPwForm(f => ({ ...f, newPw: e.target.value }))} required />
                  <div className="form-text">Minimum 12 characters</div>
                </div>
                <div className="mb-3">
                  <CFormLabel>Confirm new password *</CFormLabel>
                  <CFormInput type="password" value={pwForm.confirm} onChange={e => setPwForm(f => ({ ...f, confirm: e.target.value }))} required />
                </div>
                {pwError && <CAlert color="danger">{pwError}</CAlert>}
                <div className="d-flex justify-content-end">
                  <CButton type="submit" color={isSelf ? 'primary' : 'warning'} disabled={pwSaving}>
                    {pwSaving ? 'Saving…' : isSelf ? 'Update password' : 'Force reset'}
                  </CButton>
                </div>
              </CForm>
            </CCardBody>
          </CCard>
        </CTabPane>

        {/* 2FA */}
        <CTabPane visible={tab === 'twofa'}>
          <CCard style={{ maxWidth: 520 }}>
            <CCardBody>
              {!isSelf ? (
                <div className="d-flex align-items-center gap-3">
                  <span className="fs-3">{user?.totp_enabled ? '🔐' : '🔓'}</span>
                  <div>
                    <strong>Two-factor authentication is {user?.totp_enabled ? 'enabled' : 'not enabled'}</strong>
                    <p className="text-body-secondary small mb-0">Only the user can enable or disable 2FA from their own profile.</p>
                  </div>
                </div>
              ) : user?.totp_enabled ? (
                <div>
                  <div className="d-flex align-items-center gap-3 mb-3">
                    <span className="fs-3">🔐</span>
                    <div>
                      <strong>Two-factor authentication is active</strong>
                      <p className="text-body-secondary small mb-0">Your account is protected with a TOTP authenticator app.</p>
                    </div>
                  </div>
                  <hr />
                  <p className="small text-body-secondary">Enter a code from your authenticator app to disable 2FA.</p>
                  <CForm onSubmit={e => { e.preventDefault(); openDisable2FA() }}>
                    <div className="d-flex gap-2 align-items-end">
                      <div className="flex-fill">
                        <CFormLabel>TOTP code</CFormLabel>
                        <CFormInput placeholder="123456" maxLength={6} value={disableCode} onChange={e => setDisableCode(e.target.value)} />
                      </div>
                      <CButton type="submit" color="danger" variant="outline">Disable 2FA</CButton>
                    </div>
                  </CForm>
                  <ConfirmModal opened={disable2FAOpened} onClose={closeDisable2FA} onConfirm={doDisable2FA}
                    title="Disable 2FA" message="Are you sure? Your account will be less secure." confirmLabel="Disable" />
                </div>
              ) : totpSetup ? (
                <div>
                  <div className="d-flex align-items-center gap-3 mb-3">
                    <span className="fs-3">📱</span>
                    <div>
                      <strong>Scan with your authenticator app</strong>
                      <p className="text-body-secondary small mb-0">Use Google Authenticator, Authy, or any TOTP app.</p>
                    </div>
                  </div>
                  <div className="d-flex justify-content-center py-3">
                    <div style={{ background: '#fff', padding: 12, borderRadius: 8, lineHeight: 0 }}>
                      <QRCodeSVG value={totpSetup.uri} size={180} />
                    </div>
                  </div>
                  <p className="small text-body-secondary text-center">Can&apos;t scan? Manual secret:</p>
                  <pre className="text-center bg-body-tertiary p-2 rounded small" style={{ letterSpacing: 2, userSelect: 'all' }}>
                    {totpSetup.secret}
                  </pre>
                  <hr />
                  <CForm onSubmit={verifyTOTP}>
                    <div className="mb-3">
                      <CFormLabel>6-digit code</CFormLabel>
                      <CFormInput placeholder="123456" maxLength={6} autoFocus value={totpCode} onChange={e => setTotpCode(e.target.value)} />
                    </div>
                    <div className="d-flex justify-content-end gap-2">
                      <CButton color="secondary" variant="outline" onClick={() => setTotpSetup(null)}>Cancel</CButton>
                      <CButton type="submit" color="success" disabled={totpLoading}>{totpLoading ? 'Verifying…' : 'Verify & enable 2FA'}</CButton>
                    </div>
                  </CForm>
                </div>
              ) : (
                <div>
                  <div className="d-flex align-items-center gap-3 mb-3">
                    <span className="fs-3">🔓</span>
                    <div>
                      <strong>Two-factor authentication is not enabled</strong>
                      <p className="text-body-secondary small mb-0">Add extra security with a TOTP authenticator app.</p>
                    </div>
                  </div>
                  <div className="row g-2 mb-3">
                    {['1. Click Set up 2FA','2. Scan QR code','3. Enter code to verify'].map(step => (
                      <div key={step} className="col-4">
                        <div className="border rounded p-2 text-center small text-body-secondary">{step}</div>
                      </div>
                    ))}
                  </div>
                  <CButton color="primary" onClick={startTOTPSetup} disabled={totpLoading}>
                    {totpLoading ? 'Setting up…' : 'Set up 2FA'}
                  </CButton>
                </div>
              )}
            </CCardBody>
          </CCard>
        </CTabPane>

        {/* Sessions */}
        <CTabPane visible={tab === 'sessions'}>
          <CCard style={{ maxWidth: 480 }}>
            <CCardBody>
              <div className="d-flex align-items-center gap-3 mb-3">
                <span className="fs-3">🔑</span>
                <div>
                  <strong>{isSelf ? 'Active sessions' : 'Revoke all sessions'}</strong>
                  <p className="text-body-secondary small mb-0">
                    {isSelf
                      ? 'Sign out of all devices. You will be redirected to login.'
                      : 'Force this user to sign in again on all devices.'}
                  </p>
                </div>
              </div>
              <hr />
              {isSelf ? (
                <CButton color="danger" variant="outline" onClick={openLogoutAll}>Sign out all devices</CButton>
              ) : (
                <CButton color="warning" variant="outline" onClick={doRevokeSessions}>Revoke all sessions</CButton>
              )}
            </CCardBody>
          </CCard>
          {isSelf && (
            <ConfirmModal
              opened={logoutAllOpened}
              onClose={closeLogoutAll}
              onConfirm={doLogoutAll}
              title="Sign out all devices"
              message="This will revoke all your active sessions. You will be redirected to login."
              confirmLabel="Sign out all"
            />
          )}
        </CTabPane>
      </CTabContent>
    </>
  )
}
