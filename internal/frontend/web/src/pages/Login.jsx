import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CContainer, CCard, CCardBody, CForm, CFormInput,
  CFormLabel, CButton, CAlert, CInputGroup, CInputGroupText,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilLockLocked, cilUser, cilShieldAlt } from '@coreui/icons'
import { auth, setTokens } from '../api.js'

export default function Login() {
  const navigate = useNavigate()
  const [step, setStep]         = useState('credentials')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totp, setTotp]         = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await auth.login(username, password, step === 'totp' ? totp : undefined)
      setTokens(data)
      navigate('/dashboard')
    } catch (err) {
      if (err.status === 401 && err.message?.toLowerCase().includes('totp')) {
        setStep('totp')
      } else {
        setError(err.message ?? 'Login failed')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <CContainer>
        <div className="row justify-content-center">
          <div className="col-md-5 col-lg-4">
            <CCard className="shadow-lg border-0 p-4">
              <CCardBody>
                <div className="text-center mb-4">
                  <div className="fs-1 mb-2">🛡</div>
                  <h2 className="fw-bold">MetalWAF</h2>
                  <p className="text-body-secondary">
                    {step === 'totp' ? 'Enter your 2FA code' : 'Sign in to your account'}
                  </p>
                </div>

                {error && <CAlert color="danger">{error}</CAlert>}

                <CForm onSubmit={handleSubmit}>
                  {step === 'credentials' ? (
                    <>
                      <div className="mb-3">
                        <CFormLabel>Username</CFormLabel>
                        <CInputGroup>
                          <CInputGroupText>
                            <CIcon icon={cilUser} />
                          </CInputGroupText>
                          <CFormInput
                            placeholder="admin"
                            value={username}
                            onChange={e => setUsername(e.target.value)}
                            required autoFocus
                          />
                        </CInputGroup>
                      </div>
                      <div className="mb-4">
                        <CFormLabel>Password</CFormLabel>
                        <CInputGroup>
                          <CInputGroupText>
                            <CIcon icon={cilLockLocked} />
                          </CInputGroupText>
                          <CFormInput
                            type="password" placeholder="••••••••"
                            value={password}
                            onChange={e => setPassword(e.target.value)}
                            required
                          />
                        </CInputGroup>
                      </div>
                    </>
                  ) : (
                    <div className="mb-4">
                      <CFormLabel>TOTP Code</CFormLabel>
                      <CFormInput
                        placeholder="123456"
                        value={totp}
                        onChange={e => setTotp(e.target.value)}
                        maxLength={6} required autoFocus
                      />
                    </div>
                  )}

                  <div className={`d-flex ${step === 'totp' ? 'justify-content-between' : 'justify-content-end'}`}>
                    {step === 'totp' && (
                      <CButton color="secondary" variant="ghost" size="sm"
                        onClick={() => { setStep('credentials'); setError('') }}>
                        ← Back
                      </CButton>
                    )}
                    <CButton type="submit" color="primary" className={step === 'credentials' ? 'w-100' : ''} disabled={loading}>
                      {loading ? 'Please wait…' : step === 'totp' ? 'Verify' : 'Sign in'}
                    </CButton>
                  </div>
                </CForm>
              </CCardBody>
            </CCard>
            <p className="text-center text-body-secondary small mt-3">
              MetalWAF Admin · {new Date().getFullYear()}
            </p>
          </div>
        </div>
      </CContainer>
    </div>
  )
}
