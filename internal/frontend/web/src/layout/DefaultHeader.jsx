import { useEffect, useRef, useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  CHeader, CHeaderNav, CHeaderToggler, CContainer,
  CDropdown, CDropdownToggle, CDropdownMenu, CDropdownItem, CDropdownDivider,
  CAvatar, CBadge, CBreadcrumb, CBreadcrumbItem,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilMenu, cilUser, cilAccountLogout } from '@coreui/icons'
import { profile as profileApi, auth as authApi, clearTokens } from '../api.js'

// Map route paths to readable breadcrumb names
const ROUTE_NAMES = {
  dashboard: 'Dashboard',
  users: 'Users',
  sites: 'Sites',
  rules: 'WAF Rules',
  'ip-lists': 'IP Access',
  certificates: 'Certificates',
  analytics: 'Analytics',
  settings: 'Settings',
}

function useBreadcrumbs() {
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  return parts.map((p, i) => ({
    label: ROUTE_NAMES[p] ?? (p.match(/^\d+$/) ? 'Profile' : p),
    path: '/' + parts.slice(0, i + 1).join('/'),
    active: i === parts.length - 1,
  }))
}

export default function DefaultHeader({ sidebarShow, toggleSidebar }) {
  const navigate = useNavigate()
  const headerRef = useRef()
  const [me, setMe] = useState(null)
  const breadcrumbs = useBreadcrumbs()

  useEffect(() => {
    profileApi.get().then(setMe).catch(() => {})
  }, [])

  // Add scroll shadow exactly like the CoreUI template
  useEffect(() => {
    const handleScroll = () => {
      headerRef.current &&
        headerRef.current.classList.toggle('shadow-sm', document.documentElement.scrollTop > 0)
    }
    document.addEventListener('scroll', handleScroll)
    return () => document.removeEventListener('scroll', handleScroll)
  }, [])

  async function handleLogout() {
    try { await authApi.logout() } catch (_) {}
    clearTokens()
    navigate('/login')
  }

  const initials = me?.username?.slice(0, 2).toUpperCase() ?? '??'

  return (
    <CHeader position="sticky" className="mb-4 p-0" ref={headerRef}>
      <CContainer fluid className="border-bottom px-4">
        <CHeaderToggler onClick={toggleSidebar} style={{ marginInlineStart: '-14px' }}>
          <CIcon icon={cilMenu} size="lg" />
        </CHeaderToggler>

        <CHeaderNav className="ms-auto">
          <CDropdown variant="nav-item">
            <CDropdownToggle caret={false} className="py-0 pe-0">
              <CAvatar color="primary" size="md" textColor="white">
                {initials}
              </CAvatar>
            </CDropdownToggle>

            <CDropdownMenu className="pt-0" placement="bottom-end">
              {me && (
                <>
                  <div className="px-3 py-2 text-muted small border-bottom">
                    <div className="fw-semibold text-body">{me.username}</div>
                    <div>{me.email}</div>
                    {me.role === 'admin' && (
                      <CBadge color="danger" className="mt-1">admin</CBadge>
                    )}
                  </div>
                </>
              )}

              <CDropdownItem onClick={() => me?.id && navigate(`/users/${me.id}`)}>
                <CIcon icon={cilUser} className="me-2" />
                My Profile
              </CDropdownItem>

              <CDropdownDivider />

              <CDropdownItem className="text-danger" onClick={handleLogout}>
                <CIcon icon={cilAccountLogout} className="me-2" />
                Sign out
              </CDropdownItem>
            </CDropdownMenu>
          </CDropdown>
        </CHeaderNav>
      </CContainer>
      <CContainer className="px-4" fluid>
        <CBreadcrumb className="my-0">
          <CBreadcrumbItem href="/dashboard">Home</CBreadcrumbItem>
          {breadcrumbs.map(b =>
            b.active
              ? <CBreadcrumbItem key={b.path} active>{b.label}</CBreadcrumbItem>
              : <CBreadcrumbItem key={b.path} href={b.path}>{b.label}</CBreadcrumbItem>
          )}
        </CBreadcrumb>
      </CContainer>
    </CHeader>
  )
}
