import { useState, useCallback, useEffect, useRef } from 'react'
import { Outlet } from 'react-router-dom'
import { CContainer, CToast, CToastBody, CToastClose, CToaster } from '@coreui/react'
import DefaultSidebar from './DefaultSidebar'
import DefaultHeader  from './DefaultHeader'
import { subscribeToasts } from '../lib/notifications'

export default function DefaultLayout() {
  const [sidebarShow, setSidebarShow] = useState(true)
  const [sidebarUnfoldable, setSidebarUnfoldable] = useState(false)
  const [toasts, setToasts] = useState([])
  const toastRef = useRef()

  // Subscribe to global notification events
  useEffect(() => subscribeToasts(toast => {
    setToasts(prev => [...prev, toast])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== toast.id)), 4500)
  }), [])

  const toggleSidebar = useCallback(() => setSidebarShow(v => !v), [])

  return (
    <div>
      <DefaultSidebar
        sidebarShow={sidebarShow}
        setSidebarShow={setSidebarShow}
        unfoldable={sidebarUnfoldable}
        setUnfoldable={setSidebarUnfoldable}
      />

      <div className="wrapper d-flex flex-column min-vh-100">
        <DefaultHeader
          sidebarShow={sidebarShow}
          toggleSidebar={toggleSidebar}
        />

        <div className="body flex-grow-1">
          <CContainer className="px-4" lg>
            <Outlet />
          </CContainer>
        </div>
      </div>

      {/* Toast container */}
      <CToaster ref={toastRef} placement="top-end">
        {toasts.map(t => (
          <CToast
            key={t.id}
            color={t.color}
            visible
            autohide
            delay={4000}
            className="align-items-center text-white border-0"
          >
            <div className="d-flex">
              <CToastBody>
                {t.title && <strong className="me-1">{t.title}:</strong>}
                {t.message}
              </CToastBody>
              <CToastClose className="me-2 m-auto" white />
            </div>
          </CToast>
        ))}
      </CToaster>
    </div>
  )
}
