import { NavLink } from 'react-router-dom'
import {
  CSidebar, CSidebarBrand, CSidebarHeader,
  CSidebarFooter, CSidebarToggler, CCloseButton,
} from '@coreui/react'
import AppSidebarNav from './AppSidebarNav'
import _nav from '../_nav'

export default function DefaultSidebar({ sidebarShow, setSidebarShow, unfoldable, setUnfoldable }) {
  return (
    <CSidebar
      className="border-end"
      colorScheme="dark"
      position="fixed"
      unfoldable={unfoldable}
      visible={sidebarShow}
      onVisibleChange={(v) => !unfoldable && setSidebarShow(v)}
    >
      <CSidebarHeader className="border-bottom border-bottom-subtle">
        <CSidebarBrand as={NavLink} to="/dashboard" className="sidebar-brand w-100 d-flex flex-column align-items-center justify-content-center py-2 text-center" style={{ textDecoration: 'none' }}>
          <span style={{ fontSize: '2rem', lineHeight: 1 }}>🛡</span>
          <span style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '0.05em' }}>MetalWAF</span>
        </CSidebarBrand>
        <CCloseButton className="d-lg-none" dark onClick={() => setSidebarShow(false)} />
      </CSidebarHeader>

      <AppSidebarNav items={_nav} />

      <CSidebarFooter className="border-top d-none d-lg-flex">
        <CSidebarToggler onClick={() => setUnfoldable(v => !v)} />
      </CSidebarFooter>
    </CSidebar>
  )
}
