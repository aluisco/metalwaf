import { NavLink } from 'react-router-dom'
import {
  CSidebar, CSidebarBrand, CSidebarNav,
  CSidebarToggler, CSidebarHeader, CSidebarFooter,
} from '@coreui/react'
import SimpleBar from 'simplebar-react'
import AppSidebarNav from './AppSidebarNav'
import _nav from '../_nav'

export default function DefaultSidebar({ sidebarShow, setSidebarShow, unfoldable, setUnfoldable }) {
  return (
    <CSidebar
      colorScheme="dark"
      position="fixed"
      unfoldable={unfoldable}
      visible={sidebarShow}
      onVisibleChange={setSidebarShow}
    >
      <CSidebarHeader className="border-bottom border-bottom-subtle">
        <CSidebarBrand as={NavLink} to="/dashboard" className="sidebar-brand">
          <span className="brand-icon">🛡</span>
          <span>MetalWAF</span>
        </CSidebarBrand>
      </CSidebarHeader>

      <CSidebarNav>
        <SimpleBar style={{ height: '100%', minHeight: 0 }}>
          <AppSidebarNav items={_nav} />
        </SimpleBar>
      </CSidebarNav>

      <CSidebarFooter className="border-top border-top-subtle d-none d-lg-flex">
        <CSidebarToggler onClick={() => setUnfoldable(v => !v)} />
      </CSidebarFooter>
    </CSidebar>
  )
}
