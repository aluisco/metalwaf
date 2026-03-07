import { NavLink } from 'react-router-dom'
import { CNavItem, CNavTitle, CNavLink } from '@coreui/react'
import CIcon from '@coreui/icons-react'

export default function AppSidebarNav({ items }) {
  return (
    <>
      {items.map((item, idx) => {
        if (item.component === 'CNavTitle') {
          return <CNavTitle key={idx}>{item.name}</CNavTitle>
        }

        const iconEl = item.icon
          ? <CIcon icon={item.icon} customClassName="nav-icon" />
          : null

        return (
          <CNavItem key={idx}>
            <CNavLink as={NavLink} to={item.to}>
              {iconEl}
              {item.name}
            </CNavLink>
          </CNavItem>
        )
      })}
    </>
  )
}
