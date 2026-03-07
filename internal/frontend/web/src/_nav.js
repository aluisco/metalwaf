import {
  cilSpeedometer, cilGlobeAlt, cilShieldAlt, cilBan,
  cilFile, cilChartLine, cilPeople, cilSettings,
} from '@coreui/icons'

const _nav = [
  { component: 'CNavItem', name: 'Dashboard',   to: '/dashboard',    icon: cilSpeedometer },
  { component: 'CNavTitle', name: 'Proxy' },
  { component: 'CNavItem', name: 'Sites',        to: '/sites',        icon: cilGlobeAlt    },
  { component: 'CNavItem', name: 'WAF Rules',    to: '/rules',        icon: cilShieldAlt   },
  { component: 'CNavItem', name: 'IP Access',    to: '/ip-lists',     icon: cilBan         },
  { component: 'CNavItem', name: 'Certificates', to: '/certificates', icon: cilFile        },
  { component: 'CNavTitle', name: 'Monitoring' },
  { component: 'CNavItem', name: 'Analytics',    to: '/analytics',    icon: cilChartLine   },
  { component: 'CNavTitle', name: 'Administration' },
  { component: 'CNavItem', name: 'Users',        to: '/users',        icon: cilPeople      },
  { component: 'CNavItem', name: 'Settings',     to: '/settings',     icon: cilSettings    },
]

export default _nav
