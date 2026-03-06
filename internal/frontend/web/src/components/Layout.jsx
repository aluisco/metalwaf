import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  AppShell, Burger, Group, NavLink as MantineNavLink,
  Text, Badge, ActionIcon, Tooltip, Stack,
  useMantineColorScheme
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { clearTokens, auth } from '../api.js'

const NAV = [
  { path: '/dashboard',    label: 'Dashboard',   icon: '◈' },
  { path: '/sites',        label: 'Sites',        icon: '⊞' },
  { path: '/rules',        label: 'WAF Rules',    icon: '⛨' },
  { path: '/certificates', label: 'Certificates', icon: '⊕' },
  { path: '/analytics',    label: 'Analytics',    icon: '△' },
  { path: '/settings',     label: 'Settings',     icon: '⚙' },
]

export default function Layout() {
  const [opened, { toggle }] = useDisclosure()
  const { colorScheme, toggleColorScheme } = useMantineColorScheme()
  const navigate = useNavigate()

  async function handleLogout() {
    try { await auth.logout() } catch (_) {}
    clearTokens()
    navigate('/login')
  }

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Group gap="xs">
              <Text fw={700} size="lg" style={{ letterSpacing: '-0.5px' }}>MetalWAF</Text>
              <Badge size="xs" variant="light" color="teal">LITE</Badge>
            </Group>
          </Group>
          <Group gap={4}>
            <Tooltip label={colorScheme === 'dark' ? 'Light mode' : 'Dark mode'}>
              <ActionIcon variant="subtle" onClick={toggleColorScheme} size="lg" aria-label="Toggle theme">
                {colorScheme === 'dark' ? '☀' : '☾'}
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Sign out">
              <ActionIcon variant="subtle" color="red" onClick={handleLogout} size="lg" aria-label="Logout">
                ⏻
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <Stack gap={2}>
          {NAV.map(item => (
            <MantineNavLink
              key={item.path}
              component={NavLink}
              to={item.path}
              label={item.label}
              leftSection={<span style={{ fontSize: 13 }}>{item.icon}</span>}
            />
          ))}
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  )
}

