import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  AppShell, Burger, Group, NavLink as MantineNavLink,
  Text, Badge, ActionIcon, Tooltip, Stack, Box, Divider,
  Avatar, Menu, useMantineColorScheme, UnstyledButton
} from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { clearTokens, auth, profile as profileApi } from '../api.js'
import {
  IconLayoutDashboard, IconWorldWww, IconShieldBolt, IconCertificate,
  IconChartBar, IconSettings, IconSun, IconMoon, IconPower, IconShield,
  IconUsers, IconUser, IconChevronDown, IconLogout, IconKey, IconShieldLock
} from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import ConfirmModal from './ConfirmModal.jsx'

const NAV = [
  { path: '/dashboard',    label: 'Dashboard',    icon: IconLayoutDashboard },
  { path: '/sites',        label: 'Sites',         icon: IconWorldWww },
  { path: '/rules',        label: 'WAF Rules',     icon: IconShieldBolt },
  { path: '/ip-lists',     label: 'IP Access',     icon: IconShieldLock },
  { path: '/certificates', label: 'Certificates',  icon: IconCertificate },
  { path: '/analytics',    label: 'Analytics',     icon: IconChartBar },
  { path: '/users',        label: 'Users',         icon: IconUsers },
  { path: '/settings',     label: 'Settings',      icon: IconSettings },
]

export default function Layout() {
  const [opened, { toggle }] = useDisclosure()
  const { colorScheme, toggleColorScheme } = useMantineColorScheme()
  const navigate = useNavigate()
  const [me, setMe] = useState(null)
  const [logoutOpened, { open: openLogout, close: closeLogout }] = useDisclosure()

  useEffect(() => {
    profileApi.get().then(setMe).catch(() => {})
  }, [])

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
            <Group gap="xs" align="center">
              <IconShield size={20} stroke={2} color="var(--mantine-color-teal-6)" />
              <Text fw={800} size="lg" style={{ letterSpacing: '-0.5px' }}>MetalWAF</Text>
              <Badge size="xs" variant="light" color="teal">ADMIN</Badge>
            </Group>
          </Group>
          <Group gap={4}>
            <Tooltip label={colorScheme === 'dark' ? 'Light mode' : 'Dark mode'}>
              <ActionIcon variant="subtle" onClick={toggleColorScheme} size="lg" aria-label="Toggle theme">
                {colorScheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
              </ActionIcon>
            </Tooltip>

            {/* User avatar menu */}
            <Menu shadow="md" width={200} position="bottom-end">
              <Menu.Target>
                <UnstyledButton
                  px={8} py={5}
                  style={{
                    borderRadius: 'var(--mantine-radius-md)',
                    transition: 'background 120ms',
                  }}
                  styles={{ root: { '&:hover': { background: 'var(--mantine-color-default-hover)' } } }}
                >
                  <Group gap={6} wrap="nowrap" align="center">
                    <Avatar size={32} radius="xl" color="teal" variant="light">
                      {me?.username?.slice(0, 2).toUpperCase() ?? '?'}
                    </Avatar>
                    <Box visibleFrom="sm">
                      <Text size="sm" fw={600} lh={1.2}>{me?.username ?? '…'}</Text>
                      <Text size="xs" c="dimmed" lh={1.2} tt="capitalize">{me?.role ?? ''}</Text>
                    </Box>
                    <IconChevronDown size={14} />
                  </Group>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Label>
                  <Text size="xs" fw={700}>{me?.username ?? '…'}</Text>
                  <Badge size="xs" color={me?.role === 'admin' ? 'violet' : 'blue'} variant="light">{me?.role}</Badge>
                </Menu.Label>
                <Menu.Divider />
                <Menu.Item
                  leftSection={<IconUser size={15} />}
                  onClick={() => navigate('/profile')}
                >
                  My profile
                </Menu.Item>
                <Menu.Item
                  leftSection={<IconKey size={15} />}
                  onClick={() => navigate('/profile')}
                >
                  Change password
                </Menu.Item>
                <Menu.Divider />
                <Menu.Item
                  leftSection={<IconLogout size={15} />}
                  color="red"
                  onClick={openLogout}
                >
                  Sign out
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs" style={{ display: 'flex', flexDirection: 'column' }}>
        <Stack gap={2} style={{ flex: 1 }}>
          {NAV.map(item => (
            <MantineNavLink
              key={item.path}
              component={NavLink}
              to={item.path}
              label={item.label}
              leftSection={<item.icon size={17} stroke={1.6} />}
            />
          ))}
        </Stack>
        <Box px="xs" pb="xs">
          <Divider mb="xs" />
          <Group gap="xs">
            <Box w={8} h={8} style={{ borderRadius: '50%', background: 'var(--mantine-color-teal-6)', flexShrink: 0 }} />
            <Text size="xs" c="dimmed">v0.1.0 · running</Text>
          </Group>
        </Box>
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>

      <ConfirmModal
        opened={logoutOpened}
        onClose={closeLogout}
        onConfirm={handleLogout}
        title="Sign out"
        message="Are you sure you want to sign out of MetalWAF?"
        confirmLabel="Sign out"
        confirmColor="red"
      />
    </AppShell>
  )
}

