import { useEffect, useState } from 'react'
import { profile as api, auth as authApi, clearTokens } from '../api.js'
import { useNavigate } from 'react-router-dom'
import {
  Stack, Title, Group, Button, Card, Text, Badge, Divider,
  PasswordInput, TextInput, ThemeIcon, Alert, Skeleton,
  Box, Avatar, SimpleGrid, Tabs, Code
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useDisclosure } from '@mantine/hooks'
import {
  IconUser, IconLock, IconShieldCheck, IconShieldOff,
  IconDeviceFloppy, IconLogout, IconQrcode, IconKey
} from '@tabler/icons-react'
import { QRCodeSVG } from 'qrcode.react'
import ConfirmModal from '../components/ConfirmModal.jsx'

export default function Profile() {
  const [user, setUser]         = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const navigate                = useNavigate()

  const [pwForm, setPwForm]     = useState({ current: '', newPw: '', confirm: '' })
  const [pwSaving, setPwSaving] = useState(false)
  const [pwError, setPwError]   = useState('')

  // TOTP setup flow
  const [totpSetup, setTotpSetup]   = useState(null) // { secret, uri }
  const [totpCode,  setTotpCode]    = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [totpLoading, setTotpLoading] = useState(false)

  const [logoutAllOpened, { open: openLogoutAll, close: closeLogoutAll }] = useDisclosure()
  const [disable2FAOpened, { open: openDisable2FA, close: closeDisable2FA }] = useDisclosure()

  const load = () => {
    setLoading(true)
    api.get().then(setUser).catch(e => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(load, [])

  // ── Change password ──────────────────────────────────────────────────────
  async function changePassword(e) {
    e.preventDefault()
    setPwError('')
    if (pwForm.newPw !== pwForm.confirm) { setPwError('New passwords do not match'); return }
    if (pwForm.newPw.length < 12)        { setPwError('New password must be at least 12 characters'); return }
    setPwSaving(true)
    try {
      await api.changePassword(pwForm.current, pwForm.newPw)
      setPwForm({ current: '', newPw: '', confirm: '' })
      notifications.show({ message: 'Password changed — please sign in again', color: 'teal' })
      // Sessions were revoked server-side; redirect to login
      clearTokens()
      navigate('/login')
    } catch (err) {
      setPwError(err.message)
    } finally { setPwSaving(false) }
  }

  // ── 2FA setup ────────────────────────────────────────────────────────────
  async function startTOTPSetup() {
    setTotpLoading(true)
    setTotpCode('')
    try {
      const data = await api.setupTOTP()
      setTotpSetup(data) // { secret, uri }
    } catch (err) {
      notifications.show({ title: 'Error', message: err.message, color: 'red' })
    } finally { setTotpLoading(false) }
  }

  async function verifyTOTP(e) {
    e.preventDefault()
    setTotpLoading(true)
    try {
      await api.verifyTOTP(totpCode)
      setTotpSetup(null); setTotpCode('')
      notifications.show({ message: '2FA enabled successfully', color: 'teal' })
      load()
    } catch (err) {
      notifications.show({ title: '2FA error', message: err.message, color: 'red' })
    } finally { setTotpLoading(false) }
  }

  async function doDisable2FA() {
    setTotpLoading(true)
    try {
      await api.disableTOTP(disableCode)
      setDisableCode(''); closeDisable2FA()
      notifications.show({ message: '2FA disabled', color: 'orange' })
      load()
    } catch (err) {
      notifications.show({ title: '2FA error', message: err.message, color: 'red' })
    } finally { setTotpLoading(false) }
  }

  async function doLogoutAll() {
    try {
      await authApi.logoutAll()
    } catch (_) {}
    clearTokens()
    navigate('/login')
  }

  if (loading) return (
    <Stack>
      <Skeleton h={32} w={200} />
      <Skeleton h={120} />
      <Skeleton h={220} />
    </Stack>
  )
  if (error) return <Alert color="red">{error}</Alert>

  const avatarLetter = user?.username?.slice(0, 2).toUpperCase()

  return (
    <Stack gap="lg">
      <Group gap="xs">
        <ThemeIcon size={32} variant="light" color="teal" radius="md">
          <IconUser size={18} />
        </ThemeIcon>
        <Title order={2}>My Profile</Title>
      </Group>

      {/* Profile card */}
      <Card withBorder radius="md" padding="lg">
        <Group gap="lg" align="flex-start" wrap="nowrap">
          <Avatar size={72} radius="xl" color="teal" variant="gradient"
            gradient={{ from: 'teal', to: 'cyan', deg: 135 }}>
            {avatarLetter}
          </Avatar>
          <Box>
            <Text fw={800} size="xl">{user?.username}</Text>
            <Text c="dimmed" size="sm" mt={2}>{user?.email || 'No email set'}</Text>
            <Group gap="xs" mt="sm">
              <Badge color={user?.role === 'admin' ? 'violet' : 'blue'} variant="light">
                {user?.role}
              </Badge>
              <Badge
                color={user?.totp_enabled ? 'teal' : 'gray'}
                variant={user?.totp_enabled ? 'light' : 'outline'}
                leftSection={user?.totp_enabled
                  ? <IconShieldCheck size={12} />
                  : <IconShieldOff size={12} />
                }
              >
                {user?.totp_enabled ? '2FA enabled' : '2FA disabled'}
              </Badge>
            </Group>
          </Box>
        </Group>
      </Card>

      <Tabs defaultValue="password" variant="outline" radius="md">
        <Tabs.List>
          <Tabs.Tab value="password" leftSection={<IconLock size={16} />}>
            Change Password
          </Tabs.Tab>
          <Tabs.Tab value="twofa" leftSection={<IconShieldCheck size={16} />}>
            Two-Factor Auth
          </Tabs.Tab>
          <Tabs.Tab value="sessions" leftSection={<IconKey size={16} />}>
            Sessions
          </Tabs.Tab>
        </Tabs.List>

        {/* ── Password tab ──────────────────────────────────────────── */}
        <Tabs.Panel value="password" pt="md">
          <Card withBorder radius="md" padding="lg" maw={480}>
            <Text fw={600} mb="md">Change your password</Text>
            <form onSubmit={changePassword}>
              <Stack gap="sm">
                <PasswordInput
                  label="Current password" required
                  value={pwForm.current}
                  onChange={e => setPwForm(f => ({ ...f, current: e.target.value }))}
                />
                <PasswordInput
                  label="New password" required
                  description="At least 12 characters"
                  value={pwForm.newPw}
                  onChange={e => setPwForm(f => ({ ...f, newPw: e.target.value }))}
                />
                <PasswordInput
                  label="Confirm new password" required
                  value={pwForm.confirm}
                  onChange={e => setPwForm(f => ({ ...f, confirm: e.target.value }))}
                />
                {pwError && <Alert color="red" variant="light">{pwError}</Alert>}
                <Group justify="flex-end" mt="xs">
                  <Button
                    type="submit"
                    loading={pwSaving}
                    leftSection={<IconDeviceFloppy size={15} />}
                  >
                    Update password
                  </Button>
                </Group>
              </Stack>
            </form>
          </Card>
        </Tabs.Panel>

        {/* ── 2FA tab ───────────────────────────────────────────────── */}
        <Tabs.Panel value="twofa" pt="md">
          <Card withBorder radius="md" padding="lg" maw={520}>
            {user?.totp_enabled ? (
              <Stack gap="md">
                <Group gap="sm">
                  <ThemeIcon color="teal" variant="light" size={36} radius="xl">
                    <IconShieldCheck size={20} />
                  </ThemeIcon>
                  <Box>
                    <Text fw={600}>Two-factor authentication is active</Text>
                    <Text size="xs" c="dimmed">
                      Your account is protected with a TOTP authenticator app.
                    </Text>
                  </Box>
                </Group>
                <Divider />
                <Text fw={500} size="sm">Disable 2FA</Text>
                <Text size="xs" c="dimmed">
                  Enter a code from your authenticator app to confirm. This will make your
                  account less secure.
                </Text>
                <form onSubmit={e => { e.preventDefault(); openDisable2FA() }}>
                  <Group align="flex-end" gap="sm">
                    <TextInput
                      label="TOTP code"
                      placeholder="123456"
                      maxLength={6}
                      value={disableCode}
                      onChange={e => setDisableCode(e.target.value)}
                      style={{ flex: 1 }}
                    />
                    <Button
                      type="submit"
                      color="red"
                      variant="light"
                      leftSection={<IconShieldOff size={15} />}
                    >
                      Disable 2FA
                    </Button>
                  </Group>
                </form>

                <ConfirmModal
                  opened={disable2FAOpened}
                  onClose={closeDisable2FA}
                  onConfirm={doDisable2FA}
                  title="Disable 2FA"
                  message="Are you sure you want to disable two-factor authentication? Your account will be less secure."
                  confirmLabel="Disable"
                  confirmColor="red"
                />
              </Stack>
            ) : totpSetup ? (
              <Stack gap="md">
                <Group gap="sm">
                  <ThemeIcon color="teal" variant="light" size={36} radius="xl">
                    <IconQrcode size={20} />
                  </ThemeIcon>
                  <Box>
                    <Text fw={600}>Scan QR code with your authenticator</Text>
                    <Text size="xs" c="dimmed">
                      Use Google Authenticator, Authy, or any TOTP app.
                    </Text>
                  </Box>
                </Group>

                <Group justify="center" py="sm">
                  <Box
                    p="md"
                    style={{
                      background: '#fff',
                      borderRadius: 8,
                      display: 'inline-block',
                      lineHeight: 0,
                    }}
                  >
                    <QRCodeSVG value={totpSetup.uri} size={180} />
                  </Box>
                </Group>

                <Text size="xs" c="dimmed" ta="center">
                  Can&apos;t scan? Enter this secret manually:
                </Text>
                <Code block style={{ textAlign: 'center', letterSpacing: 2, userSelect: 'all' }}>
                  {totpSetup.secret}
                </Code>

                <Divider label="Then verify" labelPosition="center" />

                <form onSubmit={verifyTOTP}>
                  <Stack gap="sm">
                    <TextInput
                      label="Enter 6-digit code from your app"
                      placeholder="123456"
                      maxLength={6}
                      value={totpCode}
                      onChange={e => setTotpCode(e.target.value)}
                      autoFocus
                    />
                    <Group justify="flex-end" gap="sm">
                      <Button variant="default" onClick={() => setTotpSetup(null)}>Cancel</Button>
                      <Button
                        type="submit"
                        loading={totpLoading}
                        leftSection={<IconShieldCheck size={15} />}
                      >
                        Verify &amp; enable 2FA
                      </Button>
                    </Group>
                  </Stack>
                </form>
              </Stack>
            ) : (
              <Stack gap="md">
                <Group gap="sm">
                  <ThemeIcon color="gray" variant="light" size={36} radius="xl">
                    <IconShieldOff size={20} />
                  </ThemeIcon>
                  <Box>
                    <Text fw={600}>Two-factor authentication is not enabled</Text>
                    <Text size="xs" c="dimmed">
                      Add an extra layer of security to your account using a TOTP authenticator.
                    </Text>
                  </Box>
                </Group>
                <SimpleGrid cols={3}>
                  {['1. Click Set up 2FA', '2. Scan QR code', '3. Enter code to verify'].map(step => (
                    <Card key={step} withBorder padding="sm" radius="sm">
                      <Text size="xs" c="dimmed">{step}</Text>
                    </Card>
                  ))}
                </SimpleGrid>
                <Button
                  onClick={startTOTPSetup}
                  loading={totpLoading}
                  leftSection={<IconShieldCheck size={15} />}
                >
                  Set up 2FA
                </Button>
              </Stack>
            )}
          </Card>
        </Tabs.Panel>

        {/* ── Sessions tab ─────────────────────────────────────────── */}
        <Tabs.Panel value="sessions" pt="md">
          <Card withBorder radius="md" padding="lg" maw={480}>
            <Stack gap="md">
              <Group gap="sm">
                <ThemeIcon color="orange" variant="light" size={36} radius="xl">
                  <IconKey size={20} />
                </ThemeIcon>
                <Box>
                  <Text fw={600}>Active sessions</Text>
                  <Text size="xs" c="dimmed">
                    Sign out of all devices at once. You will be logged out immediately.
                  </Text>
                </Box>
              </Group>
              <Divider />
              <Button
                color="red"
                variant="light"
                leftSection={<IconLogout size={15} />}
                onClick={openLogoutAll}
              >
                Sign out all devices
              </Button>
            </Stack>
          </Card>

          <ConfirmModal
            opened={logoutAllOpened}
            onClose={closeLogoutAll}
            onConfirm={doLogoutAll}
            title="Sign out all devices"
            message="This will revoke all your active sessions on every device. You will be redirected to the login page."
            confirmLabel="Sign out all"
            confirmColor="red"
          />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  )
}
