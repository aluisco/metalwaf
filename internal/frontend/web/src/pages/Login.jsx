import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Center, Paper, Title, TextInput, PasswordInput,
  Button, Stack, Text, Alert, Group
} from '@mantine/core'
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
    <Center mih="100vh">
      <Paper shadow="md" p="xl" w={380} radius="md" withBorder>
        <Stack>
          <Stack gap={4} align="center">
            <Title order={2}>MetalWAF</Title>
            <Text c="dimmed" size="sm">
              {step === 'totp' ? 'Enter your 2FA code' : 'Sign in to your account'}
            </Text>
          </Stack>

          {error && <Alert color="red" variant="light">{error}</Alert>}

          <form onSubmit={handleSubmit}>
            <Stack gap="sm">
              {step === 'credentials' ? (
                <>
                  <TextInput
                    label="Username" placeholder="admin"
                    value={username} onChange={e => setUsername(e.target.value)}
                    required autoFocus
                  />
                  <PasswordInput
                    label="Password" placeholder="••••••••"
                    value={password} onChange={e => setPassword(e.target.value)}
                    required
                  />
                </>
              ) : (
                <TextInput
                  label="TOTP Code" placeholder="123456"
                  value={totp} onChange={e => setTotp(e.target.value)}
                  maxLength={6} required autoFocus
                />
              )}

              <Group mt="xs" justify={step === 'totp' ? 'space-between' : 'flex-end'}>
                {step === 'totp' && (
                  <Button variant="subtle" size="sm" onClick={() => { setStep('credentials'); setError('') }}>
                    ← Back
                  </Button>
                )}
                <Button type="submit" loading={loading} fullWidth={step === 'credentials'}>
                  {step === 'totp' ? 'Verify' : 'Sign in'}
                </Button>
              </Group>
            </Stack>
          </form>
        </Stack>
      </Paper>
    </Center>
  )
}
