import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

import { loadPolicy, auditLog, type Policy } from '../lib/agentnanny-core.ts'
import AgentNannyPlugin from '../agentnanny.ts'

function makePolicy(overrides: Partial<Policy> = {}): Policy {
  return {
    scope_id: 'abc12345',
    // Captured per call — never hoist to module scope, or TTL tests inherit a
    // stale wall clock.
    created: new Date().toISOString(),
    ttl_seconds: 0,
    allow_groups: [],
    allow_tools: [],
    deny: [],
    _global_deny: [],
    ...overrides,
  }
}

describe('loadPolicy', () => {
  let sessionDir: string
  const originalEnv = { ...process.env }

  beforeEach(() => {
    sessionDir = mkdtempSync(join(tmpdir(), 'agentnanny-test-'))
    process.env.AGENTNANNY_SESSION_DIR = sessionDir
  })

  afterEach(() => {
    process.env = { ...originalEnv }
    rmSync(sessionDir, { recursive: true, force: true })
  })

  it('returns null when scopeId is undefined', () => {
    expect(loadPolicy(undefined)).toBeNull()
  })

  it('returns null when scopeId is empty', () => {
    expect(loadPolicy('')).toBeNull()
  })

  it('returns null when session file is absent', () => {
    expect(loadPolicy('deadbeef')).toBeNull()
  })

  it('returns null when session file is empty', () => {
    writeFileSync(join(sessionDir, 'deadbeef.json'), '')
    expect(loadPolicy('deadbeef')).toBeNull()
  })

  it('returns null when session file is malformed', () => {
    writeFileSync(join(sessionDir, 'deadbeef.json'), '{not json')
    expect(loadPolicy('deadbeef')).toBeNull()
  })

  it('returns null when scope_id in file does not match env', () => {
    const policy = makePolicy({ scope_id: 'other999' })
    writeFileSync(join(sessionDir, 'deadbeef.json'), JSON.stringify(policy))
    expect(loadPolicy('deadbeef')).toBeNull()
  })

  it('returns null when required keys are missing', () => {
    writeFileSync(join(sessionDir, 'deadbeef.json'), JSON.stringify({ scope_id: 'deadbeef' }))
    expect(loadPolicy('deadbeef')).toBeNull()
  })

  it('returns the policy for a valid session file', () => {
    const policy = makePolicy({ scope_id: 'deadbeef' })
    writeFileSync(join(sessionDir, 'deadbeef.json'), JSON.stringify(policy))
    expect(loadPolicy('deadbeef')).toEqual(policy)
  })

  it('returns null for an expired session and removes the file', () => {
    const expired = new Date(Date.now() - 60_000).toISOString()
    const policy = makePolicy({ scope_id: 'deadbeef', created: expired, ttl_seconds: 30 })
    const path = join(sessionDir, 'deadbeef.json')
    writeFileSync(path, JSON.stringify(policy))
    expect(loadPolicy('deadbeef')).toBeNull()
    expect(existsSync(path)).toBe(false)
  })

  it('returns the policy when ttl_seconds is 0 (no expiry)', () => {
    const policy = makePolicy({ scope_id: 'deadbeef', ttl_seconds: 0 })
    writeFileSync(join(sessionDir, 'deadbeef.json'), JSON.stringify(policy))
    expect(loadPolicy('deadbeef')).toEqual(policy)
  })

  it('returns null for scope ids with path traversal', () => {
    expect(loadPolicy('../evil')).toBeNull()
    expect(loadPolicy('foo/bar')).toBeNull()
  })

  it('ignores AGENTNANNY_SESSION_DIR outside test runs (fail-close)', () => {
    // sessionDir() only honors the override under a test runner; production
    // always reads tmpdir()/agentnanny/sessions, matching where Python
    // `activate` writes. Write a valid policy to the override dir, then
    // simulate a production env — the plugin must NOT find it there.
    const policy = makePolicy({ scope_id: 'deadbeef' })
    writeFileSync(join(sessionDir, 'deadbeef.json'), JSON.stringify(policy))
    const saved = { BUN_TEST: process.env.BUN_TEST, VITEST: process.env.VITEST }
    delete process.env.BUN_TEST
    delete process.env.VITEST
    try {
      expect(loadPolicy('deadbeef')).toBeNull()
    } finally {
      if (saved.BUN_TEST !== undefined) process.env.BUN_TEST = saved.BUN_TEST
      if (saved.VITEST !== undefined) process.env.VITEST = saved.VITEST
    }
  })
})

// ---------------------------------------------------------------------------
// Plugin hook integration — drives `tool.execute.before` and `permission.ask`
// through the AgentNannyPlugin default export with a fabricated session file.
// ---------------------------------------------------------------------------

type HookMap = Awaited<ReturnType<typeof AgentNannyPlugin>>

describe('AgentNannyPlugin hooks', () => {
  let sessionDir: string
  let auditLogFile: string
  let hooks: HookMap
  const originalEnv = { ...process.env }

  beforeEach(async () => {
    sessionDir = mkdtempSync(join(tmpdir(), 'agentnanny-hook-test-'))
    auditLogFile = join(sessionDir, 'audit.log')
    process.env.AGENTNANNY_SESSION_DIR = sessionDir
    process.env.AGENTNANNY_LOG = auditLogFile
    delete process.env.AGENTNANNY_SCOPE
    // Plugin signature requires PluginInput but our hooks never touch it —
    // pass a stub so we can exercise the hooks directly.
    hooks = await AgentNannyPlugin({} as never)
  })

  afterEach(() => {
    process.env = { ...originalEnv }
    rmSync(sessionDir, { recursive: true, force: true })
  })

  function writeSession(policy: Policy): void {
    writeFileSync(join(sessionDir, `${policy.scope_id}.json`), JSON.stringify(policy))
    process.env.AGENTNANNY_SCOPE = policy.scope_id
  }

  describe('tool.execute.before', () => {
    it('is a no-op when AGENTNANNY_SCOPE is unset', async () => {
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).resolves.toBeUndefined()
    })

    it('is a no-op when the session file is absent', async () => {
      process.env.AGENTNANNY_SCOPE = 'deadbeef'
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).resolves.toBeUndefined()
    })

    it('throws when the op matches the session deny list', async () => {
      writeSession(makePolicy({ deny: ['Bash(rm*)'] }))
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /tmp/x' } }),
      ).rejects.toThrow(/agentnanny:.*deny/)
    })

    it('throws when the op matches the global deny snapshot', async () => {
      writeSession(makePolicy({ _global_deny: ['Bash(DROP TABLE*)'] }))
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'DROP TABLE users' } }),
      ).rejects.toThrow(/agentnanny:.*global deny/)
    })

    it('does not throw for an allow-listed op', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'read', sessionID: 's1', callID: 'c1' }, { args: { filePath: '/tmp/x' } }),
      ).resolves.toBeUndefined()
    })

    it('does not throw for an unmatched op (passthrough)', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'curl https://x' } }),
      ).resolves.toBeUndefined()
    })

    it('is a no-op when the session TTL has expired', async () => {
      const expired = new Date(Date.now() - 60_000).toISOString()
      writeSession(makePolicy({ created: expired, ttl_seconds: 30, deny: ['Bash(rm*)'] }))
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).resolves.toBeUndefined()
    })

    it('does not crash when the session file is malformed', async () => {
      process.env.AGENTNANNY_SCOPE = 'deadbeef'
      writeFileSync(join(sessionDir, 'deadbeef.json'), '{not json')
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).resolves.toBeUndefined()
    })

    it('does not crash when the session file is empty', async () => {
      process.env.AGENTNANNY_SCOPE = 'deadbeef'
      writeFileSync(join(sessionDir, 'deadbeef.json'), '')
      const hook = hooks['tool.execute.before']!
      await expect(
        hook({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).resolves.toBeUndefined()
    })
  })

  describe('permission.ask', () => {
    it('short-circuits to allow when the op was allowed in tool.execute.before', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'read', sessionID: 's1', callID: 'c1' }, { args: { filePath: '/tmp/x' } })

      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'read',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'c1',
          title: 'Read /tmp/x',
          metadata: {},
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('allow')
    })

    it('evicts the cached allow on read — a second ask for the same callID re-evaluates', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'read', sessionID: 's1', callID: 'c1' }, { args: { filePath: '/tmp/x' } })

      const ask = hooks['permission.ask']!
      const metadata = { filePath: '/tmp/x' }
      const first = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        { id: 'p1', type: 'read', sessionID: 's1', messageID: 'm1', callID: 'c1', title: 'Read /tmp/x', metadata, time: { created: Date.now() } },
        first,
      )
      expect(first.status).toBe('allow')

      // Second ask for the same callID misses the (now-evicted) cache entry and
      // lands on the fallback re-evaluation — still allow via metadata.
      const second = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        { id: 'p2', type: 'read', sessionID: 's1', messageID: 'm1', callID: 'c1', title: 'Read /tmp/x', metadata, time: { created: Date.now() } },
        second,
      )
      expect(second.status).toBe('allow')
    })

    it('does not double-log an allow served from the cache', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'read', sessionID: 's1', callID: 'c1' }, { args: { filePath: '/tmp/x' } })

      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        { id: 'p1', type: 'read', sessionID: 's1', messageID: 'm1', callID: 'c1', title: 'Read /tmp/x', metadata: {}, time: { created: Date.now() } },
        output,
      )
      expect(output.status).toBe('allow')

      const lines = readFileSync(auditLogFile, 'utf-8').trim().split('\n')
      expect(lines).toHaveLength(1)
    })

    it('denies via fallback when before-hook threw and callID was not cached', async () => {
      writeSession(makePolicy({ deny: ['Bash(rm*)'] }))
      const before = hooks['tool.execute.before']!
      // Deny throws at the before-hook — in production permission.ask never
      // fires for this call. But if it does fire (e.g. different callID),
      // the fallback re-evaluation catches it.
      await expect(
        before({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /' } }),
      ).rejects.toThrow()

      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'different-call-id',
          title: 'rm -rf /',
          metadata: { command: 'rm -rf /' },
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('deny')
    })

    it('fallback: allows via permission metadata when callID was not cached', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      // Skip tool.execute.before entirely — simulate callID mismatch.
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'read',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'unknown-call-id',
          title: 'Read /tmp/x',
          metadata: { filePath: '/tmp/x' },
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('allow')
    })

    it('fallback: denies via permission metadata when policy denies', async () => {
      writeSession(makePolicy({ deny: ['Bash(rm*)'] }))
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'unknown-call-id',
          title: 'rm -rf /',
          metadata: { command: 'rm -rf /' },
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('deny')
    })

    it('fallback: passthrough when policy does not match', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'unknown-call-id',
          title: 'curl https://x',
          metadata: { command: 'curl https://x' },
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('ask')
    })

    it('leaves status alone for passthrough ops', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'curl https://x' } })

      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'c1',
          title: 'curl https://x',
          metadata: {},
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('ask')
    })

    it('fallback: allows bash via pattern when metadata is empty', async () => {
      // Regression: bash carries the command in Permission.pattern, and
      // metadata is {} — the fallback must read pattern or the allow never
      // lands and opencode.json's `*` -> ask still prompts.
      writeSession(makePolicy({ allow_groups: ['shell'] }))
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'unknown-call-id',
          title: 'gh pr diff 278360',
          metadata: {},
          pattern: 'gh pr diff 278360 -R askscio/scio 2>&1',
          time: { created: Date.now() },
        } as never,
        output,
      )
      expect(output.status).toBe('allow')
    })

    it('fallback: denies bash via pattern when the deny list matches', async () => {
      writeSession(makePolicy({ deny: ['Bash(git push --force*)'] }))
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'bash',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'unknown-call-id',
          title: 'git push --force',
          metadata: {},
          pattern: 'git push --force origin main',
          time: { created: Date.now() },
        } as never,
        output,
      )
      expect(output.status).toBe('deny')
    })

    it('is a no-op when there is no active scope', async () => {
      const ask = hooks['permission.ask']!
      const output = { status: 'ask' as 'ask' | 'deny' | 'allow' }
      await ask(
        {
          id: 'p1',
          type: 'read',
          sessionID: 's1',
          messageID: 'm1',
          callID: 'c1',
          title: 'Read',
          metadata: {},
          time: { created: Date.now() },
        },
        output,
      )
      expect(output.status).toBe('ask')
    })
  })

  describe('audit log parity', () => {
    it('appends a denied entry on deny', async () => {
      writeSession(makePolicy({ deny: ['Bash(rm*)'] }))
      const before = hooks['tool.execute.before']!
      await expect(
        before({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'rm -rf /tmp/x' } }),
      ).rejects.toThrow()

      const log = readFileSync(auditLogFile, 'utf-8')
      const line = log.trim().split('\n').at(-1)!
      const [ts, source, action, tool, detail] = line.split('\t')
      expect(source).toBe('opencode-plugin')
      expect(action).toBe('denied')
      expect(tool).toBe('Bash')
      expect(detail).toBe('rm -rf /tmp/x')
      expect(new Date(ts).toString()).not.toBe('Invalid Date')
    })

    it('appends an allowed entry on allow', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'read', sessionID: 's1', callID: 'c1' }, { args: { filePath: '/tmp/x' } })

      const log = readFileSync(auditLogFile, 'utf-8')
      const line = log.trim().split('\n').at(-1)!
      const [, source, action, tool] = line.split('\t')
      expect(source).toBe('opencode-plugin')
      expect(action).toBe('allowed')
      expect(tool).toBe('Read')
    })

    it('does not log passthrough ops', async () => {
      writeSession(makePolicy({ allow_tools: ['Read'] }))
      const before = hooks['tool.execute.before']!
      await before({ tool: 'bash', sessionID: 's1', callID: 'c1' }, { args: { command: 'curl https://x' } })

      expect(existsSync(auditLogFile)).toBe(false)
    })

    it('auditLog is callable standalone and writes 5-field TSV', () => {
      auditLog('allowed', 'Bash', 'ls -la')
      const log = readFileSync(auditLogFile, 'utf-8')
      const fields = log.trim().split('\n').at(-1)!.split('\t')
      expect(fields).toHaveLength(5)
      expect(fields[1]).toBe('opencode-plugin')
      expect(fields[2]).toBe('allowed')
      expect(fields[3]).toBe('Bash')
      expect(fields[4]).toBe('ls -la')
    })

    it('truncates detail to 200 chars', () => {
      auditLog('allowed', 'Bash', 'x'.repeat(500))
      const log = readFileSync(auditLogFile, 'utf-8')
      const detail = log.trim().split('\n').at(-1)!.split('\t')[4]
      expect(detail).toHaveLength(200)
    })

    it('writes timestamps byte-compatible with Python isoformat(timespec="seconds")', () => {
      auditLog('allowed', 'Bash', 'ls')
      const log = readFileSync(auditLogFile, 'utf-8')
      const ts = log.trim().split('\n').at(-1)!.split('\t')[0]
      // Python writes e.g. 2026-09-04T11:00:00+00:00 — seconds precision, +00:00
      // offset (not milliseconds, not 'Z').
      expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$/)
    })

    it('rotates the log to .1 when it exceeds 10 MB', () => {
      writeFileSync(auditLogFile, 'x'.repeat(10 * 1024 * 1024))
      auditLog('allowed', 'Bash', 'after rotation')
      expect(existsSync(`${auditLogFile}.1`)).toBe(true)
      const log = readFileSync(auditLogFile, 'utf-8')
      expect(log.trim().split('\t')[4]).toBe('after rotation')
    })

    it('leaves a small log untouched', () => {
      auditLog('allowed', 'Bash', 'first')
      expect(existsSync(`${auditLogFile}.1`)).toBe(false)
    })
  })
})
